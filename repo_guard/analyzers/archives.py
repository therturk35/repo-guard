"""Arşiv analizörü: zip / tar / gzip / bzip2 / xz — DİSKE AÇMADAN, bellekte okur.

Neden diske açmıyoruz? Arşiv açma saldırıları:
  * Zip-Slip: üye adı "../../.bashrc" gibi dışarı taşan yol -> açan program dosya sistemine yazar.
  * Sembolik/sabit bağ üyeleri: sonradan yazılan dosyayı hassas yola yönlendirir.
  * Zip-bomb: küçük arşiv, devasa açılmış veri (disk/RAM doldurur).
  * Şifreli üye: içerik denetlenemez (kör nokta).
Biz yalnızca ÜYE ADI/ÜST VERİSİNİ inceler ve sınırlı bayt okuruz; hiçbir şey diske yazılmaz.
"""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import posixpath
import tarfile
import zipfile
from typing import Callable

from ..limits import Limits
from ..models import Finding, Severity as S
from .base import FileCtx, make

ScanMember = Callable[[str, bytes, int], list]


def _bad_name(name: str) -> bool:
    n = name.replace("\\", "/")
    return n.startswith("/") or (len(n) > 1 and n[1] == ":") or ".." in posixpath.normpath(n).split("/")


def analyze(ctx: FileCtx, raw: bytes, scan_member: ScanMember, lim: Limits) -> list[Finding]:
    """raw: arşivin TÜM baytları (boyut sınırı çağıran tarafından uygulanır)."""
    out: list[Finding] = []
    if ctx.depth >= lim.max_archive_depth:
        return [make("RG-ARC-001", "Arşiv iç içelik sınırı aşıldı (içi taranmadı)", S.LOW, "high", "blind-spot", ctx.path, 0,
                     ctx.name, "Çok katlı arşivler kör nokta oluşturur.", "Elle açıp tarayın.", ("T1027.013",))]
    try:
        if ctx.kind == "zip":
            out += _zip(ctx, raw, scan_member, lim)
        elif ctx.kind == "tar" or (ctx.kind in ("gzip", "bzip2", "xz") and _looks_tar(ctx.kind, raw, lim)):
            out += _tar(ctx, raw, scan_member, lim)
        elif ctx.kind in ("gzip", "bzip2", "xz"):
            out += _single(ctx, raw, scan_member, lim)
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError, ValueError, lzma.LZMAError, RuntimeError, NotImplementedError) as e:
        out.append(make("RG-ARC-009", "Arşiv okunamadı (bozuk/desteklenmeyen)", S.LOW, "medium", "blind-spot", ctx.path, 0,
                        f"{type(e).__name__}: {str(e)[:80]}", "İçerik denetlenemedi.", "Başka bir araçla inceleyin.", ("T1027.013",)))
    return out


def _decompress(kind: str, raw: bytes, limit: int) -> bytes:
    """Sınırlı açma: en fazla limit+1 bayt üretir (bomba koruması)."""
    bio = io.BytesIO(raw)
    if kind == "gzip":
        with gzip.GzipFile(fileobj=bio) as f:
            return f.read(limit + 1)
    if kind == "bzip2":
        with bz2.BZ2File(bio) as f:
            return f.read(limit + 1)
    with lzma.LZMAFile(io.BytesIO(raw)) as f:
        return f.read(limit + 1)


def _looks_tar(kind: str, raw: bytes, lim: Limits) -> bool:
    try:
        head = _decompress(kind, raw, 600)
    except Exception:
        return False
    return len(head) >= 262 and head[257:262] == b"ustar"


def _single(ctx, raw, scan_member, lim):
    out = []
    data = _decompress(ctx.kind, raw, lim.max_file_bytes)
    if len(data) > lim.max_file_bytes:
        out.append(make("RG-ARC-002", "Sıkıştırılmış dosya çok büyük açılıyor (bomba şüphesi)", S.MEDIUM, "medium", "archive", ctx.path, 0,
                        f"> {lim.max_file_bytes} bayt", "Zip-bomb benzeri kaynak tüketimi.", "Açmayın.", ("T1499.001",)))
        data = data[:lim.max_file_bytes]
    inner = ctx.path + "!/" + ctx.name.rsplit(".", 1)[0]
    out += scan_member(inner, data, ctx.depth + 1)
    return out


def _zip(ctx, raw, scan_member, lim):
    out: list[Finding] = []
    zf = zipfile.ZipFile(io.BytesIO(raw))
    infos = zf.infolist()
    if len(infos) > lim.max_archive_members:
        out.append(make("RG-ARC-003", "Arşivde aşırı çok üye", S.MEDIUM, "medium", "archive", ctx.path, 0, f"{len(infos)} üye",
                        "Kaynak tüketimi / kör nokta.", "Elle inceleyin.", ("T1499",)))
        infos = infos[:lim.max_archive_members]
    total = 0
    budget = lim.max_archive_total_bytes
    slip = enc = 0
    for zi in infos:
        total += zi.file_size
        if _bad_name(zi.filename):
            slip += 1
            if slip == 1:
                out.append(make("RG-ARC-004", "Zip-Slip: üye adı dışarı taşan yol içeriyor", S.HIGH, "high", "archive", ctx.path, 0,
                                zi.filename, "Arşivi açan program dosyayı hedef klasör DIŞINA yazabilir (örn. ~/.bashrc).",
                                "Bu arşivi açmayın.", ("T1574", "T1036")))
        if zi.flag_bits & 0x1:
            enc += 1
            continue
        if zi.is_dir():
            continue
        mode = (zi.external_attr >> 16) & 0o170000
        if mode == 0o120000:   # sembolik bağ
            out.append(make("RG-ARC-005", "Arşiv içinde sembolik bağ", S.MEDIUM, "medium", "archive", f"{ctx.path}!/{zi.filename}", 0,
                            zi.filename, "Açıldığında hassas yola yönlendirme yapılabilir.", "Açmadan önce hedefi inceleyin.", ("T1574",)))
            continue
        if zi.compress_size and zi.file_size > lim.ratio_min_size and zi.file_size / max(zi.compress_size, 1) > lim.max_ratio:
            out.append(make("RG-ARC-002", "Aşırı sıkıştırma oranı (zip-bomb şüphesi)", S.MEDIUM, "medium", "archive", f"{ctx.path}!/{zi.filename}", 0,
                            f"{zi.compress_size} → {zi.file_size} bayt", "Açıldığında disk/RAM tüketir.", "Açmayın.", ("T1499.001",)))
            continue
        if zi.file_size > lim.max_file_bytes * 8 or budget <= 0:
            continue
        with zf.open(zi) as fh:
            data = fh.read(min(zi.file_size, lim.max_file_bytes) + 1)
        budget -= len(data)
        out += scan_member(f"{ctx.path}!/{zi.filename}", data, ctx.depth + 1)
    if enc:
        out.append(make("RG-ARC-006", "Şifreli arşiv üyeleri (içerik denetlenemedi)", S.MEDIUM, "high", "blind-spot", ctx.path, 0,
                        f"{enc} şifreli üye", "Şifreli yük antivirüs/statik taramadan kaçmak için kullanılır.", "Parolayı kaynağından doğrulayıp güvenli ortamda açın.", ("T1027.013",)))
    if total > lim.max_archive_total_bytes:
        out.append(make("RG-ARC-002", "Toplam açılmış boyut sınırı aştı", S.MEDIUM, "medium", "archive", ctx.path, 0,
                        f"{total} bayt", "Kaynak tüketimi.", "Açmayın.", ("T1499.001",)))
    return out


def _tar(ctx, raw, scan_member, lim):
    out: list[Finding] = []
    if ctx.kind != "tar":
        raw = _decompress(ctx.kind, raw, lim.max_archive_total_bytes)
        if len(raw) > lim.max_archive_total_bytes:
            return [make("RG-ARC-002", "Açılmış tar çok büyük (bomba şüphesi)", S.MEDIUM, "medium", "archive", ctx.path, 0, "sınır aşıldı",
                         "Kaynak tüketimi.", "Açmayın.", ("T1499.001",))]
    tf = tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
    n = 0
    budget = lim.max_archive_total_bytes
    for ti in tf:                                   # extract ETMEYİZ; yalnızca üst veri ve sınırlı okuma
        n += 1
        if n > lim.max_archive_members:
            out.append(make("RG-ARC-003", "Arşivde aşırı çok üye", S.MEDIUM, "medium", "archive", ctx.path, 0, f">{lim.max_archive_members}",
                            "Kaynak tüketimi.", "Elle inceleyin.", ("T1499",)))
            break
        p = f"{ctx.path}!/{ti.name}"
        if _bad_name(ti.name):
            out.append(make("RG-ARC-004", "Tar-Slip: üye adı dışarı taşan yol içeriyor", S.HIGH, "high", "archive", p, 0, ti.name,
                            "Açan program hedef klasör dışına yazabilir.", "Bu arşivi açmayın.", ("T1574",)))
        if ti.issym() or ti.islnk():
            sev = S.HIGH if _bad_name(ti.linkname) else S.MEDIUM
            out.append(make("RG-ARC-005", "Arşiv içinde sembolik/sabit bağ", sev, "medium", "archive", p, 0, f"{ti.name} -> {ti.linkname}",
                            "Hassas yollara yönlendirebilir.", "Açmadan önce hedefi inceleyin.", ("T1574",)))
            continue
        if ti.isdev() or ti.isfifo():
            out.append(make("RG-ARC-007", "Arşivde aygıt/FIFO üyesi", S.HIGH, "medium", "archive", p, 0, ti.name,
                            "Aygıt dosyaları normal arşivde bulunmaz.", "Açmayın.", ("T1574",)))
            continue
        if ti.mode & 0o6000:
            out.append(make("RG-ARC-008", "Arşivde setuid/setgid bit", S.HIGH, "medium", "archive", p, 0, oct(ti.mode),
                            "Açıldığında ayrıcalık yükseltme için kullanılabilir.", "Açmayın.", ("T1548.001",)))
        if not ti.isfile() or ti.size > lim.max_file_bytes * 8 or budget <= 0:
            continue
        fh = tf.extractfile(ti)
        if fh is None:
            continue
        data = fh.read(min(ti.size, lim.max_file_bytes) + 1)
        budget -= len(data)
        out += scan_member(p, data, ctx.depth + 1)
    return out
