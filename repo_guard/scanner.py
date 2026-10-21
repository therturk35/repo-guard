"""Ana tarayıcı: dosya sistemini gezer, her dosyayı güvenle okur, analizörlere verir.

GÜVENLİK İLKELERİ (bu dosyanın her satırı bunlara uyar):
  1. ASLA çalıştırma/import/eval yok — yalnızca bayt okuma.
  2. Sembolik bağları TAKİP ETME (taranan dizin dışını okumamak için).
  3. Yalnızca düzenli dosyaları aç (FIFO/soket/aygıt açmak tarayıcıyı kilitleyebilir).
  4. Her kaynağa sınır (Limits); sınır aşımı sessiz değil, rapora yazılır -> complete=False.
  5. Bir dosyadaki hata tüm taramayı durdurmaz; errors listesine eklenir.
"""
from __future__ import annotations

import datetime as _dt
import fnmatch
import os
import stat
import time
from typing import Optional

from . import __version__
from .analyzers import archives, binaries, content, gitmeta, manifests, toolconfigs, unicode_tricks, workflows
from .analyzers.base import FileCtx, make
from .catalog import all_rules
from .correlate import correlate, finalize
from .filetype import ARCHIVE_KINDS, EXECUTABLE_KINDS, decode_text, detect_lang, sniff
from .limits import Limits
from .models import Finding, ScanReport, Severity

# Taranmayacak (devasa ve içeriği salt git nesnesi) git alt dizinleri
_SKIP_GIT_SUBDIRS = {"objects", "refs", "logs", "lfs", "info", "packed-refs"}


class IgnoreList:
    """Harici ignore dosyası. Biçim:  KURAL_ID [yol-glob]   (# yorum).

    GÜVENLİK: Yalnızca taranan deponun DIŞINDAKİ bir dosyadan okunur; depo kendi
    kendini 'temiz' ilan edemesin diye depo içindeki ignore dosyası ASLA kullanılmaz.
    """

    def __init__(self, path: Optional[str] = None):
        self.entries: list[tuple[str, str]] = []
        if path:
            with open(path, encoding="utf-8") as fh:
                for ln in fh:
                    ln = ln.split("#")[0].strip()
                    if not ln:
                        continue
                    parts = ln.split(None, 1)
                    self.entries.append((parts[0], parts[1] if len(parts) > 1 else "*"))

    def matches(self, f: Finding) -> bool:
        return any(rid in (f.rule_id, "*") and fnmatch.fnmatch(f.path, g) for rid, g in self.entries)


class Scanner:
    def __init__(self, limits: Optional[Limits] = None, ignore: Optional[IgnoreList] = None):
        self.lim = limits or Limits()
        self.rules = all_rules()
        self.ignore = ignore or IgnoreList()
        self._t0 = 0.0
        self._rep: ScanReport

    # ------------------------------------------------------------------ genel
    def scan(self, target: str) -> ScanReport:
        self._t0 = time.monotonic()
        self._rep = ScanReport(target=target, version=__version__, started=_dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"))
        rep = self._rep
        try:
            if os.path.islink(target):
                rep.errors.append("hedef bir sembolik bağ; doğrudan gerçek yolu verin")
                rep.complete = False
            elif os.path.isdir(target):
                self._walk(target)
            elif os.path.isfile(target):
                self._scan_file(target, os.path.basename(target))
            else:
                rep.errors.append(f"hedef bulunamadı: {target}")
                rep.complete = False
        except Exception as e:                                 # son savunma hattı
            rep.errors.append(f"beklenmeyen hata: {type(e).__name__}: {e}")
            rep.complete = False
        # ignore uygula, ilişkilendir, karar ver
        kept = []
        for f in correlate(rep.findings):
            if self.ignore.matches(f):
                rep.ignored_count += 1
            else:
                kept.append(f)
        rep.findings = sorted(kept, key=lambda f: (-int(f.severity), f.path, f.line, f.rule_id))
        rep.seconds = round(time.monotonic() - self._t0, 3)
        finalize(rep)
        return rep

    def _over_time(self) -> bool:
        if time.monotonic() - self._t0 > self.lim.max_seconds:
            if "zaman sınırı aşıldı" not in self._rep.errors:
                self._rep.errors.append("zaman sınırı aşıldı")
                self._rep.complete = False
            return True
        return False

    # --------------------------------------------------------------- yürüyüş
    def _walk(self, root: str) -> None:
        rep, lim = self._rep, self.lim
        root_real = os.path.realpath(root)
        for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
            rel_dir = os.path.relpath(dirpath, root)
            depth = 0 if rel_dir == "." else rel_dir.count(os.sep) + 1
            # .git içinde yalnızca config / hooks'a bak
            if os.path.basename(dirpath) == ".git":
                dirnames[:] = [d for d in dirnames if d == "hooks"]
                filenames = [f for f in filenames if f == "config"]
            elif "/.git/hooks" in dirpath.replace("\\", "/") + "/":
                dirnames[:] = []
            if depth >= lim.max_depth:
                dirnames[:] = []
                rep.skipped.append(f"{rel_dir}: derinlik sınırı")
            dirnames.sort()
            for d in list(dirnames):
                full = os.path.join(dirpath, d)
                if os.path.islink(full):            # dizin bağını takip etme
                    dirnames.remove(d)
                    self._note_symlink(full, root, root_real)
            for fn in sorted(filenames):
                if rep.files_scanned >= lim.max_files:
                    rep.errors.append(f"dosya sayısı sınırı ({lim.max_files}) aşıldı")
                    rep.complete = False
                    return
                if rep.bytes_read >= lim.max_total_bytes:
                    rep.errors.append("toplam okuma bütçesi aşıldı")
                    rep.complete = False
                    return
                if self._over_time():
                    return
                full = os.path.join(dirpath, fn)
                if os.path.islink(full):
                    self._note_symlink(full, root, root_real)
                    continue
                self._scan_file(full, os.path.relpath(full, root))

    def _note_symlink(self, full: str, root: str, root_real: str) -> None:
        rel = os.path.relpath(full, root)
        try:
            tgt = os.readlink(full)
            real = os.path.realpath(full)
        except OSError:
            return
        outside = not (real == root_real or real.startswith(root_real + os.sep))
        if outside:
            self._rep.findings.append(make("RG-FS-001", "Depo dışına işaret eden sembolik bağ", Severity.MEDIUM, "medium", "filesystem", rel, 0,
                                           f"{rel} -> {tgt}", "Bu bağ takip edilirse (örn. araçlar/derleyiciler) hassas dosyalar okunabilir.",
                                           "Bağı kaldırın; takip etmeyin.", ("T1574",)))
        self._rep.skipped.append(f"{rel}: sembolik bağ (takip edilmedi)")

    # ------------------------------------------------------------------ dosya
    def _scan_file(self, full: str, rel: str) -> None:
        rep, lim = self._rep, self.lim
        try:
            st = os.lstat(full)
            if not stat.S_ISREG(st.st_mode):
                rep.skipped.append(f"{rel}: düzenli dosya değil")
                return
            size = st.st_size
            with open(full, "rb") as fh:
                head = fh.read(lim.max_file_bytes)
                tail = b""
                truncated = size > lim.max_file_bytes
                if truncated:
                    fh.seek(max(size - lim.tail_bytes, lim.max_file_bytes))
                    tail = fh.read(lim.tail_bytes)
                kind0 = sniff(head)
                raw_full = None
                if kind0 in ARCHIVE_KINDS and size <= lim.max_archive_total_bytes // 4:
                    fh.seek(0)
                    raw_full = fh.read(size)
            rep.bytes_read += len(head) + len(tail) + (len(raw_full) if raw_full else 0)
            data = head + (b"\n" + tail if tail else b"")
            if truncated:
                rep.skipped.append(f"{rel}: büyük dosya, baş+son parça tarandı ({size} bayt)")
            rep.files_scanned += 1
            rep.findings.extend(self._analyze(rel, os.path.basename(full), data, size, 0, raw_full, truncated))
        except OSError as e:
            rep.errors.append(f"{rel}: okunamadı ({e.__class__.__name__})")
            rep.complete = False
        except Exception as e:
            rep.errors.append(f"{rel}: analiz hatası ({type(e).__name__}: {str(e)[:80]})")
            rep.complete = False

    def _scan_member(self, path: str, data: bytes, depth: int) -> list[Finding]:
        """Arşiv üyesini (bellekteki baytlar) tarar."""
        self._rep.files_scanned += 1
        self._rep.bytes_read += len(data)
        try:
            raw = data if sniff(data[:4096]) in ARCHIVE_KINDS else None
            return self._analyze(path, os.path.basename(path.split("!/")[-1]), data, len(data), depth, raw, False)
        except Exception as e:
            self._rep.errors.append(f"{path}: üye analiz hatası ({type(e).__name__})")
            self._rep.complete = False
            return []

    def _analyze(self, path, name, data, size, depth, raw_full, truncated) -> list[Finding]:
        kind = sniff(data)
        lang = detect_lang(name, data[:64])
        text = decode_text(data) if kind in ("text", "script") else ""
        ctx = FileCtx(path, name, data, size, kind, lang, text, truncated, depth)
        out: list[Finding] = []
        out += content.analyze(ctx, self.rules, self.lim.max_findings_per_file)
        out += unicode_tricks.analyze(ctx)
        out += binaries.analyze(ctx, self.rules)
        out += manifests.analyze(ctx)
        out += workflows.analyze(ctx)
        out += gitmeta.analyze(ctx)
        out += toolconfigs.analyze(ctx)
        if kind in ARCHIVE_KINDS:
            if raw_full is not None:
                out += archives.analyze(ctx, raw_full, self._scan_member, self.lim)
            else:
                out.append(make("RG-ARC-010", "Arşiv çok büyük, içi taranmadı", Severity.LOW, "high", "blind-spot", path, 0, f"{size} bayt",
                                "Boyut sınırı nedeniyle içerik denetlenemedi.", "Sınırı artırın veya elle inceleyin.", ("T1027.013",)))
        if truncated:
            out.append(make("RG-FS-002", "Dosya boyut sınırını aştı (kısmen tarandı)", Severity.INFO, "high", "blind-spot", path, 0, f"{size} bayt",
                            "Orta kısım okunmadı; yük ortada saklanmış olabilir.", "--max-file-mb değerini artırın.", ()))
        return out
