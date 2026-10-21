"""İkili (binary) dosya analizörü — dosyayı ÇALIŞTIRMADAN yalnızca baytlarına bakar.

Yaptıkları:
  1. Uzantı sahteciliği: ".png" adlı ama içinde ELF/PE olan dosya (T1036.008).
  2. Depoda çalıştırılabilir dosya varlığı (kaynak kodu depoda derlenmiş ikili = denetlenemez).
  3. Paketlenmiş (UPX) veya çok yüksek entropili çalıştırılabilir.
  4. İkili içindeki okunabilir dizeler (strings): URL, webhook, madenci, yol göstergeleri.
"""
from __future__ import annotations

import math
import os
import re
from collections import Counter

from ..catalog import Rule
from ..filetype import EXECUTABLE_KINDS, EXPECTED_BY_EXT, UNSCANNABLE_ARCHIVE_KINDS
from ..models import Severity as S
from .base import FileCtx, make
from . import content

_STR = re.compile(rb"[\x20-\x7e]{8,300}")


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in Counter(b).values())


def analyze(ctx: FileCtx, rules: list[Rule]):
    out = []
    ext = os.path.splitext(ctx.name.lower())[1]
    exe = ctx.kind in EXECUTABLE_KINDS
    expected = EXPECTED_BY_EXT.get(ext)
    if expected and ctx.kind not in expected and ctx.kind not in ("empty",) and (exe or ctx.kind in ("zip", "gzip", "script")):
        out.append(make("RG-BIN-001", "Uzantı sahteciliği: içerik uzantıyla uyuşmuyor", S.HIGH, "high", "malware", ctx.path, 0,
                        f"uzantı {ext} ama içerik türü {ctx.kind}",
                        "Zararsız görünen bir dosya adının arkasına çalıştırılabilir/arşiv gizlenmiş.",
                        "Dosyayı açmayın; kaynağını sorgulayın.", ("T1036.008",)))
    if exe:
        out.append(make("RG-BIN-002", f"Depoda derlenmiş çalıştırılabilir dosya ({ctx.kind})", S.MEDIUM if ctx.kind != "lnk" else S.HIGH,
                        "medium", "malware", ctx.path, 0, f"{ctx.name} ({ctx.size} bayt)",
                        "Derlenmiş ikili, kaynak kodla eşleştiği doğrulanamayan kördür; zararlı dağıtımın yaygın yoludur.",
                        "Çalıştırmayın; kaynaktan kendiniz derleyin veya hash'i resmi yayınla karşılaştırın.", ("T1204.002",)))
        if b"UPX!" in ctx.data[:4096] or b"UPX0" in ctx.data[:4096]:
            out.append(make("RG-BIN-003", "UPX ile paketlenmiş çalıştırılabilir", S.MEDIUM, "medium", "obfuscation", ctx.path, 0,
                            "UPX imzası", "Paketleme, içeriğin statik incelemesini zorlaştırır.", "Açıp (upx -d) inceleyin; sandbox'ta analiz edin.", ("T1027.002",)))
        elif len(ctx.data) > 4096 and _entropy(ctx.data[:262144]) > 7.6:
            out.append(make("RG-BIN-004", "Çok yüksek entropili çalıştırılabilir (paketli/şifreli olabilir)", S.MEDIUM, "low", "obfuscation",
                            ctx.path, 0, f"entropi ≈ {_entropy(ctx.data[:262144]):.2f}", "Yüksek entropi sıkıştırılmış/şifreli yük belirtisidir.",
                            "Sandbox'ta analiz edin.", ("T1027",)))
        # Dizeleri çıkar ve metin kurallarını uygula (yalnızca ağ/kimlik/madenci göstergeleri)
        strings = b"\n".join(_STR.findall(ctx.data[:1_500_000])[:5000]).decode("ascii", "ignore")
        if strings:
            sub = FileCtx(ctx.path + " [strings]", ctx.name, b"", ctx.size, "text", "binary-strings", strings)
            keep = [r for r in rules if r.category in ("exfil", "credential", "malware") and not r.is_secret]
            for f in content.analyze(sub, keep, 15):
                out.append(f)
    if ctx.kind in UNSCANNABLE_ARCHIVE_KINDS:
        out.append(make("RG-BIN-005", f"İçine bakılamayan arşiv türü ({ctx.kind})", S.LOW, "high", "blind-spot", ctx.path, 0,
                        ctx.name, "Bu arşivin içeriği denetlenemedi (kör nokta).", "Güvenli bir ortamda açıp ayrıca tarayın.", ("T1027.013",)))
    if ctx.kind == "ole":
        out.append(make("RG-BIN-006", "Eski Office/OLE belgesi (makro içerebilir)", S.LOW, "low", "malware", ctx.path, 0, ctx.name,
                        "OLE belgeleri VBA makrosu taşıyabilir.", "Makroları etkinleştirmeden önce analiz edin.", ("T1137.001",)))
    return out
