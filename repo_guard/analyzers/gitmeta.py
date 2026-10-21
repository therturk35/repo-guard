"""Git üst veri analizörü: .git/config, .git/hooks/*, .gitmodules, .gitattributes.

Klonlanmış bir depoda bazı git ayarları BAZI git komutlarında rastgele komut
çalıştırır (core.fsmonitor, core.sshCommand, filter.*.smudge, hook dosyaları).
Ayrıca .gitmodules'ta `ext::` taşıyıcısı veya `file://` gibi yollar saldırı vektörüdür.
"""
from __future__ import annotations

import re

from ..models import Severity as S
from .base import FileCtx, basename, make


def analyze(ctx: FileCtx):
    p = ctx.path.replace("\\", "/")
    name = basename(p).lower()
    out = []
    if "/.git/hooks/" in "/" + p or p.startswith(".git/hooks/"):
        if not name.endswith(".sample") and ctx.size > 0:
            out.append(make("RG-GIT-001", f"Etkin git hook dosyası: {name}", S.HIGH, "medium", "supply-chain", ctx.path, 0, f"{name} ({ctx.size} bayt)",
                            "Hook'lar commit/checkout gibi komutlarda otomatik çalışır; klonla gelmesi normal değildir.",
                            "İçeriği okuyun; yoksa silin.", ("T1546",)))
        return out
    if name == "config" and ("/.git/" in "/" + p):
        for n, ln in enumerate(ctx.text.split("\n"), 1):
            if re.match(r"\s*(fsmonitor|sshcommand|hookspath|pager|editor|askpass)\s*=\s*\S", ln, re.I) or re.match(r"\s*(smudge|clean|process)\s*=\s*\S", ln, re.I):
                out.append(make("RG-GIT-002", "Git yapılandırmasında komut çalıştırabilen ayar", S.HIGH, "medium", "supply-chain", ctx.path, n, ln.strip(),
                                "Bu ayar bazı git komutlarında komut çalıştırır.", "Değeri kaldırın.", ("T1546",)))
        return out
    if name == ".gitmodules":
        for n, ln in enumerate(ctx.text.split("\n"), 1):
            m = re.match(r"\s*url\s*=\s*(\S+)", ln)
            if m:
                u = m.group(1)
                if u.startswith(("ext::", "file:", "/", "-")) or re.match(r"[a-z]+::", u):
                    out.append(make("RG-GIT-003", "Tehlikeli alt modül adresi", S.HIGH, "high", "supply-chain", ctx.path, n, ln.strip(),
                                    "ext::/file:/yerel yollar klonlama sırasında komut çalıştırma/yerel dosya okuma vektörüdür.",
                                    "`git clone --no-recurse-submodules` kullanın.", ("T1195.001",)))
                elif u.startswith("http://"):
                    out.append(make("RG-GIT-004", "Alt modül şifresiz HTTP üzerinden", S.LOW, "medium", "supply-chain", ctx.path, n, ln.strip(),
                                    "Ortadaki adam içerik değiştirebilir.", "https kullanın.", ("T1557",)))
        return out
    if name == ".gitattributes":
        for n, ln in enumerate(ctx.text.split("\n"), 1):
            if re.search(r"\bfilter=\w+", ln):
                out.append(make("RG-GIT-005", ".gitattributes filter kullanımı", S.LOW, "low", "supply-chain", ctx.path, n, ln.strip(),
                                "filter sürücüsü yerel yapılandırmada komuta bağlanabilir.", "Sürücü tanımını kontrol edin.", ("T1546",)))
    return out
