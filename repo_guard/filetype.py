"""Dosya türü tespiti: uzantıya DEĞİL, içeriğin ilk baytlarına (magic bytes) bakar.

Neden önemli? Saldırganlar 'resim.png' adlı bir dosyanın içine çalıştırılabilir
dosya koyabilir (uzantı sahteciliği, T1036.008). Gerçek türü içerikten bulup
uzantıyla karşılaştırırız.

Burada hiçbir şey çalıştırılmaz; sadece baytlar okunur.
"""

from __future__ import annotations

import os
import re

# Çalıştırılabilir dosya türleri
EXECUTABLE_KINDS = frozenset({"pe", "elf", "macho", "macho-fat", "lnk"})
# İçine bakabildiğimiz arşivler
ARCHIVE_KINDS = frozenset({"zip", "gzip", "bzip2", "xz", "tar"})
# İçine BAKAMADIĞIMIZ (stdlib desteklemiyor) arşivler: rapor edilir, kör nokta olarak
UNSCANNABLE_ARCHIVE_KINDS = frozenset({"7z", "rar", "zstd"})

# Uzantı -> beklenen içerik türleri (uyuşmazlık tespiti için)
EXPECTED_BY_EXT: dict[str, frozenset[str]] = {
    ".png": frozenset({"png"}),
    ".jpg": frozenset({"jpeg"}), ".jpeg": frozenset({"jpeg"}),
    ".gif": frozenset({"gif"}),
    ".pdf": frozenset({"pdf"}),
    ".ico": frozenset({"ico", "png"}),
    ".txt": frozenset({"text"}), ".md": frozenset({"text"}), ".csv": frozenset({"text"}),
    ".json": frozenset({"text"}), ".log": frozenset({"text"}),
}


def sniff(head: bytes) -> str:
    """İlk baytlardan dosya türünü tahmin eder. 'text' ve 'binary' genel kategorilerdir."""
    h = head[:4096]
    if not h:
        return "empty"
    if h.startswith(b"\x7fELF"):
        return "elf"
    if h.startswith(b"MZ") and len(h) >= 0x40:
        # PE doğrulaması: e_lfanew ofsetinde 'PE\0\0' imzası olmalı
        off = int.from_bytes(h[0x3C:0x40], "little")
        if 0 < off <= len(h) - 4 and h[off:off + 4] == b"PE\x00\x00":
            return "pe"
    if h[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macho"
    if h[:4] == b"\xca\xfe\xba\xbe":
        # Aynı imza hem Mach-O 'fat' hem Java .class için kullanılır:
        # fat'te sonraki 4 bayt mimari sayısıdır (küçük), class'ta sürüm numarasıdır (>=45).
        return "macho-fat" if int.from_bytes(h[4:8], "big") < 30 else "java-class"
    if h.startswith(b"PK\x03\x04") or h.startswith(b"PK\x05\x06"):
        return "zip"
    if h.startswith(b"\x1f\x8b"):
        return "gzip"
    if h.startswith(b"BZh"):
        return "bzip2"
    if h.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if h.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if h.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if h.startswith(b"\x28\xb5\x2f\xfd"):
        return "zstd"
    if len(h) >= 262 and h[257:262] == b"ustar":
        return "tar"
    if h.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if h.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if h.startswith(b"GIF87a") or h.startswith(b"GIF89a"):
        return "gif"
    if h.startswith(b"%PDF"):
        return "pdf"
    if h.startswith(b"\x00\x00\x01\x00"):
        return "ico"
    if h.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"          # eski Office / MSI
    if h.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "lnk"          # Windows kısayolu
    if h.startswith(b"\x00asm"):
        return "wasm"
    if h.startswith(b"#!"):
        return "script"
    return "text" if is_texty(h) else "binary"


def is_texty(head: bytes) -> bool:
    """İçerik metin gibi mi? (BOM'lu UTF-16 dahil)"""
    if head.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")):
        return True
    if b"\x00" in head:
        return False
    # Yazdırılamayan kontrol baytlarının oranı düşükse metindir
    bad = sum(1 for b in head if b < 9 or (13 < b < 32 and b != 27))
    return bad / max(len(head), 1) < 0.02


def decode_text(data: bytes) -> str:
    """Baytları metne çevirir. BOM'a göre UTF-16 / UTF-8; hatalı baytlar 'replace' ile geçilir."""
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace")
    return data.decode("utf-8", errors="replace")


# ------------------------------ dil / bağlam tespiti ------------------------------

_LANG_BY_EXT = {
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ksh": "shell", ".command": "shell",
    ".py": "python", ".pyw": "python",
    ".js": "js", ".mjs": "js", ".cjs": "js", ".ts": "js", ".jsx": "js", ".tsx": "js",
    ".ps1": "powershell", ".psm1": "powershell", ".psd1": "powershell",
    ".bat": "batch", ".cmd": "batch",
    ".rb": "ruby", ".php": "php", ".pl": "perl",
    ".md": "docs", ".markdown": "docs", ".rst": "docs", ".txt": "docs", ".adoc": "docs",
    ".yml": "yaml", ".yaml": "yaml", ".json": "json", ".toml": "config", ".ini": "config", ".cfg": "config",
    ".pth": "pth",
}

_LANG_BY_NAME = {
    "makefile": "makefile", "gnumakefile": "makefile", "justfile": "makefile",
    "dockerfile": "dockerfile", "containerfile": "dockerfile",
    ".envrc": "shell", ".bashrc": "shell", ".zshrc": "shell", ".profile": "shell",
}

_SHEBANG_RE = re.compile(rb"^#!\s*\S*?(?:/env\s+)?(\w+)")


def detect_lang(name: str, head: bytes) -> str:
    """Dosyanın 'dili/bağlamı': kurallar bu etikete göre uygulanır (örn. docs'ta önem düşürülür)."""
    lower = name.lower()
    if lower in _LANG_BY_NAME:
        return _LANG_BY_NAME[lower]
    if lower.startswith("dockerfile"):
        return "dockerfile"
    ext = os.path.splitext(lower)[1]
    if ext in _LANG_BY_EXT:
        return _LANG_BY_EXT[ext]
    if head.startswith(b"#!"):
        m = _SHEBANG_RE.match(head)
        interp = m.group(1).decode("ascii", "ignore") if m else ""
        if interp in ("sh", "bash", "zsh", "ksh", "dash"):
            return "shell"
        if interp.startswith("python"):
            return "python"
        if interp in ("node", "deno", "bun"):
            return "js"
        if interp in ("ruby", "perl", "php"):
            return interp
    return "text"
