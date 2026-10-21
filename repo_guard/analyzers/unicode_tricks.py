"""Gizli/yanıltıcı Unicode analizörü.

Trojan Source (CVE-2021-42574): bidi kontrol karakterleri kodun GÖRÜNÜŞÜNÜ ve
GERÇEK çalışma sırasını ayırır; inceleyen kişi masum bir satır görür.
Unicode 'tag' karakterleri (U+E0000..) ise yapay zekâ ajanlarına görünmez
talimat gizlemek için kullanılır. Bunların koda ve yapılandırmaya girmesi için
meşru bir sebep nadirdir.
"""
from __future__ import annotations

import re

from ..models import Severity as S
from ..textutil import BIDI_CHARS, ZERO_WIDTH_CHARS
from .base import FileCtx, is_doc_path, make

_CODE_LANGS = {"python", "js", "shell", "powershell", "batch", "ruby", "php", "perl", "makefile", "dockerfile", "yaml", "json", "config", "pth"}
_WORD = re.compile(r"[^\W\d_]{4,}", re.UNICODE)


def _script_of(ch: str) -> str:
    o = ord(ch)
    if o < 0x250:
        return "latin"
    if 0x370 <= o <= 0x3FF:
        return "greek"
    if 0x400 <= o <= 0x52F:
        return "cyrillic"
    return "other"


def analyze(ctx: FileCtx):
    if not ctx.is_text or not ctx.text:
        return []
    out = []
    bidi_line = tag_line = zw_line = homo_line = 0
    for n, line in enumerate(ctx.text.split("\n"), 1):
        if not line:
            continue
        if not bidi_line and any(c in BIDI_CHARS for c in line):
            bidi_line = n
        if not tag_line and any(0xE0000 <= ord(c) <= 0xE007F for c in line):
            tag_line = n
        if not zw_line and ctx.lang in _CODE_LANGS and any(c in ZERO_WIDTH_CHARS and c != "﻿" for c in line):
            zw_line = n
        if not homo_line and ctx.lang in _CODE_LANGS and not line.isascii():
            for w in _WORD.findall(line):
                scripts = {_script_of(c) for c in w}
                if "latin" in scripts and ("cyrillic" in scripts or "greek" in scripts):
                    homo_line = n
                    break
    if bidi_line:
        out.append(make("RG-UNI-001", "Çift yönlü (bidi) Unicode kontrol karakteri (Trojan Source)", S.HIGH if (ctx.lang in _CODE_LANGS and not is_doc_path(ctx.path, ctx.lang)) else S.MEDIUM,
                        "high", "obfuscation", ctx.path, bidi_line, ctx.text.split("\n")[bidi_line - 1][:150],
                        "Kodun ekranda görünen sırası ile gerçek işlenme sırası farklılaşabilir; inceleme yanıltılır.",
                        "Karakterleri gösteren bir editörle açın; meşru değilse reddedin.", ("T1036", "T1027")))
    if tag_line:
        out.append(make("RG-UNI-002", "Görünmez Unicode 'tag' karakterleri (gizli metin)", S.HIGH, "high", "obfuscation",
                        ctx.path, tag_line, ctx.text.split("\n")[tag_line - 1][:150],
                        "Görünmeyen ASCII metni gizlenebilir; yapay zekâ ajanlarına gizli talimat vermek için kullanılır.",
                        "Karakterleri çözüp içeriği okuyun.", ("T1027.010",)))
    if zw_line:
        out.append(make("RG-UNI-003", "Kodda sıfır genişlikli karakter", S.MEDIUM, "medium", "obfuscation",
                        ctx.path, zw_line, ctx.text.split("\n")[zw_line - 1][:150],
                        "Görünmez karakterler tanımlayıcıları/dizeleri farklılaştırıp inceleyeni yanıltabilir.",
                        "Karakterleri temizleyin ve etkisini kontrol edin.", ("T1027",)))
    if homo_line:
        out.append(make("RG-UNI-004", "Latin ile Kiril/Yunan harfleri karışık kelime (homoglif)", S.MEDIUM, "low", "obfuscation",
                        ctx.path, homo_line, ctx.text.split("\n")[homo_line - 1][:150],
                        "Benzer görünen harflerle sahte tanımlayıcı/alan adı oluşturulabilir.",
                        "Kelimeyi ASCII karşılığıyla karşılaştırın.", ("T1036",)))
    return out
