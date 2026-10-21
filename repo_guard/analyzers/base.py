"""Analizör ortak yapıları: FileCtx (bir dosyanın bağlamı) ve bulgu üretici yardımcılar."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

from ..models import Finding, Severity
from ..textutil import sanitize


@dataclass
class FileCtx:
    """Bir dosyanın analizörlere verilen özeti. İçerik BAYT olarak tutulur, hiçbir zaman çalıştırılmaz."""
    path: str          # taranan kökten göreli (arşiv içi: "a.zip!/x")
    name: str          # taban ad
    data: bytes        # okunan içerik (büyük dosyada baş + son parça)
    size: int          # gerçek dosya boyutu
    kind: str          # sniff() sonucu
    lang: str          # detect_lang() sonucu
    text: str = ""     # çözülmüş metin (metin dosyası ise)
    truncated: bool = False
    depth: int = 0     # arşiv iç içelik seviyesi

    @property
    def is_text(self) -> bool:
        return self.kind in ("text", "script")


def make(rule_id, title, sev, conf, cat, path, line, snippet, why, fix, mitre=(), detail="", context="") -> Finding:
    """Kural dışı (yapısal) bulgular için Finding üretir; alıntıyı güvenli hale getirir."""
    return Finding(rule_id, title, sev, conf, cat, path, line, sanitize(snippet), why, fix, tuple(mitre), detail, context)


def is_doc_path(path: str, lang: str) -> bool:
    """Belge / örnek / test yolu mu? Bu bağlamda bulgular bir kademe düşürülür (yanlış alarmı azaltır)."""
    if lang == "docs":
        return True
    parts = path.lower().replace("\\", "/").split("/")
    if any(p in ("docs", "doc", "examples", "example", "tests", "test", "__tests__", "spec", "specs", "fixtures", "testdata", "samples", "benchmark", "benchmarks", "bench", "benches", "eval", "evals", "templates", "template") for p in parts[:-1]):
        return True
    return bool(_TESTFILE.search(parts[-1]))


# test dosyası adları: foo_test.go, test_foo.py, foo.test.ts, foo.spec.js, conftest.py
_TESTFILE = re.compile(r"(?:_test\.|\.test\.|\.spec\.|^test_|^conftest\.py$|_spec\.|^tests?(?:_\w+)?\.rs$)")


def basename(path: str) -> str:
    return os.path.basename(path.split("!/")[-1])
