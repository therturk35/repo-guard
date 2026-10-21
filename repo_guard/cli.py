"""Komut satırı arayüzü.

Kullanım:
  repo-guard scan <klasör|arşiv>          yerel klasörü/arşivi tara
  repo-guard fetch <sahip/depo>           GitHub'dan güvenle indir (çalıştırmadan) ve tara
  repo-guard rules                        kural listesi
  repo-guard explain RG-EXEC-001          bir kuralın ayrıntısı
  repo-guard selftest                     kural örneklerini doğrula
Çıkış kodları: 0 temiz | 1 --fail-on eşiği aşıldı | 2 tarama eksik/hata
"""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .catalog import REGISTRY, all_rules
from .fetch import safe_clone
from .limits import MIB, Limits
from .models import Severity
from .reports import FORMATS
from .scanner import IgnoreList, Scanner


def selftest() -> int:
    bad = 0
    for r in all_rules():
        for p in r.positives:
            if not any(r.pattern.search(l) for l in p.split("\n")):
                print(f"BAŞARISIZ (eşleşmeliydi) {r.id}: {p[:60]}"); bad += 1
        for n in r.negatives:
            if any(r.pattern.search(l) for l in n.split("\n")):
                print(f"BAŞARISIZ (eşleşmemeliydi) {r.id}: {n[:60]}"); bad += 1
    print(f"{len(REGISTRY)} kural, hata: {bad}")
    return 1 if bad else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="repo-guard", description="Çalıştırmadan statik repo güvenlik denetimi")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("scan", "fetch"):
        p = sub.add_parser(name)
        p.add_argument("target")
        p.add_argument("--format", choices=sorted(FORMATS), default="text")
        p.add_argument("--out")
        p.add_argument("--min-severity", default="low", help="prompt biçiminde 'medium' önerilir")
        p.add_argument("--fail-on", default="high", help="bu önem ve üstünde bulgu varsa çıkış kodu 1")
        p.add_argument("--ignore-file", help="DEPO DIŞINDA bir ignore dosyası")
        p.add_argument("--max-file-mb", type=int, default=2)
        p.add_argument("--max-seconds", type=float, default=900)
    sub.add_parser("rules")
    ex = sub.add_parser("explain"); ex.add_argument("rule_id")
    sub.add_parser("selftest")
    a = ap.parse_args(argv)

    if a.cmd == "selftest":
        return selftest()
    if a.cmd == "rules":
        for r in sorted(all_rules(), key=lambda r: r.id):
            print(f"{r.id:12} {r.severity.label:8} {r.category:13} {r.title}")
        return 0
    if a.cmd == "explain":
        all_rules()
        r = REGISTRY.get(a.rule_id.upper())
        if not r:
            print("kural yok"); return 2
        print(f"{r.id} — {r.title}\nÖnem: {r.severity.label}  Güven: {r.confidence}  Kategori: {r.category}\nMITRE: {', '.join(r.mitre) or '—'}\n"
              f"Neden: {r.why}\nNe yapmalı: {r.fix}\nÖrnek eşleşen: {r.positives[:2]}")
        return 0

    target = a.target
    sha = None
    if a.cmd == "fetch":
        target, sha = safe_clone(a.target)
        print(f"# indirildi: {a.target} @ {sha} -> {target}", file=sys.stderr)
    lim = Limits(max_file_bytes=a.max_file_mb * MIB, max_seconds=a.max_seconds)
    rep = Scanner(lim, IgnoreList(a.ignore_file)).scan(target)
    ms = Severity.parse(a.min_severity)
    fmt = FORMATS[a.format]
    out = fmt(rep, ms) if a.format in ("text", "markdown", "prompt") else fmt(rep)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(out)
    else:
        print(out)
    if not rep.complete:
        return 2
    return 1 if any(f.severity >= Severity.parse(a.fail_on) for f in rep.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
