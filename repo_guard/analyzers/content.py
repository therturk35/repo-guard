"""İçerik analizörü: katalogdaki regex kurallarını satır satır uygular.

Önemli noktalar:
  * Anahtar kelime ön-filtresi: satır küçük harfe çevrilir, kuralın keywords'ünden
    hiçbiri yoksa regex hiç çalışmaz (hız + ReDoS azaltma).
  * Çok uzun satırlar 4000 karakterlik örtüşen parçalara bölünür; böylece tek
    satıra gizlenmiş yük de taranır ama regex'e sınırsız girdi verilmez.
  * Belge/test yollarında önem bir kademe düşürülür ve bağlam notu eklenir.
  * Sır kuralları: yer tutucu/düşük entropili değerler elenir, değer maskelenir.
"""
from __future__ import annotations

import re

from ..catalog import Rule, all_rules
from ..models import Finding, Severity
from ..textutil import looks_like_placeholder, mask_secret, sanitize, shannon_entropy, window
from .base import FileCtx, is_doc_path

CHUNK = 4000
OVERLAP = 300
_SECRET_RULES = None

# Satır, tehlikeli kalıbı KULLANMAK yerine ANLATIYOR/ENGELLİYOR/SINIYORSA (kara liste, imza, test, regex tanımı)
# bulgu bir kademe düşürülür. Saldırgan bunu taklit edebilir; bu yüzden yalnızca düşürür, asla silmez.
_DEFENSIVE = re.compile(r"(?i)\b(deny|denylist|blocklist|blocked?|danger(?:ous)?|malicious|forbid(?:den)?|prohibit(?:ed)?|assert\w*|expect\(|should(?:_| )not|never run|do not run|don't run|signature|pattern|regexp?|evil)|^\s*(?://|#|\*|/\*|--|echo\b|printf?\b|print_\w+|console\.(?:log|error)|logger\.\w+)")


def _secret_rules():
    global _SECRET_RULES
    if _SECRET_RULES is None:
        _SECRET_RULES = [r for r in all_rules() if r.is_secret]
    return _SECRET_RULES


def mask_line(line: str) -> str:
    """Satırdaki bilinen sır biçimlerini maskeler (rapor sır sızdırmasın)."""
    for r in _secret_rules():
        def _sub(m, r=r):
            g = r.secret_group
            val = m.group(g) if g else m.group(0)
            return m.group(0).replace(val, mask_secret(val))
        try:
            line = r.pattern.sub(_sub, line)
        except Exception:
            pass
    return line


def _chunks(line: str):
    if len(line) <= CHUNK:
        yield 0, line
        return
    pos = 0
    while pos < len(line):
        yield pos, line[pos:pos + CHUNK]
        pos += CHUNK - OVERLAP


def _lower_sev(sev: Severity) -> Severity:
    return Severity(max(int(sev) - 1, 0)) if sev > Severity.LOW else sev


def analyze(ctx: FileCtx, rules: list[Rule], max_findings: int = 60) -> list[Finding]:
    if not ctx.is_text or not ctx.text:
        return []
    doc = is_doc_path(ctx.path, ctx.lang)
    # Tek satırlık dev JSON/YAML (belgeleri string olarak gömen paketlenmiş veri): kod değil, veri blobu
    blob = ctx.lang in ("json", "yaml") and max((len(l) for l in ctx.text.split("\n")), default=0) > 3000
    out: list[Finding] = []
    seen: set[tuple] = set()
    applicable = [r for r in rules if (r.langs is None or ctx.lang in r.langs)]
    in_rust_tests = False
    for lineno, raw in enumerate(ctx.text.split("\n"), 1):
        if not raw.strip():
            continue
        # Rust: '#[cfg(test)]' sonrası genelde dosya sonuna kadar birim testleridir -> test bağlamı
        if not in_rust_tests and ctx.path.endswith(".rs") and raw.lstrip().startswith("#[cfg(test)]"):
            in_rust_tests = True
        # Yapısal kural RG-OBF-003: tek satırda aşırı uzun kod (regex ile değil uzunlukla)
        if len(raw) > 20000 and ctx.lang in ("python", "shell", "powershell"):
            out.append(Finding("RG-OBF-003", "Tek satırda aşırı uzun kod (obfüske şüphesi)", Severity.LOW, "low",
                               "obfuscation", ctx.path, lineno, sanitize(raw[:120]) + "…",
                               "Okunamaz tek satır; gizleme olabilir (minify edilmiş kod da olabilir).",
                               "Orijinal kaynakla karşılaştırın.", ("T1027",), f"satır uzunluğu {len(raw)}", ""))
        if len(out) >= max_findings:
            break
        for off, part in _chunks(raw):
            low = part.lower()
            for r in applicable:
                if r.keywords and not any(k in low for k in r.keywords):
                    continue
                m = r.pattern.search(part)
                if not m:
                    continue
                key = (r.id, lineno)
                if key in seen:
                    continue
                if r.is_secret:
                    val = m.group(r.secret_group) if r.secret_group else m.group(0)
                    if looks_like_placeholder(val):
                        continue
                    if r.id == "RG-SEC-005" and shannon_entropy(val) < 3.2:
                        continue
                seen.add(key)
                sev, ctxnote = r.severity, ""
                if in_rust_tests and not doc:
                    sev, ctxnote = _lower_sev(sev), "Rust birim testi (#[cfg(test)]): önem düşürüldü"
                elif blob and not r.is_secret:
                    sev, ctxnote = _lower_sev(sev), "gömülü veri/belge blobu: önem düşürüldü"
                elif doc and r.category in ("exec", "destructive", "persistence", "exfil", "obfuscation", "supply-chain"):
                    sev, ctxnote = _lower_sev(sev), "belge/örnek/test yolu: önem düşürüldü"
                elif doc and r.is_secret:
                    sev, ctxnote = _lower_sev(sev), "örnek/test yolu: gerçek olmayabilir"
                if not ctxnote and not r.is_secret and r.category in ("exec", "destructive", "persistence", "exfil", "obfuscation", "credential") \
                        and _DEFENSIVE.search(part):
                    sev, ctxnote = _lower_sev(sev), "savunma/anlatım bağlamı (kara liste, test, yorum): önem düşürüldü"
                snippet = sanitize(mask_line(window(part, m.start(), m.end())), 180)
                out.append(Finding(r.id, r.title, sev, r.confidence, r.category, ctx.path, lineno,
                                   snippet, r.why, r.fix, r.mitre, "", ctxnote))
    return out
