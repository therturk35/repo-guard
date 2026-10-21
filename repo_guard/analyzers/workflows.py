"""GitHub Actions iş akışı analizörü (.github/workflows/*.yml).

Başlıca açıklar:
  * pull_request_target + PR kodunu checkout -> fork'tan gelen kod GİZLİ ANAHTARLARLA çalışır ("pwn request").
  * `run:` içinde ${{ github.event.* }} -> issue başlığı/PR adı gibi saldırgan metni kabuk komutuna enjekte eder.
  * `uses:` sabit SHA yerine etiket/dal -> aksiyon sahibi ele geçirilirse tedarik zinciri saldırısı (tj-actions olayı).
  * `permissions: write-all` / `secrets: inherit` -> gereğinden geniş yetki.
Burada YAML ayrıştırıcı kullanmadan (ek bağımlılık/çalışma riski olmasın diye) satır tabanlı bakarız.
"""
from __future__ import annotations

import re

from ..models import Severity as S
from .base import FileCtx, make

_INJ = re.compile(r"\$\{\{\s*(?:github\.event\.(?:issue|pull_request|comment|review|head_commit|commits|pages|discussion)[\w.\[\]*]*(?:title|body|author\.name|label|ref|email|message|text)|github\.head_ref|github\.event\.workflow_run\.head_branch)", re.I)
_USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)")
_SHA = re.compile(r"@[0-9a-f]{40}\b")


def is_workflow(path: str) -> bool:
    p = path.replace("\\", "/").lower()
    return ".github/workflows/" in p and p.endswith((".yml", ".yaml"))


def analyze(ctx: FileCtx):
    if not ctx.is_text or not is_workflow(ctx.path):
        return []
    out = []
    text = ctx.text
    lines = text.split("\n")
    has_prt = re.search(r"^\s*pull_request_target\b|on:\s*\[?[^\n]*pull_request_target", text, re.M) is not None
    if has_prt and "actions/checkout" in text and re.search(r"github\.event\.pull_request\.head\.(?:sha|ref)|refs/pull/\S+/(?:head|merge)", text):
        out.append(make("RG-GHA-001", "pull_request_target ile PR kodunu checkout ('pwn request')", S.HIGH, "high", "ci", ctx.path, 0,
                        "pull_request_target + head.sha/ref checkout",
                        "Fork'tan gelen güvenilmez kod, depo gizli anahtarları ve yazma yetkisiyle çalışır.",
                        "pull_request kullanın veya PR kodunu çalıştırmayın.", ("T1195.002", "T1552")))
    in_run = False
    for n, ln in enumerate(lines, 1):
        s = ln.strip()
        if re.match(r"-?\s*run:", s):
            in_run = True
        elif re.match(r"-?\s*(?:-\s*)?(?:name|uses|with|env|if|id|shell|steps|working-directory|continue-on-error|timeout-minutes):", s):
            in_run = False          # yeni anahtar: run gövdesi bitti
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*:\s*\$\{\{", s):
            continue                # env: eşlemesi = önerilen GÜVENLİ kullanım
        if _INJ.search(ln) and (in_run or "run:" in ln or "script:" in ln):
            out.append(make("RG-GHA-002", "Betik enjeksiyonu: saldırgan kontrollü ${{ }} ifadesi komutta", S.HIGH, "medium", "ci", ctx.path, n, s,
                            "Issue/PR başlığı gibi alanlar kabuk komutuna doğrudan yerleşir; komut enjekte edilebilir.",
                            "Değeri ortam değişkenine atayıp tırnaklı kullanın.", ("T1059.004",)))
        m = _USES.match(ln)
        if m:
            ref = m.group(1)
            if not ref.startswith(("./", "docker://")) and not _SHA.search(ref):
                owner = ref.split("/")[0].lower()
                official = owner in ("actions", "github")
                out.append(make("RG-GHA-003", "Aksiyon sabit SHA'ya sabitlenmemiş", S.LOW if official else S.MEDIUM, "low", "ci", ctx.path, n, ref,
                                "Etiket/dal taşınabilir; aksiyon sahibi ele geçirilirse kötü kod çalışır.",
                                "40 haneli commit SHA'sına sabitleyin.", ("T1195.002",)))
    if re.search(r"permissions:\s*write-all", text):
        out.append(make("RG-GHA-004", "permissions: write-all", S.MEDIUM, "medium", "ci", ctx.path, 0, "permissions: write-all",
                        "Gereğinden geniş GITHUB_TOKEN yetkisi.", "En az yetki ilkesi uygulayın.", ("T1078",)))
    if re.search(r"secrets:\s*inherit", text):
        out.append(make("RG-GHA-005", "secrets: inherit", S.LOW, "low", "ci", ctx.path, 0, "secrets: inherit",
                        "Tüm gizli anahtarlar çağrılan iş akışına geçer.", "Yalnız gerekenleri geçirin.", ("T1552",)))
    if re.search(r"\bself-hosted\b", text) and has_prt:
        out.append(make("RG-GHA-006", "Self-hosted runner + pull_request_target", S.HIGH, "medium", "ci", ctx.path, 0, "self-hosted",
                        "Fork kodu kendi makinenizde çalışabilir.", "Self-hosted runner'ı güvenilmez PR'a açmayın.", ("T1190",)))
    return out
