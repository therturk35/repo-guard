"""Rapor biçimleri: text (terminal), json, markdown, sarif, html.

Tüm çıktılar bulguların ZATEN temizlenmiş (sanitize + sır maskeleme) alıntılarını
kullanır. HTML'de ayrıca html.escape uygulanır. Böylece taranan zararlı içerik
raporu açan kişiye saldıramaz (terminal kaçışı, XSS).
"""
from __future__ import annotations

import html
import json

from .correlate import VERDICT_TEXT
from .models import ScanReport, Severity
from .textutil import sanitize


def _d(f):
    return {"rule_id": f.rule_id, "title": f.title, "severity": f.severity.label, "confidence": f.confidence, "category": f.category,
            "path": sanitize(f.path, 300), "line": f.line, "snippet": f.snippet, "why": f.why, "fix": f.fix, "mitre": list(f.mitre),
            "detail": f.detail, "context": f.context}


def to_json(r: ScanReport) -> str:
    return json.dumps({"tool": "repo-guard", "version": r.version, "target": sanitize(r.target, 300), "started": r.started, "seconds": r.seconds,
                       "files_scanned": r.files_scanned, "bytes_read": r.bytes_read, "complete": r.complete, "verdict": r.verdict,
                       "score": r.score, "secret_findings": r.secret_count, "ignored": r.ignored_count, "errors": r.errors,
                       "skipped_count": len(r.skipped), "findings": [_d(f) for f in r.findings]}, ensure_ascii=False, indent=2)


def to_text(r: ScanReport, min_sev: Severity = Severity.LOW, max_items: int = 60) -> str:
    L = [f"repo-guard {r.version} — {sanitize(r.target, 200)}",
         f"Karar: {VERDICT_TEXT[r.verdict]}   skor={r.score}   dosya={r.files_scanned}   süre={r.seconds}s   sızan-sır={r.secret_count}"]
    if not r.complete:
        L.append("UYARI: tarama EKSİK — " + "; ".join(r.errors[:3]))
    shown = [f for f in r.findings if f.severity >= min_sev]
    for f in shown[:max_items]:
        loc = f"{sanitize(f.path, 120)}" + (f":{f.line}" if f.line else "")
        L.append(f"[{f.severity.label.upper():8}] {f.rule_id} {f.title}\n    {loc}  (güven: {f.confidence})" + (f"  [{f.context}]" if f.context else "")
                 + (f"\n    > {f.snippet}" if f.snippet else ""))
    if len(shown) > max_items:
        L.append(f"... ve {len(shown) - max_items} bulgu daha (--format json ile tamamı)")
    if not shown:
        L.append("Gösterilecek bulgu yok.")
    L.append("Not: Statik analizdir; 'bulgu yok' güvenlik garantisi değildir.")
    return "\n".join(L)


def to_markdown(r: ScanReport, min_sev: Severity = Severity.LOW) -> str:
    L = [f"# repo-guard raporu — `{sanitize(r.target, 200)}`", "",
         f"- **Karar:** {VERDICT_TEXT[r.verdict]}", f"- **Skor:** {r.score} · **Dosya:** {r.files_scanned} · **Süre:** {r.seconds}s · **Sızan sır bulgusu:** {r.secret_count}",
         f"- **Tarama tamam mı:** {'evet' if r.complete else 'HAYIR — ' + '; '.join(r.errors[:3])}", ""]
    shown = [f for f in r.findings if f.severity >= min_sev]
    if not shown:
        L.append("Bulgu yok.")
    for f in shown:
        loc = f"`{sanitize(f.path, 120)}`" + (f":{f.line}" if f.line else "")
        L += [f"### {f.rule_id} · {f.title} ({f.severity.label}, güven: {f.confidence})", f"- Konum: {loc}"
              + (f" _({f.context})_" if f.context else ""), f"- Alıntı: `{f.snippet.replace('`', chr(39))}`" if f.snippet else "- Alıntı: —",
              f"- Neden: {f.why}", f"- Ne yapmalı: {f.fix}", f"- MITRE: {', '.join(f.mitre) or '—'}", ""]
    return "\n".join(L)


def to_sarif(r: ScanReport) -> str:
    rules, seen = [], set()
    for f in r.findings:
        if f.rule_id not in seen:
            seen.add(f.rule_id)
            rules.append({"id": f.rule_id, "name": f.title, "shortDescription": {"text": f.title}, "fullDescription": {"text": f.why},
                          "help": {"text": f.fix}, "properties": {"tags": ["security", f.category] + list(f.mitre)}})
    lvl = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note"}
    results = [{"ruleId": f.rule_id, "level": lvl[f.severity], "message": {"text": f"{f.title}: {f.snippet}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": sanitize(f.path.split("!/")[0], 300)}, "region": {"startLine": max(f.line, 1)}}}]}
               for f in r.findings]
    return json.dumps({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
                       "runs": [{"tool": {"driver": {"name": "repo-guard", "version": r.version, "rules": rules}}, "results": results}]}, ensure_ascii=False, indent=2)


def to_html(r: ScanReport) -> str:
    e = html.escape
    rows = "".join(f"<tr><td>{e(f.severity.label)}</td><td>{e(f.rule_id)}</td><td>{e(f.title)}</td><td>{e(sanitize(f.path, 200))}:{f.line}</td><td><code>{e(f.snippet)}</code></td></tr>"
                   for f in r.findings)
    return ("<!doctype html><meta charset=utf-8><meta http-equiv=Content-Security-Policy content=\"default-src 'none'; style-src 'unsafe-inline'\">"
            f"<title>repo-guard</title><style>body{{font:14px system-ui;margin:2rem}}td,th{{border:1px solid #ccc;padding:4px 8px;text-align:left}}</style>"
            f"<h1>repo-guard — {e(sanitize(r.target, 200))}</h1><p><b>{e(VERDICT_TEXT[r.verdict])}</b> · skor {r.score}</p>"
            f"<table><tr><th>Önem</th><th>Kural</th><th>Başlık</th><th>Konum</th><th>Alıntı</th></tr>{rows}</table>")


FORMATS = {"text": to_text, "json": to_json, "markdown": to_markdown, "sarif": to_sarif, "html": to_html}


# ---------------------------------------------------------------------------------------------
# Düzeltme promptu: bulguları, bir yapay zekâ kodlama ajanına (Claude Code, Cursor, Copilot...)
# yapıştırılabilecek talimata çevirir. Ajan HER bulguyu önce doğrulamalı; işlem gerektirmeyeni düzeltmeye
# çalışmamalı. Sırlar zaten maskelenmiş gelir; prompt asla tam sır içermez.
# ---------------------------------------------------------------------------------------------
FIX_GUIDE = {
    "RG-GHA-002": "Saldırgan kontrollü ${{ github.event.* }} ifadesini `run:` içinden çıkar; adımın `env:` bloğuna ata (örn. TITLE: ${{ github.event.issue.title }}) ve kabukta yalnızca \"$TITLE\" olarak, çift tırnakla kullan. JSON gerekiyorsa `jq -n --arg t \"$TITLE\" '{title:$t}'` ile üret.",
    "RG-GHA-001": "pull_request_target iş akışında PR kodunu checkout etme. Gerekmiyorsa `pull_request` tetikleyicisine geç; gerekiyorsa iki aşamalı (workflow_run) yapı kur ve sırları güvenilmeyen koda verme.",
    "RG-GHA-003": "`uses:` satırlarını 40 haneli commit SHA'sına sabitle; yanına sürümü yorum olarak yaz (örn. @<sha> # v4.1.1). Dependabot ile güncel tut.",
    "RG-GHA-004": "`permissions:` alanını en az yetkiyle tanımla (örn. contents: read).",
    "RG-EXEC-001": "`curl ... | sh` yerine betiği dosyaya indir, yayıncının SHA-256 değeriyle doğrula (`sha256sum -c`), sonra çalıştır; mümkünse paket yöneticisi veya sürümü sabitlenmiş resmi aksiyon kullan.",
    "RG-EXEC-002": "İndirilen kodu doğrudan yorumlayıcıya verme; indir, hash doğrula, sonra çalıştır.",
    "RG-EXEC-003": "PowerShell'de `iex (irm ...)` yerine dosyayı indir, `Get-FileHash` ile doğrula, imzalıysa `Get-AuthenticodeSignature` kontrol et.",
    "RG-EXEC-006": "exec/eval ile dinamik kod yükleme gerçekten gerekli mi? Gerekliyse yalnızca imzalı/hash doğrulanmış yerel dosyayı yükle; kodlanmış (base64/zlib) yük kullanma.",
    "RG-SEC": "Sır gerçekse: ÖNCE ilgili serviste anahtarı iptal et/döndür, sonra koddan kaldırıp ortam değişkenine veya gizli yöneticisine taşı, git geçmişinden temizle (git filter-repo). Test verisiyse açıkça sahte bir değer kullan (örn. 'ghp_' + 'x'*36) ve dosyayı test dizinine taşı.",
    "RG-PKG-001": "npm yaşam döngüsü betiğini kaldır veya yalnızca derleme yapan, ağa çıkmayan bir komuta indir; kullanıcılara `npm install --ignore-scripts` öner.",
    "RG-PKG": "Bağımlılıkları resmi kayıt defterinden, sürüm + hash sabitleyerek al (pip: --require-hashes, npm: lockfile).",
    "RG-CFG": "Depoyu açınca/ajan başlayınca otomatik çalışan komutları kaldır veya yalnızca açık kullanıcı onayıyla çalışacak hale getir; `npx -y paket@latest` yerine sürüm sabitle.",
    "RG-UNI": "Görünmez/çift yönlü Unicode karakterleri kaynak koddan temizle; CI'a bu karakterleri reddeden bir kontrol ekle.",
    "RG-ARC": "Şüpheli arşivi depodan çıkar; gerekiyorsa kaynağından yeniden üret ve hash'ini belgeleyin.",
    "RG-BIN": "Derlenmiş ikiliyi depodan kaldır; kaynaktan CI'da derle ve sürüm eki olarak yayınla.",
}


def _guide(rule_id: str) -> str:
    if rule_id in FIX_GUIDE:
        return FIX_GUIDE[rule_id]
    for k, v in FIX_GUIDE.items():
        if rule_id.startswith(k):
            return v
    return ""


def to_prompt(r: ScanReport, min_sev: Severity = Severity.MEDIUM) -> str:
    shown = [f for f in r.findings if f.severity >= min_sev and not f.context]
    L = ["Sen bu depodaki güvenlik bulgularını düzelten dikkatli bir mühendissin. Aşağıdaki liste repo-guard (statik tarayıcı) çıktısıdır.",
         "Kurallar:",
         "1. Her bulguyu önce kaynakta OKU ve doğrula. Kara liste/dedektör kodu, test verisi veya belge örneğiyse DOKUNMA; 'işlem gerekmez' diye raporla.",
         "2. Gerçek olanları en küçük, davranışı bozmayan değişiklikle düzelt. Hiçbir betiği/kurulumu bu iş için ÇALIŞTIRMA; yalnızca dosya düzenle.",
         "3. Sır bulgusunda değeri asla yazdırma veya commit mesajına koyma; kullanıcıya 'önce anahtarı iptal et' de.",
         "4. Bitince: değiştirilen dosyalar, her bulgu için (düzeltildi / işlem gerekmez / kullanıcı kararı gerekli) ve testleri nasıl çalıştıracağını yaz.",
         "", f"Bulgular ({len(shown)} adet, önem >= {min_sev.label}):"]
    for i, f in enumerate(shown, 1):
        loc = sanitize(f.path, 160) + (f":{f.line}" if f.line else "")
        L.append(f"{i}. [{f.severity.label}] {f.rule_id} {f.title} — {loc}")
        if f.snippet:
            L.append(f"   Alıntı: {f.snippet}")
        g = _guide(f.rule_id) or f.fix
        L.append(f"   Önerilen düzeltme: {g}")
    if not shown:
        L.append("(Bu eşikte bulgu yok.)")
    return "\n".join(L)


FORMATS["prompt"] = to_prompt
