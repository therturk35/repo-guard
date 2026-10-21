"""Sinyal ilişkilendirme ve karar (verdict) üretimi.

Tek bir sinyal çoğu zaman masumdur ("~/.ssh okumak", "curl kullanmak"). Gerçek
kötü niyet çoğunlukla BİRLEŞİMDE görünür:
  kimlik okuma  + ağ gönderimi          -> veri sızdırma (COR-001)
  indir-çalıştır + kalıcılık            -> zararlı yükleyici (COR-002)
  gizleme       + indir/çalıştır        -> gizlenmiş yükleyici (COR-003)
Aynı DOSYADA birlikte görülmeleri bu kuralları tetikler. Belge/örnek bağlamında
düşürülmüş bulgular birleşime dahil edilmez (README'deki örnek komutlar yanlış alarm yaratmasın).
"""
from __future__ import annotations

from collections import defaultdict

from .models import CONFIDENCE_WEIGHT, SEVERITY_WEIGHT, Finding, ScanReport, Severity

_EXEC_IDS = {"RG-EXEC-001", "RG-EXEC-002", "RG-EXEC-003", "RG-EXEC-005", "RG-EXEC-010", "RG-EXEC-011", "RG-EXEC-012"}
_PERSIST_PREFIX = "RG-PERS-"
_CRED_IDS = {"RG-CRED-001", "RG-CRED-002", "RG-CRED-003"}   # CRED-004 (toplu env) çok yaygın: korelasyona katılmaz
_NET_IDS = {"RG-NET-001", "RG-NET-002", "RG-NET-003", "RG-CRED-005", "RG-EXEC-001", "RG-EXEC-002", "RG-EXEC-003"}


def _real(f: Finding) -> bool:
    """Bağlam nedeniyle düşürülmemiş mi?"""
    return not f.context


def correlate(findings: list[Finding]) -> list[Finding]:
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_file[f.path].append(f)
    extra: list[Finding] = []
    for path, fs in by_file.items():
        # Belge/veri biçimleri (md/json/txt/rst) kod değildir: orada birleşim "anlatım"dır, davranış değil.
        if path.lower().split("!/")[-1].endswith((".md", ".json", ".txt", ".rst", ".markdown")):
            continue
        ids = {f.rule_id for f in fs if _real(f)}
        cats = {f.category for f in fs if _real(f)}
        if ids & _CRED_IDS and ids & _NET_IDS and "RG-CRED-005" not in ids:
            extra.append(Finding("RG-COR-001", "Kimlik verisi okuma + ağ gönderimi aynı dosyada", Severity.CRITICAL, "medium", "correlation",
                                 path, 0, "bkz. " + ", ".join(sorted(ids & (_CRED_IDS | _NET_IDS))),
                                 "Gizli dosya/ortam değişkeni okuyan ve aynı dosyada ağa veri gönderebilen kod, veri sızdırma (infostealer) davranışına uyar.",
                                 "Dosyayı satır satır okuyun; gerçek akışı doğrulamadan çalıştırmayın.", ("T1041", "T1552")))
        if ids & _EXEC_IDS and any(i.startswith(_PERSIST_PREFIX) for i in ids):
            extra.append(Finding("RG-COR-002", "İndir-çalıştır + kalıcılık aynı dosyada", Severity.CRITICAL, "medium", "correlation",
                                 path, 0, "bkz. " + ", ".join(sorted(ids)),
                                 "Dışarıdan kod getirip sistemde kalıcı hale getiren yükleyici (dropper) deseni.",
                                 "Çalıştırmayın; kaynağı inceleyin.", ("T1105", "T1547")))
        if "obfuscation" in cats and ids & _EXEC_IDS:
            extra.append(Finding("RG-COR-003", "Gizleme + indir-çalıştır aynı dosyada", Severity.HIGH, "medium", "correlation",
                                 path, 0, "bkz. " + ", ".join(sorted(ids)),
                                 "Hem içeriği gizleyen hem dışarıdan kod çalıştıran dosyalar zararlıda tipiktir.",
                                 "Gizlenmiş kısmı çözüp okuyun.", ("T1027", "T1059")))
    return findings + extra


def finalize(report: ScanReport) -> None:
    """Skor ve karar üretir; rapora yazar."""
    threat = [f for f in report.findings if f.category not in ("secret", "blind-spot")]
    report.secret_count = sum(1 for f in report.findings if f.category == "secret")
    report.score = round(sum(SEVERITY_WEIGHT[f.severity] * CONFIDENCE_WEIGHT[f.confidence] for f in threat), 1)
    crit_real = [f for f in threat if f.severity == Severity.CRITICAL and f.confidence in ("high", "medium") and _real(f)]
    high_real = [f for f in threat if f.severity >= Severity.HIGH and _real(f)]
    # "malicious_likely" için tek bir kritik eşleşme YETMEZ (savunma araçları test/imza içinde tehlikeli
    # dizeler taşır; saha testinde görüldü). Birleşim (COR) veya birbirinden farklı >=3 kritik kural gerekir.
    if any(f.rule_id.startswith("RG-COR-") for f in threat if _real(f)) or len({f.rule_id for f in crit_real}) >= 3:
        report.verdict = "malicious_likely"
    elif high_real or crit_real:
        report.verdict = "suspicious"
    elif any(f.severity >= Severity.LOW for f in report.findings):
        report.verdict = "review"
    else:
        report.verdict = "no_findings"
    if not report.complete:
        report.note = "Tarama eksik tamamlandı (sınır/hata); 'bulgu yok' sonucuna güvenmeyin."


VERDICT_TEXT = {
    "malicious_likely": "ZARARLI OLMA İHTİMALİ YÜKSEK — çalıştırmayın, inceleyin",
    "suspicious": "ŞÜPHELİ — elle inceleme gerekli",
    "review": "DÜŞÜK RİSKLİ BULGULAR — gözden geçirin",
    "no_findings": "Bulgu yok (bu 'güvenli' demek DEĞİLDİR)",
}
