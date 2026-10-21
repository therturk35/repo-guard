"""Veri modelleri: önem düzeyi, bulgu (Finding) ve tarama raporu.

Bu dosya kasıtlı olarak SADECE veri tanımlar; hiçbir analiz mantığı içermez.
Böylece "motor ne üretir?" sorusunun cevabı tek bir yerde okunabilir.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


class Severity(enum.IntEnum):
    """Bulgunun ciddiyeti. IntEnum olduğu için `>=` ile karşılaştırılabilir."""

    INFO = 0       # Bilgi: tek başına bir risk değil
    LOW = 1        # Düşük: iyi uygulama ihlali / zayıf sinyal
    MEDIUM = 2     # Orta: incelenmeli
    HIGH = 3       # Yüksek: büyük olasılıkla tehlikeli davranış
    CRITICAL = 4   # Kritik: neredeyse kesin kötü niyet veya doğrudan sızıntı

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> "Severity":
        """'high' gibi bir metni Severity'ye çevirir (CLI argümanları için)."""
        try:
            return cls[value.strip().upper()]
        except KeyError:
            raise ValueError(f"geçersiz önem düzeyi: {value!r} "
                             f"(geçerli: {', '.join(s.label for s in cls)})") from None


# Bulgunun güvenilirliği: kuralın yanlış alarm verme ihtimalini ifade eder.
CONFIDENCES = ("low", "medium", "high")

# Skorlama ağırlıkları (verdict hesabında kullanılır, bkz. correlate.py)
SEVERITY_WEIGHT = {
    Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 5,
    Severity.HIGH: 15, Severity.CRITICAL: 40,
}
CONFIDENCE_WEIGHT = {"low": 0.4, "medium": 0.7, "high": 1.0}


@dataclass(frozen=True)
class Finding:
    """Tek bir bulgu. Değiştirilemez (frozen) ki rapor üretimi sırasında bozulmasın."""

    rule_id: str                  # örn. RG-EXEC-001
    title: str                    # kısa başlık
    severity: Severity
    confidence: str               # low | medium | high
    category: str                 # exec, credential, exfil, secret, supply-chain, ...
    path: str                     # taranan kökten göreli yol (arşiv içi: "a.zip!/x")
    line: int                     # 1 tabanlı satır; 0 = satır yok / dosya geneli
    snippet: str                  # temizlenmiş + sırları maskelenmiş kısa alıntı
    why: str                      # neden riskli (kuraldan)
    fix: str                      # ne yapmalı (kuraldan)
    mitre: tuple[str, ...] = ()   # MITRE ATT&CK teknik kimlikleri
    detail: str = ""              # bu bulguya özel ek bilgi
    context: str = ""             # önem düşürme gibi bağlam notu (örn. "belge dosyası")


@dataclass
class ScanReport:
    """Bir taramanın tüm sonucu."""

    target: str
    version: str
    started: str                  # ISO zaman
    seconds: float = 0.0
    files_scanned: int = 0
    bytes_read: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)    # taramayı EKSİK bırakan sorunlar
    skipped: list[str] = field(default_factory=list)   # bilerek atlananlar (bilgi)
    complete: bool = True         # False ise sonuç eksik olabilir
    score: float = 0.0            # ağırlıklı tehdit skoru
    verdict: str = "no_findings"  # malicious_likely | suspicious | review | no_findings
    secret_count: int = 0         # sızdırılmış gizli bilgi bulgusu sayısı (tehdit skorundan ayrı)
    ignored_count: int = 0        # --ignore-file ile bastırılan bulgu sayısı
    note: Optional[str] = None
