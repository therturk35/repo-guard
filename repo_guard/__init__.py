"""repo-guard: GitHub'dan indirilen kodu ÇALIŞTIRMADAN (statik) denetleyen güvenlik motoru.

Neyi arar?
  * Zararlı yazılım belirtileri   (indir-çalıştır, reverse shell, gizlenmiş yük, miner ...)
  * Sistemi çökertme/yok etme     (fork bomb, rm -rf /, disk silme ...)
  * API anahtarı / kimlik hırsızlığı (SSH/AWS/tarayıcı verisi okuyup ağa gönderme)
  * Tedarik zinciri tuzakları     (npm/pip kurulum betikleri, typosquatting, GitHub Actions açıkları)
  * Arşiv saldırıları             (zip-slip, zip-bomb, şifreli arşiv)
  * Gizli karakter hileleri       (Trojan Source, görünmez Unicode)

ÖNEMLİ İLKE: Bu motor taranan hiçbir dosyayı ASLA çalıştırmaz, import etmez, eval etmez.
Yalnızca baytları okur ve örüntü/yapı analizi yapar. "Bulgu yok" sonucu "güvenli" demek DEĞİLDİR.
"""

__version__ = "0.1.0"

# Herkese açık API (kütüphane olarak kullanım için)
from .models import Finding, ScanReport, Severity  # noqa: E402
from .limits import Limits  # noqa: E402
from .scanner import Scanner  # noqa: E402

__all__ = ["Scanner", "Limits", "Finding", "ScanReport", "Severity", "__version__"]
