"""Açığa çıkmış gizli bilgi (sır) kuralları.

Bu kurallar "repo yazarının kazara commit ettiği anahtarı" bulur. Bulunan değer
RAPORDA ASLA TAM YAZILMAZ (maskelenir). Örnekler, depoyu GitHub'ın push-koruması
tetiklemesin diye çalışma anında parçalardan birleştirilir.
"""
from .catalog import add
from .models import Severity as S

_A = "a1B2c3D4" * 5   # 40 karakterlik sahte rastgele gövde

add("RG-SEC-001", "GitHub kişisel erişim jetonu", S.HIGH, "high", "secret",
    r"\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b",
    "Geçerliyse depo/hesap erişimi verir.", "Jetonu iptal edin (revoke) ve geçmişten temizleyin.",
    keywords=("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"), mitre=("T1552.001",),
    positives=("t = '" + "ghp_" + _A[:36] + "'",), negatives=("ghp_short",), secret_group=1, is_secret=True)

add("RG-SEC-002", "AWS erişim anahtarı kimliği", S.HIGH, "high", "secret",
    r"\b((?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16})\b",
    "AWS hesabına erişim anahtarı kimliği.", "Anahtarı devre dışı bırakıp döndürün.",
    keywords=("akia", "asia", "aida", "aroa"), mitre=("T1552.001",),
    positives=("k = '" + "AKIA" + "ABCDEFGHIJKLMNOP" + "'",), negatives=("AKIAshort",), secret_group=1, is_secret=True)

add("RG-SEC-003", "Özel anahtar bloğu (PEM)", S.CRITICAL, "high", "secret",
    r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)(?=\s*$|\\n|\\r|['\"]?\s*[A-Za-z0-9+/]{40,})",
    "Özel anahtar herkese açık depoda bulunmamalıdır.", "Anahtarı geçersiz kılıp yenisini üretin.",
    keywords=("private key",), mitre=("T1552.004",),
    positives=("-----BEGIN " + "RSA PRIVATE KEY-----",), negatives=("-----BEGIN PUBLIC KEY-----", "(r'-----BEGIN RSA PRIVATE KEY-----', 'RSA key')"), secret_group=1, is_secret=True)

add("RG-SEC-004", "Slack / Stripe / Google / Anthropic / OpenAI tipi API anahtarı", S.HIGH, "high", "secret",
    r"\b(xox[baprs]-[A-Za-z0-9-]{20,}|sk_live_[A-Za-z0-9]{20,}|rk_live_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_\-]{35}|sk-ant-[A-Za-z0-9_\-]{30,}|sk-(?:proj-)?[A-Za-z0-9_\-]{40,}|npm_[A-Za-z0-9]{36}|pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})\b",
    "Hizmet API anahtarı; geçerliyse maliyet ve veri sızıntısı yaratır.", "İlgili hizmetten iptal edin.",
    keywords=("xox", "sk_live", "rk_live", "aiza", "sk-", "npm_", "pypi-"), mitre=("T1552.001",),
    positives=("k='" + "sk_li" + "ve_" + _A[:24] + "'", "k='" + "AI" + "za" + _A[:35] + "'"),
    negatives=("sk-short",), secret_group=1, is_secret=True)

add("RG-SEC-005", "Koda gömülü parola/jeton ataması", S.MEDIUM, "low", "secret",
    r"(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9/+_\-=.]{16,})['\"]",
    "Sabit kodlanmış gizli bilgi şüphesi (örnek/yer tutucu değerler elenir).", "Ortam değişkeni veya gizli yönetici kullanın.",
    keywords=("password", "passwd", "secret", "api_key", "api-key", "apikey", "token"), mitre=("T1552.001",),
    positives=("api_key = '" + _A[:24] + "'",), negatives=("api_key = os.environ['K']",),
    secret_group=1, is_secret=True)
