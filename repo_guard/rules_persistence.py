"""Kalıcılık (persistence) ve ayrıcalık yükseltme kuralları."""
from .catalog import add
from .models import Severity as S

add("RG-PERS-001", "Kabuk başlangıç dosyasına yazma", S.MEDIUM, "low", "persistence",
    r">>?\s*(?:~|\$HOME|\$\{HOME\})?/?\.?(?:bashrc|zshrc|bash_profile|profile|zprofile|zshenv)\b|\btee\s+-a\s+[^\n]{0,30}\.(?:bashrc|zshrc|profile)",
    "Her yeni terminalde zararlı komutun çalışmasını sağlar.", "Eklenen satırı inceleyin.",
    keywords=("bashrc", "zshrc", "profile", "zshenv"), mitre=("T1546.004",),
    positives=("echo 'x' >> ~/.bashrc", "echo y >> $HOME/.zshrc"), negatives=("source ~/.bashrc",))

add("RG-PERS-002", "Cron / systemd / launchd ile zamanlama", S.MEDIUM, "low", "persistence",
    r"\bcrontab\s+-|\(crontab\s+-l[^\n]{0,60}\)\s*\|\s*crontab|/etc/cron\.|/etc/systemd/system/|~/\.config/systemd/user|\bsystemctl\s+enable\b|LaunchAgents|LaunchDaemons|\bschtasks\s+/create|\bSchedule[dD]Task\b[^\n]{0,30}Register|HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|\breg\s+add\b[^\n]{0,80}\\Run\b",
    "Sistem yeniden başlasa da zararlı çalışmaya devam eder (kalıcılık).", "Neyin zamanlandığını doğrulayın.",
    keywords=("crontab", "/etc/cron", "systemd", "systemctl", "launchagents", "launchdaemons", "schtasks", "scheduledtask", "currentversion", "reg add"),
    mitre=("T1053", "T1547.001"),
    positives=("(crontab -l; echo '* * * * * x') | crontab -", "schtasks /create /tn x /tr y"), negatives=("echo cron",))

add("RG-PERS-003", "SSH authorized_keys'e anahtar ekleme", S.CRITICAL, "high", "persistence",
    r">>?\s*[^\n]{0,30}authorized_keys\b|\btee\s+-a\s+[^\n]{0,30}authorized_keys|ssh-copy-id\b",
    "Saldırganın anahtarını ekleyerek kalıcı uzak erişim sağlar.", "Eklenen anahtarın kimin olduğunu doğrulayın.",
    keywords=("authorized_keys", "ssh-copy-id"), mitre=("T1098.004",),
    positives=("echo 'ssh-rsa AAA' >> ~/.ssh/authorized_keys",), negatives=("cat authorized_keys",))

add("RG-PERS-004", "sudoers / kullanıcı ekleme / SUID", S.HIGH, "medium", "persistence",
    r"NOPASSWD\s*:\s*ALL|>>?\s*/etc/sudoers|\bvisudo\b[^\n]{0,20}-f|\buseradd\b[^\n]{0,60}-(?:o\s+-)?u\s*0\b|\bchmod\s+[ugo]*\+s\b|\bchmod\s+[2467][0-7]{3}\b[^\n]{0,30}/(?:bin|usr)|\bnet\s+user\s+\S+\s+\S+\s+/add|\bnet\s+localgroup\s+administrators",
    "Ayrıcalık yükseltme veya gizli yönetici hesabı oluşturma.", "Gerekçesini doğrulayın.",
    keywords=("nopasswd", "sudoers", "visudo", "useradd", "chmod", "net user", "net localgroup"), mitre=("T1548", "T1136"),
    positives=("echo 'u ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers", "net user x P /add"), negatives=("chmod +x run.sh",))

add("RG-PERS-005", "LD_PRELOAD / ld.so.preload (rootkit tekniği)", S.HIGH, "medium", "persistence",
    r"/etc/ld\.so\.preload|\bLD_PRELOAD\s*=\s*\S+\.so|DYLD_INSERT_LIBRARIES\s*=",
    "Her sürece kötü niyetli kütüphane enjekte eder.", "Kütüphaneyi inceleyin.",
    keywords=("ld.so.preload", "ld_preload", "dyld_insert"), mitre=("T1574.006",),
    positives=("echo /tmp/x.so > /etc/ld.so.preload",), negatives=("echo hello",))

add("RG-PERS-006", "Python .pth dosyasında çalıştırılabilir kod", S.HIGH, "high", "persistence",
    r"^\s*import\s+[^\n]{0,200}(?:exec|eval|os\.system|subprocess|base64|socket)",
    "`.pth` içinde `import ...` ile başlayan satırlar Python her açıldığında ÇALIŞIR; sessiz kalıcılık yöntemidir.",
    "Dosyayı silin ve kaynağını araştırın.", langs=("pth",), mitre=("T1546.018",),
    positives=("import os; os.system('id')",), negatives=("/usr/lib/python3/site-packages",))
