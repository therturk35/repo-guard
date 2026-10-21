"""Sistemi çökertme / veri yok etme kuralları."""
from .catalog import add
from .models import Severity as S

add("RG-DEST-001", "Kök/ev dizinini silme (rm -rf /)", S.CRITICAL, "high", "destructive",
    r"\brm\s+(?:-[a-zA-Z]*[rR][a-zA-Z]*[fF]?|-[a-zA-Z]*[fF][a-zA-Z]*[rR])\s+(?:--no-preserve-root\s+)?(?:/|/\*|~/?|~/\*|\$HOME/?\*?|\"\$HOME\"/?\*?|/home(?:/\*)?|/etc|/usr|/var|/boot|/bin|/lib)(?:\s|$|;|&|\|)",
    "Kök veya sistem dizinlerini tümüyle siler; geri dönüşü yoktur.", "Asla çalıştırmayın.",
    keywords=("rm ",), mitre=("T1485", "T1561"),
    positives=("rm -rf /", "sudo rm -rf ~", "rm -rf --no-preserve-root /", "rm -rf $HOME/*"),
    negatives=("rm -rf ./build", "rm -rf /tmp/mydir", "rm file.txt"))

add("RG-DEST-002", "Fork bomb", S.CRITICAL, "high", "destructive",
    r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|while\s*(?:true|:|\[\s*1\s*\])\s*;?\s*do\s*(?:\$0|bash\s+\$0)[^\n]{0,20}&|os\.fork\(\)[^\n]{0,60}while\s+True|while\s+True\s*:\s*os\.fork\(\)",
    "Süreçleri katlayarak çoğaltır ve sistemi kilitler.", "Asla çalıştırmayın.",
    keywords=(":(){", ": ()", "fork", "$0"), mitre=("T1499", "T1498"),
    positives=(":(){ :|:& };:", "while True: os.fork()"), negatives=("os.fork()",))

add("RG-DEST-003", "Disk/bölüm üzerine doğrudan yazma veya biçimlendirme", S.CRITICAL, "high", "destructive",
    r"\bdd\s+[^\n]{0,60}\bof=/dev/(?:sd[a-z]|nvme\d|hd[a-z]|vd[a-z]|disk\d|mmcblk\d)|\bmkfs(?:\.\w+)?\s+[^\n]{0,20}/dev/(?:sd|nvme|hd|vd|mmcblk)|>\s*/dev/(?:sd[a-z]|nvme\d|hd[a-z])\b|\bshred\b[^\n]{0,40}/dev/|\bwipefs\b|\bformat\s+[a-z]:\s*/[yq]|\bdiskpart\b[^\n]{0,40}clean",
    "Diskin tamamını bozar veya siler.", "Asla çalıştırmayın.",
    keywords=("dd ", "mkfs", "/dev/", "wipefs", "format ", "diskpart"), mitre=("T1561.001",),
    positives=("dd if=/dev/zero of=/dev/sda", "mkfs.ext4 /dev/sda1", "format c: /y"), negatives=("dd if=a of=b.img",))

add("RG-DEST-004", "Gölge kopya / yedek / günlük silme", S.HIGH, "high", "destructive",
    r"\bvssadmin(?:\.exe)?\s+delete\s+shadows|\bwmic\s+shadowcopy\s+delete|\bbcdedit\b[^\n]{0,60}(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|\bwbadmin\s+delete\b|\bwevtutil\s+cl\b|\bClear-EventLog\b|\bhistory\s+-c\b[^\n]{0,20}(?:&&|;)[^\n]{0,20}(?:unset|rm)|\bshred\s+-[a-z]*u[a-z]*\s+[^\n]{0,30}(?:\.bash_history|/var/log)",
    "Fidye yazılımı ve saldırganlar kurtarmayı engellemek ve izleri silmek için kullanır.", "Asla çalıştırmayın.",
    keywords=("vssadmin", "shadowcopy", "bcdedit", "wbadmin", "wevtutil", "clear-eventlog", "history -c", "shred"),
    mitre=("T1490", "T1070"),
    positives=("vssadmin delete shadows /all /quiet", "wevtutil cl System"), negatives=("vssadmin list shadows",))

add("RG-DEST-005", "Toplu şifreleme + uzantı değiştirme (fidye yazılımı kalıbı)", S.HIGH, "low", "destructive",
    r"(?:\.locked|\.encrypted|\.crypt|\.enc|\.WNCRY|\.lockbit|\.ryuk)['\"]?[^\n]{0,80}(?:os\.walk|glob|rglob|Get-ChildItem)|(?:os\.walk|rglob|Get-ChildItem)[^\n]{0,160}(?:Fernet|AES\.new|\.encrypt\()|your files (?:have been|are) encrypted|HOW_TO_DECRYPT|README_FOR_DECRYPT",
    "Klasörleri gezip dosyaları şifreleme/uzantı değiştirme ve fidye notu kalıbı.", "Asla çalıştırmayın.",
    keywords=("walk", "glob", "get-childitem", "encrypted", "decrypt", "fernet", "aes"), mitre=("T1486",),
    positives=("your files have been encrypted", "for f in os.walk(p): Fernet(k).encrypt(d)"), negatives=("os.walk(path)",))

add("RG-DEST-006", "Sistem güvenliğini kapatma", S.HIGH, "medium", "destructive",
    r"\bsetenforce\s+0\b|\bufw\s+disable\b|\bsystemctl\s+(?:stop|disable|mask)\s+(?:firewalld|ufw|auditd|apparmor|falco|wazuh|clamav|fail2ban)|\bSet-MpPreference\b[^\n]{0,60}-Disable\w+\s+\$?true|\bnetsh\s+(?:advfirewall|firewall)\s+set\s+\w+\s+state\s+off|\biptables\s+-F\b|\bchattr\s+-i\b[^\n]{0,30}/etc|\bspctl\s+--master-disable|\bcsrutil\s+disable",
    "Güvenlik duvarı/antivirüs/izleme kapatılıyor.", "Gerekçesini doğrulayın.",
    keywords=("setenforce", "ufw", "systemctl", "set-mppreference", "netsh", "iptables", "chattr", "spctl", "csrutil"),
    mitre=("T1562.001",),
    positives=("Set-MpPreference -DisableRealtimeMonitoring $true", "systemctl stop auditd", "ufw disable"), negatives=("ufw status",))

add("RG-DEST-007", "Tehlikeli izin açma (chmod 777 -R /)", S.HIGH, "medium", "destructive",
    r"\bchmod\s+(?:-R\s+)?0?777\s+(?:-R\s+)?(?:/|/etc|/usr|/var|~|\$HOME)(?:\s|$)|\bchown\s+-R\s+\S+\s+/(?:\s|$)",
    "Sistem dizinlerinin izinlerini bozar.", "Çalıştırmayın.", keywords=("chmod", "chown"), mitre=("T1222",),
    positives=("chmod -R 777 /", "chmod 777 /etc"), negatives=("chmod 755 ./run.sh",))
