# repo-guard

**GitHub'dan indirdiğin kodu çalıştırmadan önce denetleyen, ücretsiz ve açık kaynak statik güvenlik tarayıcısı.**
Zararlı yazılım belirtilerini, sistemi çökertecek veya veri silecek komutları, API anahtarı/kimlik hırsızlığını, tedarik zinciri tuzaklarını ve yapay zekâ ajanlarını hedefleyen dosyaları arar. **Taradığı hiçbir şeyi çalıştırmaz.**

> ### Canlı test: 20 ayrı repo, gerçek veri
> repo-guard, "token kullanımını düşürüyoruz" diyen **20 ayrı GitHub reposunda** canlı olarak denendi. Toplam 26 974 dosya, yaklaşık 5 dakikada tarandı.
> * **20 reponun 0'ında** zararlı yazılım bulundu.
> * **20 reponun 1'inde** doğrulanmış bir güvenlik açığı bulundu (GitHub Actions betik enjeksiyonu; düzeltilene kadar ayrıntı gizli).
> * **20 reponun 9'unda** riskli uygulama bulundu (doğrulamasız `curl | sh` kurulumları).
> * Tüm yüksek ve kritik bulgular kaynak kodda elle doğrulandı.
>
> Yöntem, repo listesi, commit'ler ve sınırlar: **[docs/FIELD-TEST.md](docs/FIELD-TEST.md)**

## Kurulum
```bash
pip install git+https://github.com/therturk35/repo-guard   # bağımlılık yok, Python 3.9+
```

## Kullanım
```bash
repo-guard fetch sahip/depo                 # güvenli indir (hook/alt modül/LFS kapalı) + tara
repo-guard scan ./indirilen-klasor          # yerel klasör
repo-guard scan paket.zip                   # arşivi diske açmadan tara
repo-guard scan . --format prompt --min-severity medium --out fix-prompt.txt   # düzeltme promptu
repo-guard scan . --format sarif --out rg.sarif     # GitHub Code Scanning
repo-guard rules | repo-guard explain RG-GHA-002 | repo-guard selftest
```
Biçimler: `text`, `json`, `markdown`, `sarif`, `html`, `prompt`.
Çıkış kodları: `0` eşik altı · `1` `--fail-on` (varsayılan `high`) eşiği aşıldı · `2` tarama eksik (sınır veya hata). Eksik tarama asla "temiz" gibi gösterilmez.

## Açıkları kapatmak: düzeltme promptu
`--format prompt` bulguları, Claude Code, Cursor veya Copilot gibi bir ajana yapıştırılabilecek bir talimata çevirir. Ajana önce doğrulamasını, işlem gerektirmeyen eşleşmelere (test verisi, kara liste) dokunmamasını, hiçbir şeyi çalıştırmamasını ve sırları yazdırmamasını söyler. Elle kullanım ve önce/sonra kalıpları için: **[docs/FIX-PROMPT.md](docs/FIX-PROMPT.md)**

## Neyi tespit eder?
| Alan | Örnekler | MITRE |
|---|---|---|
| Kod çalıştırma / indirici | `curl\|sh`, `iex(irm …)`, base64→kabuk, reverse shell, LOLBin, madenci | T1105, T1059, T1496 |
| Kimlik / anahtar hırsızlığı | `~/.ssh`, `~/.aws/credentials`, `.npmrc`, tarayıcı şifre/çerez, cüzdan, toplu `env` + ağ gönderimi, webhook/OAST | T1552, T1555, T1041 |
| Yok etme / çökertme | `rm -rf /`, fork bomb, `dd of=/dev/sda`, gölge kopya silme, güvenlik kapatma, fidye notu | T1485, T1490, T1562 |
| Kalıcılık | `.bashrc`, cron/systemd/LaunchAgents/Run anahtarı, `authorized_keys`, `LD_PRELOAD`, `.pth` | T1546, T1053, T1098 |
| Sızmış sırlar (maskelenir) | GitHub/AWS/Slack/Stripe/Google/Anthropic/OpenAI anahtarları, PEM | T1552.001 |
| Tedarik zinciri | npm `postinstall`, `setup.py` (AST ile), typosquat, git/URL bağımlılığı | T1195 |
| GitHub Actions | pwn request, `${{ }}` betik enjeksiyonu, SHA'sız `uses:`, `write-all` | T1195.002 |
| Git meta | etkin hook, `core.fsmonitor`, `ext::` alt modül | T1546 |
| IDE / yapay zekâ ajanı | VS Code `folderOpen`, devcontainer, `.envrc`, MCP komutları, prompt injection | T1204 |
| Gizleme | Trojan Source (bidi), görünmez Unicode tag, homoglif, uzun base64, `chr()` zinciri | T1027 |
| Arşiv / ikili | zip/tar-slip, bomba, şifreli üye, symlink, uzantı sahteciliği, UPX | T1036, T1027 |

Bulgular aynı dosyada birleşince (örneğin kimlik okuma + ağ gönderimi) ayrı bir **korelasyon** bulgusu üretilir. Belge, test ve kara liste bağlamındaki eşleşmelerin önemi otomatik olarak düşürülür; neden düşürüldüğü raporda yazar.

## Güvenlik tasarımı
* Hiçbir dosya çalıştırılmaz, import edilmez, eval edilmez. `setup.py` yalnızca AST olarak ayrıştırılır.
* Symlink takip edilmez. FIFO ve aygıt dosyaları açılmaz. Arşivler diske açılmadan, boyut sınırlı olarak bellekte okunur.
* Tüm regex'ler sınırlı nicelik ve anahtar kelime ön filtresi kullanır (ReDoS testi var).
* Rapordaki alıntılar terminal kaçış dizilerinden ve bidi karakterlerinden arındırılır, sırlar maskelenir. HTML raporunda CSP kullanılır.
* Taranan repo kendi kendini "temiz" ilan edemez: ignore dosyası yalnızca `--ignore-file` ile açıkça verilir.

## Sınırlar
Statik analiz bir **işaret** verir, kanıt değil. "Bulgu yok", "güvenli" demek değildir. Çalışma anında indirilen kod, bağımlılıkların içi ve derlenmiş ikililerin davranışı görülmez. Şüpheli bir şey görürsen kodu yalıtılmış bir sanal makinede incele.

## Geliştirme
```bash
pip install -e . pytest && repo-guard selftest && python -m pytest -q
```
Kurallar `repo_guard/rules_*.py` içinde; her kural kendi pozitif/negatif örnekleriyle CI'da doğrulanır. Ayrıntılar için [CONTRIBUTING.md](CONTRIBUTING.md), güvenlik bildirimi için [SECURITY.md](SECURITY.md).

Lisans: MIT · Tuğçe Ertürk

## Kendi kendini tarar (self-scan)

CI her push'ta repo-guard'ı kendi reposunda `--fail-on high` ile çalıştırır. Kural tanımları ve örnekleri bilerek tehlikeli dizeler içerdiği için `.github/self-scan.ignore` ile hariç tutulur.
