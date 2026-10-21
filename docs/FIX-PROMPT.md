# Düzeltme promptu: açıkları yapay zekâ ajanınla kapat

repo-guard bulguları bulur. Bu sayfa ise onları **güvenle düzeltmenin** yolunu anlatır.

## A) Otomatik: kendi depona özel prompt üret (önerilen)
```bash
pip install git+https://github.com/therturk35/repo-guard
repo-guard scan . --format prompt --min-severity medium --out fix-prompt.txt
```
`fix-prompt.txt` içeriğini Claude Code, Cursor, Copilot Chat gibi bir kodlama ajanına yapıştır. Prompt; bulguları, her birinin önerilen düzeltmesini ve şu kuralları içerir: önce doğrula, işlem gerektirmeyen eşleşmeye dokunma, hiçbir şeyi çalıştırma, sırları yazdırma. Sırlar raporda zaten maskelidir.

## B) Elle: genel prompt (kopyala-yapıştır)
```text
Bu depoda güvenlik sertleştirmesi yap. Hiçbir betiği/kurulumu çalıştırma, sadece dosya düzenle.
Her değişiklikten önce ilgili kodu oku; test verisi, kara liste veya belge örneğine dokunma.
1) .github/workflows: run: içindeki ${{ github.event.* }} (issue/PR başlığı, gövde, branch adı)
   değerlerini adımın env: bloğuna taşı, kabukta "$DEGISKEN" olarak çift tırnakla kullan.
   uses: satırlarını 40 haneli commit SHA'sına sabitle; permissions: en az yetki (contents: read).
   pull_request_target içinde PR kodunu checkout etme.
2) curl|sh / iwr|iex kurulumlarını: indir → SHA-256 doğrula → çalıştır biçimine çevir.
3) Koddaki gerçek anahtarları kaldır, ortam değişkenine taşı; bana hangi anahtarları
   İPTAL etmem gerektiğini listele (değerleri yazdırma).
4) package.json pre/postinstall betiklerinde ağ erişimi varsa kaldır veya açık onaya bağla.
5) .mcp.json / .claude/settings.json / devcontainer / .vscode/tasks.json içindeki otomatik
   komutlarda "npx -y paket@latest" yerine sabit sürüm kullan.
Bitince: değişen dosyalar + her madde için (düzeltildi / gerek yok / benim kararım gerekli).
```

## Kalıplar (önce → sonra)
**GitHub Actions betik enjeksiyonu (RG-GHA-002)**
```yaml
# ÖNCE (açık): başlık kabuğa doğrudan yerleşir
- run: echo '${{ github.event.issue.title }}'
# SONRA (güvenli)
- env:
    TITLE: ${{ github.event.issue.title }}
  run: printf '%s\n' "$TITLE"
```
**İndir-çalıştır (RG-EXEC-001)**
```bash
# ÖNCE
curl -fsSL https://example.com/install.sh | sh
# SONRA
curl -fsSLo install.sh https://example.com/install.sh
echo "<yayıncının_sha256_değeri>  install.sh" | sha256sum -c - && sh install.sh
```
**Sızmış anahtar (RG-SEC-*)**: Sıra önemli. 1) Anahtarı servisten iptal et. 2) Koddan kaldır. 3) `git filter-repo` ile geçmişten temizle. Sadece silmek yetmez, çünkü anahtar git geçmişinde kalır.
