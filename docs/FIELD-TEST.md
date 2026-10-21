# Saha testi: "token kullanımını düşürüyoruz" diyen 20 GitHub reposu

> **Özet (gerçek veri, 21 Ekim 2026):** repo-guard, README'sinde açıkça token tasarrufu iddia eden **20 ayrı açık kaynak repoda** canlı olarak denendi.
> **20 reponun 0'ında zararlı yazılım** bulundu. **1 repoda doğrulanmış bir güvenlik açığı** bulundu: GitHub Actions betik enjeksiyonu. **9 repoda en az bir riskli uygulama** görüldü, bunların çoğu `curl | sh` kurulumu.
> Rakamların hepsi bu belgedeki yöntemle elde edildi; hiçbiri tahmin değildir.

## 1. Neden bu repolar?
Yapay zekâ kodlama ajanlarında "token tasarrufu" vaat eden araçlar hızla yayılıyor. Kullanıcılar bunları çoğu zaman tek bir `curl | sh` komutuyla kuruyor, ajanlarına MCP sunucusu veya kanca olarak ekliyor. Bu araçlar terminal çıktısını, kodu ve bazen gizli anahtarları görüyor. Bu yüzden tedarik zinciri açısından yüksek değerli bir hedef oluşturuyorlar.

## 2. Seçim ölçütü (önceden belirlendi)
1. Aday listeleri: GitHub `token-optimization` konusu ve token tasarrufu araçlarını listeleyen üç blog yazısı (aşağıdaki kaynaklar). Toplam 23 aday.
2. Dahil etme kuralı: **README.md içinde açık bir token tasarrufu/azaltma iddiası** olmalı (örn. "30-50% fewer tokens").
   * Çıkarılan 3 aday: biri README'sinde böyle bir iddia taşımıyor (şablon koleksiyonu), biri yalnızca token kullanımını *izliyor* (yönlendirici), biri 4 kod dosyalı bir rehber (araç değil).
3. Bir sonuç beğenildiği veya beğenilmediği için hiçbir repo eklenmedi ya da çıkarılmadı.

## 3. Yöntem: güvenli, yalnızca statik
* İndirme `repo-guard fetch` ile yapıldı: sığ klon, alt modül yok, git hook'ları kapalı, `ext::`/`file://` taşıyıcıları kapalı, LFS smudge kapalı.
* **Hiçbir repo kurulmadı, derlenmedi veya çalıştırılmadı.** Yalnızca dosya baytları okundu.
* Her repo kendi boş klasörüne indirildi. Tarama, motorun güncel sürümüyle tek seferde yapıldı (45 kural + 8 yapısal analizör).
* **Elle doğrulama:** Tüm yüksek/kritik bulgular kaynak kodda satır satır okundu ve üç sınıftan birine ayrıldı:
  * **açık:** doğrulanmış güvenlik açığı
  * **riskli:** kalıp gerçek ve kod bunu çalıştırıyor veya öneriyor (örn. `curl | sh`)
  * **işlem gerekmez:** güvenlik aracının kendi kara liste/dedektör kodu, test verisi, örnek anahtar
* Sonuçlar yüksek ve kritik önemdeki bulgulara dayanır.
* Etiketleme betiği: [`docs/field_triage.py`](field_triage.py).

## 4. Sonuçlar

| Ölçüm | Değer |
|---|---:|
| Taranan repo | 20 |
| Taranan dosya / toplam süre | 26 974 dosya / ~305 sn |
| Eksik kalan tarama (sınır/hata) | 0 |
| Doğrulanmış açık | 2 bulgu (1 repo) |
| Riskli uygulama | 24 bulgu (9 repo) |
| **Zararlı yazılım bulunan repo** | **0 / 20** |
| **Doğrulanmış açık bulunan repo** | **1 / 20** |
| **Riskli uygulama bulunan repo** | **9 / 20** |
| İşlem gerektiren yüksek/kritik bulgusu olmayan repo | 11 / 20 |

### Doğrulanmış açık (ayrıntı gizli)
Açık, bir GitHub Actions iş akışında herkesin açabildiği bir issue'nun başlığının doğrudan kabuk komutuna yerleştirilmesinden kaynaklanıyor (`${{ github.event.issue.title }}` → `run:`). Bu bir kötü niyet değil, yaygın bir yapılandırma hatası. **Repo adı ve satırlar, düzeltme yayınlanmadan açıklanmıyor.** Düzeltme kalıbı [FIX-PROMPT.md](FIX-PROMPT.md) içinde (RG-GHA-002).

### Riskli uygulamalar
Hepsi aynı ailedendi: indirilen kurulum betiğinin doğrulanmadan kabuğa verilmesi (`curl … | sh`). Görülen kaynaklar şunlardı: `astral.sh/uv`, `sh.rustup.rs`, `deb.nodesource.com`, `nvm`, `act`/`actionlint` ve projelerin kendi `install.sh` betikleri. Bunlar meşru yayıncılar. Risk, yayıncı sunucusu veya DNS ele geçirildiğinde ortaya çıkar. Düzeltme: indir → SHA-256 doğrula → çalıştır.

## 5. Kapsam (taranan repolar)
Aşağıdaki liste yalnızca **neyin tarandığını** gösterir. Repo başına sonuç, açıklanmamış açığı ifşa etmemek için bilerek verilmemiştir.

| # | Repo | Commit | Commit tarihi | Taranan dosya | Süre (sn) | Tarama |
|---:|---|---|---|---:|---:|---|
| 1 | [JuliusBrussee/caveman](https://github.com/JuliusBrussee/caveman) | `bad48a0e1df5` | 2026-10-17 | 1816 | 17.5 | tam |
| 2 | [SuperClaude-Org/SuperClaude_Framework](https://github.com/SuperClaude-Org/SuperClaude_Framework) | `fe68862c8ed9` | 2026-09-27 | 425 | 2.8 | tam |
| 3 | [Tura-AI/tura](https://github.com/Tura-AI/tura) | `a6d1364f0876` | 2026-10-07 | 1578 | 14.3 | tam |
| 4 | [alexgreensh/token-optimizer](https://github.com/alexgreensh/token-optimizer) | `b165eddd0de8` | 2026-10-21 | 1545 | 25.6 | tam |
| 5 | [chopratejas/headroom](https://github.com/chopratejas/headroom) | `fbf7bc3278c1` | 2026-10-17 | 2667 | 36.3 | tam |
| 6 | [cytostack/openwolf](https://github.com/cytostack/openwolf) | `8568f41aa8a9` | 2026-10-20 | 316 | 2.1 | tam |
| 7 | [edouard-claude/snip](https://github.com/edouard-claude/snip) | `bb1cb7fff5ad` | 2026-10-09 | 291 | 1.4 | tam |
| 8 | [eyaltoledano/claude-task-master](https://github.com/eyaltoledano/claude-task-master) | `c0c98d367c55` | 2026-04-23 | 1275 | 12.2 | tam |
| 9 | [jgravelle/jcodemunch-mcp](https://github.com/jgravelle/jcodemunch-mcp) | `6a7ec7884cfc` | 2026-10-21 | 1726 | 24.7 | tam |
| 10 | [juyterman1000/entroly](https://github.com/juyterman1000/entroly) | `869aeec4b5f4` | 2026-10-18 | 2068 | 28.2 | tam |
| 11 | [nadimtuhin/claude-token-optimizer](https://github.com/nadimtuhin/claude-token-optimizer) | `a1e437a8c299` | 2026-10-14 | 113 | 0.6 | tam |
| 12 | [ojuschugh1/sqz](https://github.com/ojuschugh1/sqz) | `cf2b03c80727` | 2026-10-11 | 324 | 3.6 | tam |
| 13 | [ooples/token-optimizer-mcp](https://github.com/ooples/token-optimizer-mcp) | `f0531cecceb3` | 2026-10-21 | 4794 | 49.9 | tam |
| 14 | [ratel-ai/ratel](https://github.com/ratel-ai/ratel) | `cd376f435223` | 2026-10-19 | 527 | 5.7 | tam |
| 15 | [rtk-ai/rtk](https://github.com/rtk-ai/rtk) | `5ab6291365e9` | 2026-10-21 | 831 | 8.9 | tam |
| 16 | [safishamsi/graphify](https://github.com/safishamsi/graphify) | `b90b9df7949b` | 2026-10-20 | 1098 | 15.8 | tam |
| 17 | [siliconvalleyglobal/TokenSaveOS](https://github.com/siliconvalleyglobal/TokenSaveOS) | `98fd546179db` | 2026-08-14 | 313 | 0.5 | tam |
| 18 | [tirth8205/code-review-graph](https://github.com/tirth8205/code-review-graph) | `d72e8fbf7ef5` | 2026-10-15 | 495 | 7.4 | tam |
| 19 | [yvgude/lean-ctx](https://github.com/yvgude/lean-ctx) | `1fba4a0eb724` | 2026-10-19 | 4608 | 46.8 | tam |
| 20 | [zdk/lowfat](https://github.com/zdk/lowfat) | `f3af4e4e3d28` | 2026-10-09 | 164 | 0.9 | tam |

Toplam: 26974 dosya, 305 saniye.

## 6. Sınırlar (dürüstlük notu)
* Statik analiz **kanıt değil, işarettir.** "Bulgu yok", "güvenli" anlamına gelmez. Çalışma anında indirilen kod, bağımlılıkların içi ve derlenmiş ikililerin davranışı görülmez.
* Bağımlılık ağaçları (`node_modules`, PyPI paketleri) indirilmedi, taranmadı.
* Sonuçlar belirtilen commit'lere aittir. Repolar sonradan değişmiş olabilir.

## 7. Kaynaklar (aday listeleri)
* GitHub topic: <https://github.com/topics/token-optimization>
* DeployHQ, "6 free GitHub repos that cut your Claude Code token bill": <https://www.deployhq.com/blog/free-github-repos-for-claude-code>
* Pinggy, "Open source tools to reduce AI coding agent token usage": <https://pinggy.io/blog/tools_to_reduce_ai_coding_agent_token_usage/>
* Pasquale Pillitteri, "Claude Code Token: 10 GitHub Repos": <https://pasqualepillitteri.it/en/news/1181/claude-code-token-10-github-repos-savings>
