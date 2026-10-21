# Katkı
* Yeni kural: ilgili `repo_guard/rules_*.py` dosyasına `add(...)` ile ekle. **En az bir `positives` ve bir `negatives` örneği zorunludur.** `repo-guard selftest` ile doğrula.
* Regex'lerde sınırsız `.*` yerine sınırlı nicelik (`{0,200}`) kullan ve `keywords` ön filtresi ver (ReDoS koruması).
* Gerçek sır içeren örnek ekleme; örnekleri parçalardan birleştir (bkz. `rules_secrets.py`).
* `python -m pytest -q` geçmeden PR açma.
