"""Saha testi elle doğrulama (triage) etiketleri + FIELD-TEST tablolarını JSON çıktılarından üretir.

Etiketler insan incelemesiyle verildi (her HIGH/CRITICAL bulgu kaynak kodda okundu):
  acik   = doğrulanmış güvenlik açığı (kötü niyet değil)
  riskli = kalıp gerçek ve kod/doküman bunu ÇALIŞTIRIYOR veya öneriyor (örn. curl|sh kurulum)
  islem_yok = işlem gerekmez (aracın kendi kara liste/dedektör kodu, test verisi, örnek anahtar)
Kullanım: python3 -I docs/field_triage.py <json_klasörü> <commits.txt>
"""
import collections, json, os, sys

def label(repo, f):
    r, p, line = f["rule_id"], f["path"], f["line"]
    if repo == "eyaltoledano__claude-task-master" and r == "RG-GHA-002":
        return "acik"
    if repo in ("Tura-AI__tura", "alexgreensh__token-optimizer", "jgravelle__jcodemunch-mcp"):
        return "islem_yok"
    if repo == "zdk__lowfat":
        return "riskli" if p.endswith("commands/plugin.rs") else "islem_yok"
    if repo == "yvgude__lean-ctx":
        return "riskli" if r == "RG-EXEC-001" else "islem_yok"
    if repo == "JuliusBrussee__caveman":
        return "islem_yok" if p == "src/tools/caveman-init.js" else "riskli"
    return "riskli"     # kalan: curl|sh kurulum komutları (uv, rustup, nodesource, nvm, act, kendi install.sh)

def main(outdir, commits):
    sha = {}
    for ln in open(commits):
        n, h, d = ln.split()
        sha[n] = (h, d)
    rows, tot = [], collections.Counter()
    repo_cls = collections.Counter()
    for fn in sorted(os.listdir(outdir)):
        repo = fn[:-5]
        r = json.load(open(os.path.join(outdir, fn)))
        act = [f for f in r["findings"] if f["severity"] in ("critical", "high") and not f["context"]]
        c = collections.Counter(label(repo, f) for f in act)
        tot.update(c)
        cls = "açık" if c["acik"] else ("riskli uygulama" if c["riskli"] else "temiz (H/C yok veya yalnız işlem gerekmeyen)")
        repo_cls[cls] += 1
        sev = collections.Counter(f["severity"] for f in r["findings"])
        rows.append((repo.replace("__", "/"), sha[repo][0][:12], sha[repo][1], r["files_scanned"], r["seconds"],
                     sev["critical"] + sev["high"], len(act), c["riskli"], c["islem_yok"], "tam" if r["complete"] else "EKSİK"))
    return rows, tot, repo_cls

if __name__ == "__main__":
    rows, tot, rc = main(sys.argv[1], sys.argv[2])
    print("| Repo | Commit | Tarih | Dosya | Süre (sn) | H/C ham | H/C bağlam sonrası | Riskli uygulama | İşlem gerekmez | Tarama |")
    print("|---|---|---|---:|---:|---:|---:|---:|---:|---|")
    for x in rows:
        print("| " + " | ".join(str(v) for v in x) + " |")
    print("\nETIKET", dict(tot), "\nREPO", dict(rc))
