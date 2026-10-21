# repo-guard

[English](README.md) | [Türkçe](README.tr.md)

**A free, open-source static security scanner that inspects code downloaded from GitHub *before* you run it.**
It looks for malware indicators, destructive commands, credential theft, supply-chain traps, and files that target AI coding agents. **It never executes anything it scans.**

> ### Field test: 20 repos, real data
> repo-guard was run against **20 GitHub repos** that advertise "reduce your token usage" (26,974 files, ~5 minutes).
> * **0 of 20** contained malware.
> * **1 of 20** had a verified vulnerability (GitHub Actions script injection; details withheld until fixed).
> * **9 of 20** shipped risky install patterns (unverified `curl | sh`).
> * Every high/critical finding was manually verified in source.
>
> Method and limits: [docs/FIELD-TEST.md](docs/FIELD-TEST.md) (Turkish)

## Install
```bash
pip install git+https://github.com/therturk35/repo-guard   # zero dependencies, Python 3.9+
```

## Usage
```bash
repo-guard fetch owner/repo            # safe download (hooks/submodules/LFS disabled) + scan
repo-guard scan ./downloaded-folder    # local directory
repo-guard scan package.zip            # scans archives without extracting to disk
repo-guard scan . --format sarif --out rg.sarif   # GitHub Code Scanning
repo-guard rules | repo-guard explain RG-GHA-002 | repo-guard selftest
```
Formats: `text`, `json`, `markdown`, `sarif`, `html`, `prompt`.
Exit codes: `0` below threshold, `1` `--fail-on` threshold exceeded (default `high`), `2` incomplete scan. An incomplete scan is never reported as clean.

## What it detects (mapped to MITRE ATT&CK)
Download-and-execute, credential/key theft, destructive commands, persistence, leaked secrets (masked), supply-chain tricks (npm `postinstall`, `setup.py` via AST, typosquats), GitHub Actions injection (pwn request, `${{ }}`), malicious git hooks, IDE/AI-agent abuse (VS Code `folderOpen`, MCP commands, prompt injection), obfuscation (Trojan Source, invisible Unicode), and archive attacks (zip-slip, bombs, symlinks).
Findings that co-occur in one file (e.g. credential read + network send) are correlated into a single higher-severity finding.

## Security design
* Nothing is executed, imported, or eval'd. `setup.py` is parsed as an AST only.
* Symlinks are not followed; FIFOs and devices are never opened; archives are read in memory with size limits.
* Bounded regexes with keyword pre-filters (ReDoS-tested). Report excerpts are sanitized; secrets are masked; HTML reports use a CSP.
* A scanned repo cannot declare itself clean: the ignore file is honored only via an explicit `--ignore-file`.

## Self-scan
CI runs repo-guard on its own repo on every push with `--fail-on high`. Rule definitions and docs intentionally contain dangerous strings, so they are excluded via `.github/self-scan.ignore`.

## Limits
Static analysis gives a **signal, not proof**. "No findings" does not mean "safe". Runtime-downloaded code, dependency internals, and compiled binaries are not inspected. If something looks suspicious, inspect it in an isolated VM.

License: MIT
