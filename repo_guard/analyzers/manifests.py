"""Paket bildirimi analizörü: package.json, setup.py, requirements*.txt, pyproject.toml.

Neden? Tedarik zinciri saldırılarının çoğu kod yerine KURULUM ANINDA çalışan
kancalarda saklanır:
  * npm: preinstall / install / postinstall / prepare betikleri `npm install` sırasında OTOMATİK çalışır.
  * pip: setup.py, `pip install` sırasında çalışan sıradan Python kodudur.
Ayrıca typosquatting: popüler paketin 1-2 harf farklı kopyası.
setup.py'yi AST ile ayrıştırırız (yani sadece SÖZDİZİMİ ağacı; kod çalıştırılmaz).
"""
from __future__ import annotations

import ast
import json
import re

from ..data_popular import POPULAR_NPM, POPULAR_PYPI
from ..models import Severity as S
from ..textutil import osa_distance
from .base import FileCtx, basename, make

_LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepublish", "prepack", "preuninstall")
_RISKY_CMD = re.compile(r"\b(curl|wget|powershell|node\s+-e|python[0-9.]*\s+-c|bash\s+-c|sh\s+-c|eval|base64|nc\b|chmod|\.exe|http://|https://)", re.I)
_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _typosquat(name: str, popular: frozenset, norm=lambda s: s.lower().replace("_", "-")):
    n = norm(name)
    if n in popular or len(n) < 5:
        return None
    for p in popular:
        if len(p) >= 5 and osa_distance(n, p, 1) == 1:
            return p
    return None


def analyze(ctx: FileCtx):
    name = basename(ctx.path).lower()
    if not ctx.is_text:
        return []
    if name == "package.json":
        return _package_json(ctx)
    if name == "setup.py":
        return _setup_py(ctx)
    if name.startswith("requirements") and name.endswith(".txt"):
        return _requirements(ctx)
    if name == "pyproject.toml":
        return _pyproject(ctx)
    return []


def _package_json(ctx):
    out = []
    try:
        pkg = json.loads(ctx.text)
    except ValueError:
        return []
    if not isinstance(pkg, dict):
        return []
    scripts = pkg.get("scripts") if isinstance(pkg.get("scripts"), dict) else {}
    for hook in _LIFECYCLE:
        cmd = scripts.get(hook)
        if not isinstance(cmd, str):
            continue
        risky = bool(_RISKY_CMD.search(cmd))
        out.append(make("RG-PKG-001", f"npm yaşam döngüsü kancası: {hook}", S.HIGH if risky else S.LOW, "high" if risky else "medium",
                        "supply-chain", ctx.path, 0, f'"{hook}": "{cmd}"',
                        "Bu betik `npm install` sırasında kullanıcı onayı olmadan çalışır; tedarik zinciri saldırılarının ana yolu.",
                        "Çalıştırdığı komutu okuyun; `npm install --ignore-scripts` kullanın.", ("T1195.002", "T1059")))
    for sect in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = pkg.get(sect)
        if not isinstance(deps, dict):
            continue
        for dep, ver in deps.items():
            if isinstance(ver, str) and re.match(r"(git\+|git://|https?://|github:)", ver):   # file:/workspace:/link: yerel monorepo bağlarıdır
                out.append(make("RG-PKG-002", "npm bağımlılığı resmi kayıt defteri dışından", S.MEDIUM, "low", "supply-chain", ctx.path, 0,
                                f"{dep}: {ver}", "Sürüm sabit değil / içerik değişebilir.", "Sürüm veya commit sabitleyin.", ("T1195.001",)))
            t = _typosquat(dep, POPULAR_NPM)
            if t:
                out.append(make("RG-PKG-003", "Olası typosquatting (npm)", S.MEDIUM, "low", "supply-chain", ctx.path, 0, f"{dep} ~ {t}",
                                "Popüler paketin bir harf farklı kopyası olabilir.", "Paket adını doğrulayın.", ("T1195.001",)))
    return out


_DANGER_CALLS = {"system", "popen", "Popen", "call", "run", "check_output", "check_call", "exec", "eval", "urlopen", "urlretrieve", "get", "post", "b64decode", "compile"}


def _setup_py(ctx):
    out = []
    try:
        tree = ast.parse(ctx.text)       # yalnızca ayrıştırma; ÇALIŞTIRMA YOK
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return [make("RG-PKG-010", "setup.py ayrıştırılamadı", S.LOW, "low", "blind-spot", ctx.path, 0, "sözdizimi hatası",
                     "Bozuk veya kasıtlı gizlenmiş olabilir.", "Elle inceleyin.", ("T1027",))]
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    net = imports & {"urllib", "urllib2", "requests", "socket", "http", "ftplib", "httpx"}
    proc = imports & {"subprocess", "os", "pty", "ctypes"}
    cmdclass = any(isinstance(n, ast.keyword) and n.arg == "cmdclass" for n in ast.walk(tree))
    # Modül düzeyinde (fonksiyon/sınıf dışı) çağrılar kurulumda doğrudan çalışır.
    for node in tree.body:
        for sub in ast.walk(node) if not isinstance(node, (ast.FunctionDef, ast.ClassDef)) else []:
            if isinstance(sub, ast.Call):
                fn = sub.func
                nm = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
                if nm in _DANGER_CALLS and nm not in ("get", "run", "call", "compile") or (nm in ("get", "run", "call") and (net or proc) and isinstance(fn, ast.Attribute)):
                    out.append(make("RG-PKG-011", f"setup.py modül düzeyinde riskli çağrı: {nm}()", S.HIGH, "medium", "supply-chain",
                                    ctx.path, getattr(sub, "lineno", 0), (ctx.text.split("\n")[getattr(sub, "lineno", 1) - 1]).strip()[:150],
                                    "`pip install` sırasında bu satır doğrudan çalışır.", "Çağrının amacını doğrulayın.", ("T1195.002", "T1059.006")))
                    break
    if net and proc:
        out.append(make("RG-PKG-012", "setup.py hem ağ hem süreç/OS modülü içe aktarıyor", S.MEDIUM, "low", "supply-chain", ctx.path, 0,
                        f"ağ: {sorted(net)} süreç: {sorted(proc)}", "Kurulum betiği indir-çalıştır yapabilir.", "İçeriği okuyun.", ("T1195.002",)))
    if cmdclass:
        out.append(make("RG-PKG-013", "setup.py özel kurulum komutu (cmdclass)", S.LOW, "low", "supply-chain", ctx.path, 0, "cmdclass=...",
                        "Kurulum adımına özel kod bağlanıyor.", "Sınıfın içeriğini okuyun.", ("T1195.002",)))
    return out


def _requirements(ctx):
    out = []
    for n, line in enumerate(ctx.text.split("\n"), 1):
        s = line.split("#")[0].strip()
        if not s:
            continue
        if re.match(r"(-i|--index-url|--extra-index-url|--trusted-host)\b", s) or re.search(r"git\+|https?://", s):
            sev = S.MEDIUM if "extra-index-url" in s or "trusted-host" in s or s.startswith("http://") else S.LOW
            out.append(make("RG-PKG-004", "pip bağımlılığı/dizini resmi PyPI dışından", sev, "low", "supply-chain", ctx.path, n, s,
                            "Dependency-confusion veya içerik değişikliği riski.", "Sürüm/hash sabitleyin.", ("T1195.001",)))
            continue
        m = _REQ.match(s)
        if m:
            t = _typosquat(m.group(1), POPULAR_PYPI)
            if t:
                out.append(make("RG-PKG-005", "Olası typosquatting (PyPI)", S.MEDIUM, "low", "supply-chain", ctx.path, n, f"{m.group(1)} ~ {t}",
                                "Popüler paketin yakın yazımlı kopyası olabilir.", "Paket adını doğrulayın.", ("T1195.001",)))
    return out


def _pyproject(ctx):
    out = []
    m = re.search(r"build-backend\s*=\s*['\"]([^'\"]+)['\"]", ctx.text)
    if m and not re.match(r"(setuptools|flit_core|hatchling|poetry\.core|pdm\.backend|maturin|scikit_build_core|mesonpy|wheel)", m.group(1)):
        out.append(make("RG-PKG-006", "Alışılmadık build-backend", S.MEDIUM, "low", "supply-chain", ctx.path, 0, m.group(1),
                        "Derleme arka ucu kurulumda kod çalıştırır.", "Paketin meşruiyetini doğrulayın.", ("T1195.002",)))
    if re.search(r"backend-path\s*=", ctx.text):
        out.append(make("RG-PKG-007", "Depo içi build backend (backend-path)", S.LOW, "low", "supply-chain", ctx.path, 0, "backend-path=...",
                        "Depodaki yerel kod kurulumda çalışır.", "İçeriği okuyun.", ("T1195.002",)))
    return out
