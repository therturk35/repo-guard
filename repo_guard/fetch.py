"""Güvenli klonlama yardımcısı: GitHub deposunu İNDİRİR ama hiçbir şeyi ÇALIŞTIRMAZ.

Git klonlama bile saldırı yüzeyidir (hook, filter, ext:: taşıyıcı, alt modül).
Önlemler: hook'lar kapalı, ext taşıyıcı kapalı, alt modüller çekilmez, LFS
smudge kapalı, etkileşimli parola istemi kapalı, sığ klon (depth 1).
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile

_SLUG = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")


def safe_clone(slug: str, dest_parent: str | None = None, timeout: int = 180) -> tuple[str, str]:
    """owner/repo -> (klasör, commit_sha). Hata olursa RuntimeError."""
    if not _SLUG.match(slug) or slug.startswith("-"):
        raise RuntimeError(f"geçersiz depo adı: {slug!r} (beklenen: sahip/depo)")
    parent = dest_parent or tempfile.mkdtemp(prefix="repo-guard-")
    dest = os.path.join(parent, slug.replace("/", "__"))
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1", GIT_CONFIG_NOSYSTEM="1")
    cmd = ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.ext.allow=never", "-c", "protocol.file.allow=never",
           "-c", "core.fsmonitor=false", "-c", "filter.lfs.smudge=", "-c", "filter.lfs.process=", "-c", "filter.lfs.required=false",
           "clone", "--depth", "1", "--no-recurse-submodules", "--single-branch", "--", f"https://github.com/{slug}.git", dest]
    try:
        subprocess.run(cmd, env=env, check=True, capture_output=True, timeout=timeout, text=True)
        sha = subprocess.run(["git", "-C", dest, "rev-parse", "HEAD"], env=env, check=True, capture_output=True, text=True, timeout=30).stdout.strip()
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"klonlama başarısız: {(e.stderr or '').strip()[:200]}") from None
    except subprocess.TimeoutExpired:
        raise RuntimeError("klonlama zaman aşımı") from None
    return dest, sha
