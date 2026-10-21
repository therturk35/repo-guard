"""Geliştirici aracı ve yapay zekâ ajanı yapılandırmaları.

Depoyu bir IDE'de veya yapay zekâ kodlama ajanıyla AÇMAK bile kod çalıştırabilir:
  * .vscode/tasks.json  runOptions.runOn = folderOpen  -> klasör açılınca görev çalışır
  * .devcontainer/devcontainer.json  initializeCommand / postCreateCommand
  * .envrc (direnv) -> dizine girince kabuk betiği
  * .mcp.json / .claude/settings.json hooks / .cursor/mcp.json -> ajan başlarken komut çalıştıran MCP sunucuları ve kancalar
  * CLAUDE.md / AGENTS.md / .cursorrules -> ajana verilen talimatlar (prompt injection yeri)
Bunlar tek başına zararlı değildir; ama "depoyu açınca otomatik çalışan şey" olduğu için gösterilir.
"""
from __future__ import annotations

import re

from ..models import Severity as S
from .base import FileCtx, is_doc_path, make

_RISKY = re.compile(r"(curl|wget|bash\s+-c|sh\s+-c|powershell|nc\s|base64|eval|\|\s*(?:ba)?sh|http://|https://[^\s\"']*\.(?:sh|ps1)|npx\s+-y|uvx\s)", re.I)


def analyze(ctx: FileCtx):
    if not ctx.is_text:
        return []
    p = ctx.path.replace("\\", "/").lower()
    out = []
    if p.endswith(".vscode/tasks.json") and re.search(r"folderopen", ctx.text, re.I):
        out.append(make("RG-CFG-001", "VS Code: klasör açılınca otomatik çalışan görev", S.HIGH, "high", "auto-exec", ctx.path, 0, "runOn: folderOpen",
                        "Depoyu VS Code'da açmanız (güven verirseniz) komutu çalıştırır.", "Güvenmeden önce tasks.json'u okuyun.", ("T1204", "T1059")))
    if "devcontainer" in p and p.endswith(".json"):
        m = re.search(r'"(initializeCommand|onCreateCommand|postCreateCommand|postStartCommand|postAttachCommand)"\s*:\s*("[^"]*"|\[[^\]]*\]|\{[^}]*\})', ctx.text)
        if m:
            risky = bool(_RISKY.search(m.group(2)))
            sev = S.HIGH if (m.group(1) == "initializeCommand" or risky) else S.LOW
            out.append(make("RG-CFG-002", f"devcontainer: {m.group(1)}", sev, "medium", "auto-exec", ctx.path, 0, m.group(0)[:150],
                            "Geliştirme konteyneri açılırken komut çalışır (initializeCommand ana makinede çalışır).", "Komutu okuyun.", ("T1204",)))
    if p.endswith("/.envrc") or p == ".envrc":
        out.append(make("RG-CFG-003", ".envrc (direnv) dosyası", S.MEDIUM if _RISKY.search(ctx.text) else S.LOW, "medium", "auto-exec", ctx.path, 0, ctx.text[:100],
                        "direnv izin verildiğinde dizine girişte betiği çalıştırır.", "`direnv allow` öncesi okuyun.", ("T1204",)))
    if p.endswith((".mcp.json", "mcp.json", ".claude/settings.json", ".claude/settings.local.json", ".cursor/mcp.json", ".gemini/settings.json")):
        if re.search(r'"(command|hooks)"', ctx.text):
            risky = bool(_RISKY.search(ctx.text))
            out.append(make("RG-CFG-004", "Yapay zekâ ajanı: MCP sunucusu/kancası komut çalıştırıyor", S.HIGH if (risky and not is_doc_path(ctx.path, ctx.lang)) else S.MEDIUM, "medium", "ai-agent",
                            ctx.path, 0, re.sub(r"\s+", " ", ctx.text[:160]),
                            "Ajan bu depoda başlatıldığında tanımlı komutlar çalışabilir.", "Ajana güven vermeden önce okuyun.", ("T1204", "T1059")))
    if re.search(r"(?:^|/)(claude\.md|agents\.md|\.cursorrules|copilot-instructions\.md|gemini\.md)$", p):
        out.append(make("RG-CFG-005", "Ajan talimat dosyası mevcut", S.INFO, "low", "ai-agent", ctx.path, 0, ctx.path.split("/")[-1],
                        "Bu dosya yapay zekâ ajanını yönlendirir; kötü niyetli talimat içerebilir.", "İçeriği okuyun.", ("T1204",)))
    if p.endswith(("package.json",)) and re.search(r'"postinstall"\s*:\s*"[^"]*(?:claude|gemini|codex)[^"]*(?:--dangerously|--yolo|-p )', ctx.text, re.I):
        out.append(make("RG-CFG-006", "Kurulumda yapay zekâ CLI'sini izin atlayarak çağırma", S.HIGH, "medium", "ai-agent", ctx.path, 0, "postinstall + ajan CLI",
                        "Kurulum sırasında ajanın yerel gizli dosyaları okumasına yol açabilir.", "Betiği okuyun.", ("T1059",)))
    return out
