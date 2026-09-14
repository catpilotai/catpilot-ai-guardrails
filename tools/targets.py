"""Per-host artifacts for a bundle, rendered deterministically from the same sources.

Every artifact is a template around the bundle's rendered component bodies:
a Claude.ai upload zip, paste-ready instruction blocks for hosts with an
instruction field, blocks for repository-based agents, and the standalone
web page that is the source for catpilot.ai/safe-ai-building. No third-party
templating dependency; plain Python strings.

Determinism: fixed zip timestamps derived from the release CalVer, no
wall-clock values anywhere, sorted output.
"""

from __future__ import annotations

import html
import io
import json
import re
import zipfile
from pathlib import Path

TARGET_NAMES = (
    "claude-zip",
    "chatgpt",
    "copilot",
    "agents-md",
    "copilot-instructions",
    "lovable",
    "bolt",
    "replit",
    "v0",
    "web",
)
PASTE_LIMIT = 8000  # ChatGPT project/GPT instructions and Copilot Studio instructions
PASTE_HEADROOM = 300  # room for the per-file header line so the whole pasted file fits
REPO_URL = "https://github.com/catpilotai/catpilot-ai-guardrails"
SITE_URL = "https://www.catpilot.ai/"
HEADING_RE = re.compile(r"^## (.+?)\s*$")


# --------------------------------------------------------------------------
# Parsing rendered component bodies


def parse_sections(body: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in body.split("\n"):
        m = HEADING_RE.match(line)
        if m:
            current = m.group(1).strip().lower()
            sections[current] = []
            continue
        if current is not None:
            sections[current].append(line)
    return sections


def bullet_items(lines: list[str]) -> list[str]:
    items: list[str] = []
    for line in lines:
        if line.startswith("- "):
            items.append(line[2:].strip())
        elif line.startswith("  ") and items and line.strip():
            items[-1] += " " + line.strip()
    return items


def first_sentence(text: str) -> str:
    text = " ".join(text.split())
    m = re.match(r"(.+?[.!?])(?:\s|$)", text)
    return m.group(1) if m else text


def strip_quotes(text: str) -> str:
    text = text.strip()
    m = re.match(r'^"([^"]+)"', text)
    return m.group(1) if m else text


def digest(skill, rendered_body: str) -> dict:
    sections = parse_sections(rendered_body)
    ask = bullet_items(sections.get("what to ask", []))
    do = bullet_items(sections.get("safe alternative", []))
    stop = bullet_items(sections.get("stop and ask a human if", []))
    if not ask or not do or not stop:
        raise ValueError(
            f"{skill.id}: a safe-building component needs 'What to ask', 'Safe alternative', and "
            "'Stop and ask a human if' sections with bullets"
        )
    return {
        "id": skill.id,
        "title": skill.title or skill.id,
        "summary": first_sentence(skill.frontmatter["description"]),
        "ask": strip_quotes(ask[0]),
        "do": do,
        "stop": stop,
        "checkpoints": skill.training_checkpoints,
    }


def preamble_digest(preamble: str) -> tuple[str, list[str], str]:
    """Return (lede paragraph, coaching bullets, trailing notice paragraph)."""
    lines = [l for l in preamble.strip().split("\n") if not l.startswith("# ")]
    paragraphs: list[list[str]] = [[]]
    for line in lines:
        if not line.strip():
            if paragraphs[-1]:
                paragraphs.append([])
            continue
        paragraphs[-1].append(line)
    paragraphs = [p for p in paragraphs if p]
    lede = " ".join(" ".join(l.strip() for l in p) for p in paragraphs[:1])
    bullets: list[str] = []
    notice = ""
    for p in paragraphs[1:]:
        if p[0].startswith("- "):
            bullets.extend(bullet_items(p))
        elif p[0].startswith("This copy") or p[0].startswith("Company-specific values"):
            notice = " ".join(l.strip() for l in p)
    return lede, bullets, notice


# --------------------------------------------------------------------------
# Condensed text (paste targets)


def condensed(cfg: dict, digests: list[dict], preamble_rendered: str, release: str, *, max_do: int = 3, max_stop: int = 3) -> str:
    """The paste-size rendering: coaching preamble, then per component the first
    question, up to max_do safe alternatives, and up to max_stop stop triggers."""
    lede, bullets, notice = preamble_digest(preamble_rendered)
    out = [
        f"Catpilot safe building guidance for an AI assistant ({cfg['name']} {release}, {REPO_URL}). "
        "Advisory: it shapes what the assistant says. It does not monitor, block, review, or approve anything.",
        "",
        lede,
        "",
        "How to coach: " + " ".join(b.rstrip(".") + "." for b in bullets),
        "",
    ]
    for n, d in enumerate(digests, 1):
        out.append(f"{n}. {d['title']}")
        out.append(f"Ask: {d['ask']}")
        out.append("Do: " + " ".join(item.rstrip(".") + "." for item in d["do"][:max_do]))
        out.append("Stop and ask a human if: " + "; ".join(item.rstrip(".") for item in d["stop"][:max_stop]) + ".")
        out.append("")
    if notice:
        out.append(notice)
    text = "\n".join(out).rstrip() + "\n"
    if len(text) > PASTE_LIMIT - PASTE_HEADROOM:
        raise ValueError(f"condensed guidance is {len(text)} characters; the paste limit is {PASTE_LIMIT} minus {PASTE_HEADROOM} of header room. Tighten the component bullets.")
    return text


def _md_header(cfg: dict, release: str, where: str) -> str:
    return f"<!-- Catpilot safe building · {cfg['name']} {release} · {where} · {REPO_URL} -->\n\n"


def _block(cfg: dict, release: str, body: str) -> str:
    return f"## Safe building with AI (Catpilot {cfg['name']} {release})\n\n" + body


# --------------------------------------------------------------------------
# Zip


def calver_tuple(release: str) -> tuple[int, int, int]:
    core = re.split(r"[-+]", release)[0].split(".")
    return int(core[0]), int(core[1]), int(core[2]) if len(core) > 2 else 1


def claude_zip(cfg: dict, release: str, bundle_skill_md: str) -> bytes:
    y, m, d = calver_tuple(release)
    stamp = (y, m, d, 0, 0, 0)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        folder = zipfile.ZipInfo(f"{cfg['name']}/", date_time=stamp)
        folder.external_attr = (0o755 << 16) | 0x10
        zf.writestr(folder, b"")
        info = zipfile.ZipInfo(f"{cfg['name']}/SKILL.md", date_time=stamp)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        zf.writestr(info, bundle_skill_md.encode("utf-8"))
    return buffer.getvalue()


# --------------------------------------------------------------------------
# Web page


CSS = """
:root{--cream:#FBF8F1;--paper:#FFFFFF;--ink:#1B1F1D;--muted:#5B615E;--faint:#8C918E;--line:#E3DFD3;--line-strong:#C9C3B4;--accent:#0F6E56;--accent-tint:#E1F5EE;--accent-deep:#085041;--serif:"Charter","Bitstream Charter","Georgia",serif;--sans:"Segoe UI","Helvetica Neue",Arial,sans-serif;--mono:"SFMono-Regular",Menlo,Consolas,monospace;--w:1120px}
*{box-sizing:border-box}html{background:var(--cream)}
body{margin:0;font-family:var(--sans);color:var(--ink);font-size:17px;line-height:1.55;background:var(--cream)}
a{color:inherit;text-decoration:underline;text-decoration-color:var(--line-strong);text-underline-offset:3px}
h1,h2,h3{font-family:var(--serif);font-weight:400;margin:0;letter-spacing:-0.01em}
h1{font-size:52px;line-height:1.05}h2{font-size:32px;line-height:1.15}h3{font-size:20px;line-height:1.25}
p{margin:0}.wrap{max-width:var(--w);margin:0 auto;padding:0 32px}
.kicker{font-size:14px;color:var(--accent);margin-bottom:12px}.lede{color:var(--muted);max-width:56ch}
.rule{border:0;border-top:1px solid var(--line);margin:0}section{padding:72px 0}
header.nav{padding:20px 0}header.nav .wrap{display:flex;align-items:center;justify-content:space-between;gap:24px}
.brand{font-size:20px;text-decoration:none}nav ul{list-style:none;display:flex;gap:28px;margin:0;padding:0;font-size:16px;color:var(--muted)}nav a{text-decoration:none}
.hero{padding:56px 0 64px}.hero h1{margin:0 0 18px;max-width:22ch}.delivery{font-size:14px;color:var(--faint);margin-top:20px}
ol.checks{list-style:none;padding:0;margin:32px 0 0;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px;counter-reset:c}
ol.checks li{background:var(--paper);border:1px solid var(--line);border-radius:12px;padding:24px;counter-increment:c}
ol.checks h3::before{content:counter(c) ". ";color:var(--accent)}ol.checks p{color:var(--muted);font-size:16px;margin:8px 0 12px}
dl{margin:0;font-size:15px}dt{color:var(--accent);font-size:13px;margin-top:10px}dd{margin:2px 0 0}
.tabs{display:flex;flex-wrap:wrap;gap:8px;margin:28px 0 0}
.tabs button{font:inherit;font-size:15px;padding:8px 14px;border:1px solid var(--line-strong);border-radius:999px;background:var(--paper);color:var(--ink);cursor:pointer}
.tabs button[aria-selected="true"]{background:var(--accent-tint);border-color:var(--accent);color:var(--accent-deep)}
.tabs button:focus-visible,.copy:focus-visible,a:focus-visible{outline:3px solid var(--accent-tint);outline-offset:2px}
.panel{background:var(--paper);border:1px solid var(--line);border-radius:12px;padding:20px 24px;margin-top:16px}
.panel .where{color:var(--muted);font-size:16px;margin-bottom:12px}
.panel pre{font-family:var(--mono);font-size:13px;line-height:1.5;background:var(--cream);border:1px solid var(--line);border-radius:8px;padding:14px;margin:0;white-space:pre-wrap;word-break:break-word;max-height:360px;overflow:auto}
.copy{font:inherit;font-size:15px;margin-top:12px;padding:8px 16px;border:1px solid var(--line-strong);border-radius:8px;background:var(--paper);color:var(--ink);cursor:pointer}
.note{margin-top:28px;color:var(--muted);max-width:70ch}
ul.links{list-style:none;padding:0;margin:20px 0 0;display:grid;gap:8px}
footer{padding:28px 0 40px;font-size:14px;color:var(--faint)}footer .wrap{display:flex;justify-content:space-between;gap:24px;flex-wrap:wrap}
@media (max-width:820px){h1{font-size:38px}h2{font-size:26px}.wrap{padding:0 20px}section{padding:48px 0}nav ul li:not(:last-child){display:none}ol.checks{grid-template-columns:1fr}.hero{padding:24px 0 40px}}
@media (prefers-reduced-motion:no-preference){.tabs button,.copy{transition:background-color .15s ease}}
""".strip()

JS = """
(function(){
  var tabs=document.querySelectorAll('.tabs [role=tab]');var panels=document.querySelectorAll('[role=tabpanel]');
  function show(id){tabs.forEach(function(t){t.setAttribute('aria-selected',String(t.getAttribute('aria-controls')===id));});panels.forEach(function(p){p.hidden=p.id!==id;});}
  tabs.forEach(function(t){t.addEventListener('click',function(){show(t.getAttribute('aria-controls'));});});
  if(tabs.length){show(tabs[0].getAttribute('aria-controls'));}
  document.querySelectorAll('.copy').forEach(function(b){b.addEventListener('click',function(){var el=document.getElementById(b.getAttribute('data-copy'));var text=el?el.textContent:'';
    if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(text).then(function(){b.textContent='Copied';setTimeout(function(){b.textContent='Copy';},1500);},function(){b.textContent='Select the text and copy it';});}
    else{b.textContent='Select the text and copy it';}});});
})();
""".strip()


def web_page(cfg: dict, digests: list[dict], paste: str, release: str, npx_command: str) -> str:
    esc = html.escape
    release_url = f"{REPO_URL}/releases/tag/{release}"
    tabs = [
        ("claude", "Claude", "Claude.ai: download the skill zip from the release and upload it under Customize → Skills. Organization owners upload it once under Organization settings → Skills and it reaches every member. In a Claude Project, paste the block below into the project instructions instead.", paste, f'<p class="where"><a href="{esc(release_url)}">Download catpilot-safe-building.zip from the {esc(release)} release</a>.</p>'),
        ("chatgpt", "ChatGPT", "Paste into a Project's Instructions, or into a Custom GPT's Instructions (limit 8,000 characters). Workspace-wide distribution needs an admin-published app; this repository does not ship one yet.", paste, ""),
        ("copilot", "Microsoft Copilot", "Copilot Studio: paste into the agent's Instructions. Microsoft 365 declarative agents: the release includes a manifest stub with the same text; publish it through your tenant's agent catalog.", paste, ""),
        ("lovable", "Lovable", "Project → Settings → Knowledge. Paste the block.", paste, ""),
        ("bolt", "Bolt", "Save the block as .bolt/prompt in the project.", paste, ""),
        ("replit", "Replit", "Paste into the Agent's instructions or into replit.md in the project.", paste, ""),
        ("v0", "v0", "Project settings → Instructions. Paste the block.", paste, ""),
        ("agents", "Coding agents", "Claude Code, Cursor, Codex, Copilot, Cline, Aider, and other agents that read Agent Skills: install with the command below, or append the block to the project's AGENTS.md.", npx_command, ""),
    ]
    checks_html = []
    for d in digests:
        checks_html.append(
            "<li>"
            f"<h3>{esc(d['title'])}</h3>"
            f"<p>{esc(d['summary'])}</p>"
            "<dl>"
            f"<dt>Ask</dt><dd>{esc(d['ask'])}</dd>"
            f"<dt>Do</dt><dd>{esc(' '.join(item.rstrip('.') + '.' for item in d['do'][:2]))}</dd>"
            f"<dt>Stop and ask a human if</dt><dd>{esc('; '.join(item.rstrip('.') for item in d['stop'][:3]))}.</dd>"
            "</dl></li>"
        )
    tab_buttons = "".join(
        f'<button role="tab" id="tab-{tid}" aria-controls="panel-{tid}" aria-selected="false">{esc(label)}</button>'
        for tid, label, _, _, _ in tabs
    )
    panels = []
    for tid, label, where, text, extra in tabs:
        panels.append(
            f'<div class="panel" role="tabpanel" id="panel-{tid}" aria-labelledby="tab-{tid}" hidden>'
            f'<p class="where">{esc(where)}</p>{extra}'
            f'<pre id="text-{tid}" aria-label="Text to give to {esc(label)}">{esc(text)}</pre>'
            f'<button class="copy" data-copy="text-{tid}">Copy</button></div>'
        )
    return (
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        f"<title>Safe AI building — Catpilot</title>\n"
        "<meta name=\"description\" content=\"Eight plain-language security checkpoints for anyone building an app, automation, dashboard, or data tool with an AI assistant, and the same guidance ready to give to the tool.\">\n"
        f"<!-- Generated by tools/bundle.py --target web from {esc(cfg['name'])} {esc(release)}. Source for catpilot.ai/safe-ai-building; port into the site's framework rather than serving this file. -->\n"
        f"<style>\n{CSS}\n</style>\n</head>\n<body>\n"
        "<header class=\"nav\"><div class=\"wrap\">"
        f"<a class=\"brand\" href=\"{esc(SITE_URL)}\">Catpilot</a>"
        "<nav aria-label=\"Primary\"><ul>"
        f"<li><a href=\"{esc(SITE_URL)}\">Home</a></li>"
        f"<li><a href=\"{esc(REPO_URL)}\">GitHub</a></li>"
        "</ul></nav></div></header>\n"
        "<section class=\"hero\"><div class=\"wrap\">"
        "<p class=\"kicker\">Safe AI building</p>"
        "<h1>Build with AI safely.</h1>"
        "<p class=\"lede\">Eight checkpoints for anyone building an app, automation, dashboard, or data tool with an AI assistant. Read them in five minutes, then give the same guidance to your AI tool.</p>"
        f"<p class=\"delivery\">Release {esc(release)} · Guidance, not monitoring or enforcement · No sign-up</p>"
        "</div></section>\n<hr class=\"rule\">\n"
        "<section id=\"checkpoints\"><div class=\"wrap\">"
        "<p class=\"kicker\">Checkpoints</p>"
        "<h2>What to check before you build, connect, or share.</h2>"
        "<p class=\"lede\">Each checkpoint matches a lesson in Catpilot's Safe AI-assisted building course, so the person and the tool get the same guidance.</p>"
        f"<ol class=\"checks\">{''.join(checks_html)}</ol>"
        "</div></section>\n<hr class=\"rule\">\n"
        "<section id=\"give\"><div class=\"wrap\">"
        "<p class=\"kicker\">Give this to your AI tool</p>"
        "<h2>Same guidance for the person and the tool.</h2>"
        "<p class=\"lede\">Pick your tool. Copy the block. Paste it where the tab says. Nothing to install, nothing to sign up for.</p>"
        f"<div class=\"tabs\" role=\"tablist\" aria-label=\"AI tools\">{tab_buttons}</div>"
        f"{''.join(panels)}"
        "<p class=\"note\">What it does and does not do: guidance the tool can reference while you build. It is not monitoring, not enforcement, and not a substitute for your company's own controls.</p>"
        "</div></section>\n<hr class=\"rule\">\n"
        "<section id=\"more\"><div class=\"wrap\">"
        "<p class=\"kicker\">More</p>"
        "<h2>Where this comes from.</h2>"
        "<ul class=\"links\">"
        f"<li><a href=\"{esc(REPO_URL)}\">The open-source repository</a>, MIT licensed, no telemetry.</li>"
        f"<li><a href=\"{esc(release_url)}\">Release {esc(release)}</a>, with the zip, the paste blocks, and this page.</li>"
        f"<li><a href=\"{esc(SITE_URL)}\">The Safe AI-assisted building course</a> for people, in Slack and Microsoft Teams.</li>"
        "</ul></div></section>\n"
        "<footer><div class=\"wrap\"><span>Catpilot · Security companion</span>"
        f"<span><a href=\"{esc(REPO_URL)}\">GitHub</a></span></div></footer>\n"
        f"<script>\n{JS}\n</script>\n</body>\n</html>\n"
    )


# --------------------------------------------------------------------------
# Rendering


def render_all(cfg: dict, skills, rendered_bodies: dict[str, str], bundle_skill_md: str, out_dir: Path, enabled: list[str]) -> list[Path]:
    release = cfg["version"]
    ordered = sorted(skills, key=lambda s: s.id)
    digests = [digest(s, rendered_bodies[s.id]) for s in ordered]
    # The preamble as rendered inside the bundle body (slots resolved).
    body_start = bundle_skill_md.split("\n---\n\n", 1)[1] if "\n---\n\n" in bundle_skill_md else bundle_skill_md
    preamble_rendered = body_start.split("\n---\n", 1)[0]
    paste = condensed(cfg, digests, preamble_rendered, release)
    npx_command = f"npx skills add catpilotai/catpilot-ai-guardrails --skill {cfg['name']}"

    files: dict[str, bytes] = {}
    if "claude-zip" in enabled:
        files[f"{cfg['name']}.zip"] = claude_zip(cfg, release, bundle_skill_md)
    if "chatgpt" in enabled:
        files["chatgpt-project-instructions.md"] = (_md_header(cfg, release, "Paste into a ChatGPT Project's Instructions or a Custom GPT's Instructions") + paste).encode("utf-8")
    if "copilot" in enabled:
        files["copilot-agent-instructions.md"] = (_md_header(cfg, release, "Paste into a Copilot Studio agent's Instructions") + paste).encode("utf-8")
        stub = {
            "$schema": "https://developer.microsoft.com/json-schemas/copilot/declarative-agent/v1.5/schema.json",
            "version": "v1.5",
            "name": "Safe building coach",
            "description": f"Plain-language security guidance for people building apps, automations, dashboards, and data tools with AI. Advisory only. Catpilot {cfg['name']} {release}.",
            "instructions": paste,
        }
        files["copilot-declarative-agent.stub.json"] = (json.dumps(stub, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    if "agents-md" in enabled:
        files["AGENTS.md"] = (_md_header(cfg, release, "Append to the project's AGENTS.md") + _block(cfg, release, paste)).encode("utf-8")
    if "copilot-instructions" in enabled:
        files["copilot-instructions.md"] = (_md_header(cfg, release, "Append to .github/copilot-instructions.md") + _block(cfg, release, paste)).encode("utf-8")
    if "lovable" in enabled:
        files["lovable-knowledge.md"] = (_md_header(cfg, release, "Paste into Lovable: Project → Settings → Knowledge") + paste).encode("utf-8")
    if "bolt" in enabled:
        files["bolt-prompt.txt"] = (f"Catpilot safe building · {cfg['name']} {release} · save as .bolt/prompt · {REPO_URL}\n\n" + paste).encode("utf-8")
    if "replit" in enabled:
        files["replit-instructions.md"] = (_md_header(cfg, release, "Paste into the Replit Agent's instructions or replit.md") + paste).encode("utf-8")
    if "v0" in enabled:
        files["v0-instructions.md"] = (_md_header(cfg, release, "Paste into v0: Project settings → Instructions") + paste).encode("utf-8")
    if "web" in enabled:
        files["web/safe-ai-building.html"] = web_page(cfg, digests, paste, release, npx_command).encode("utf-8")
    files["README.md"] = dist_readme(cfg, release, sorted(files)).encode("utf-8")

    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for rel in sorted(files):
        path = out_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(files[rel])
        written.append(path)
    return written


def dist_readme(cfg: dict, release: str, names: list[str]) -> str:
    rows = {
        f"{cfg['name']}.zip": ("Claude.ai (individual or organization)", "Customize → Skills, or Organization settings → Skills. The zip holds one folder with SKILL.md inside."),
        "chatgpt-project-instructions.md": ("ChatGPT", "Project → Instructions, or a Custom GPT's Instructions. Under 8,000 characters."),
        "copilot-agent-instructions.md": ("Microsoft Copilot Studio", "Agent → Instructions. Under 8,000 characters."),
        "copilot-declarative-agent.stub.json": ("Microsoft 365 declarative agent", "Manifest stub with the same instructions. Validate against Microsoft's current schema, then publish through the tenant's agent catalog."),
        "AGENTS.md": ("Repository-based agents", "Append the block to the project's AGENTS.md."),
        "copilot-instructions.md": ("GitHub Copilot in a repository", "Append the block to .github/copilot-instructions.md."),
        "lovable-knowledge.md": ("Lovable", "Project → Settings → Knowledge."),
        "bolt-prompt.txt": ("Bolt", "Save as .bolt/prompt in the project."),
        "replit-instructions.md": ("Replit", "Agent instructions or replit.md."),
        "v0-instructions.md": ("v0", "Project settings → Instructions."),
        "web/safe-ai-building.html": ("catpilot.ai/safe-ai-building", "Standalone source page. Port into the site's framework; do not serve this file as the site."),
    }
    lines = [
        f"# {cfg['name']} {release}: per-host artifacts",
        "",
        "Generated by `python tools/bundle.py --target all` from `src/skills/` in",
        f"{REPO_URL}. Every file carries this release in its header. Do not edit these;",
        "edit the source components and rebuild.",
        "",
        "These are guidance the tool reads. They do not monitor, block, or review",
        "anything, and pasting them is not evidence that a host loaded them.",
        "",
        "| File | Host | Where it goes |",
        "| --- | --- | --- |",
    ]
    for name in names:
        host, where = rows.get(name, ("", ""))
        lines.append(f"| `{name}` | {host} | {where} |")
    lines += [
        "",
        f"Coding agents that read Agent Skills install the same content with `npx skills add catpilotai/catpilot-ai-guardrails --skill {cfg['name']}`.",
        "",
    ]
    return "\n".join(lines)
