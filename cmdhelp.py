#!/usr/bin/env python3
"""cmd-help: an offline, no-API-key helper that turns plain English into shell commands."""

import contextlib
import difflib
import json
import os
import re
import select
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

# Sentinel returned by ask() when the user wants to quit from any prompt.
QUIT = object()

# When launched by the shell wrapper, the chosen command is printed to stdout so
# the wrapper can run it in the real shell (so cd etc. affect your terminal).
EMIT = bool(os.environ.get("CMDHELP_EMIT"))

CONFIG_FILE = os.path.expanduser("~/.cmdhelp_config.json")

# Color themes for the box. Each has a border color, a selected-row style, and reset.
THEMES = {
    "minimal": {"border": "", "sel": "\x1b[7m", "dim": "", "reset": "\x1b[0m"},
    "cyan": {"border": "\x1b[36m", "sel": "\x1b[30;46m", "dim": "\x1b[2m", "reset": "\x1b[0m"},
    "green": {"border": "\x1b[32m", "sel": "\x1b[30;42m", "dim": "\x1b[2m", "reset": "\x1b[0m"},
    "magenta": {"border": "\x1b[35m", "sel": "\x1b[30;45m", "dim": "\x1b[2m", "reset": "\x1b[0m"},
    "amber": {"border": "\x1b[33m", "sel": "\x1b[30;43m", "dim": "\x1b[2m", "reset": "\x1b[0m"},
}

CONFIG = {"theme": "minimal", "use_llm": True, "model": "llama3.2:3b"}

# Local Ollama endpoint + model. Override via env for quick experiments.
OLLAMA_URL = os.environ.get("CMDHELP_OLLAMA", "http://localhost:11434")


def load_config():
    try:
        with open(CONFIG_FILE) as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            if data.get("theme") in THEMES:
                CONFIG["theme"] = data["theme"]
            if isinstance(data.get("use_llm"), bool):
                CONFIG["use_llm"] = data["use_llm"]
            if isinstance(data.get("model"), str) and data["model"]:
                CONFIG["model"] = data["model"]
    except (OSError, ValueError):
        pass
    if os.environ.get("CMDHELP_MODEL"):
        CONFIG["model"] = os.environ["CMDHELP_MODEL"]
    if os.environ.get("CMDHELP_NO_LLM"):
        CONFIG["use_llm"] = False


def save_config():
    try:
        with open(CONFIG_FILE, "w") as fh:
            json.dump(CONFIG, fh, indent=2)
    except OSError:
        pass


def theme():
    return THEMES.get(CONFIG["theme"], THEMES["minimal"])


def ui(msg=""):
    """All interactive text goes to stderr so stdout stays clean for EMIT."""
    print(msg, file=sys.stderr)


def ask(prompt):
    """Prompt on stderr, read a line. Returns QUIT on exit words, EOF, or Ctrl+C."""
    try:
        print(prompt, end="", file=sys.stderr, flush=True)
        line = sys.stdin.readline()
    except (EOFError, KeyboardInterrupt):
        return QUIT
    if line == "":  # EOF
        return QUIT
    line = line.strip()
    if line.lower() in ("quit", "exit", "q", "/exit", "/quit"):
        return QUIT
    return line

# Patterns used to classify how risky a command is.
DANGEROUS_PATTERNS = [
    r"\brm\b", r"\brmdir\b", r"\bkill\b", r"\bpkill\b",
    r"\bchmod\b", r"\bchown\b", r"\bdd\b", r"\bmkfs\b",
    r"\bshutdown\b", r"\breboot\b", r">\s", r"\bsudo\b",
]
CAUTION_PATTERNS = [
    r"\bmv\b", r"\bcp\b", r"\btouch\b", r"\bmkdir\b",
    r"git\s+push", r"git\s+commit", r"git\s+add",
    r"\bcurl\b", r"\bwget\b", r"\bpull\b",
]

RISK_LABELS = {
    "dangerous": "!! DANGEROUS",
    "caution": "!  caution",
    "safe": "ok safe",
}


def classify_risk(cmd):
    cmd = re.sub(r"<[^>]+>", "", cmd)
    for pat in DANGEROUS_PATTERNS:
        if re.search(pat, cmd):
            return "dangerous"
    for pat in CAUTION_PATTERNS:
        if re.search(pat, cmd):
            return "caution"
    return "safe"

# Each entry: description shown to the user, the command template, and search keywords.
KNOWLEDGE_BASE = [
    {
        "desc": "List files in the current directory (detailed, including hidden)",
        "cmd": "ls -la",
        "keywords": ["list", "files", "directory", "folder", "show", "contents", "hidden", "detailed"],
    },
    {
        "desc": "Change to another directory",
        "cmd": "cd <path>",
        "keywords": ["change", "directory", "go", "into", "folder", "navigate", "move"],
    },
    {
        "desc": "Show the current working directory path",
        "cmd": "pwd",
        "keywords": ["current", "working", "directory", "where", "path", "am", "location"],
    },
    {
        "desc": "Create a new empty file",
        "cmd": "touch <filename>",
        "keywords": ["create", "make", "new", "empty", "file", "touch"],
    },
    {
        "desc": "Create a new directory (with parents if needed)",
        "cmd": "mkdir -p <dirname>",
        "keywords": ["create", "make", "new", "directory", "folder", "mkdir"],
    },
    {
        "desc": "Copy a file",
        "cmd": "cp <source> <destination>",
        "keywords": ["copy", "duplicate", "file", "cp"],
    },
    {
        "desc": "Copy a directory recursively",
        "cmd": "cp -r <source_dir> <destination_dir>",
        "keywords": ["copy", "directory", "folder", "recursive", "cp"],
    },
    {
        "desc": "Move or rename a file/directory",
        "cmd": "mv <source> <destination>",
        "keywords": ["move", "rename", "file", "directory", "folder", "mv"],
    },
    {
        "desc": "Delete a file",
        "cmd": "rm <filename>",
        "keywords": ["delete", "remove", "file", "rm", "erase"],
    },
    {
        "desc": "Delete a directory and everything in it",
        "cmd": "rm -rf <dirname>",
        "keywords": ["delete", "remove", "directory", "folder", "recursive", "rm", "erase"],
    },
    {
        "desc": "Show the contents of a file",
        "cmd": "cat <filename>",
        "keywords": ["show", "display", "read", "view", "contents", "file", "print", "cat"],
    },
    {
        "desc": "View a file one page at a time",
        "cmd": "less <filename>",
        "keywords": ["view", "read", "file", "page", "scroll", "less", "pager"],
    },
    {
        "desc": "Show the first lines of a file",
        "cmd": "head -n 20 <filename>",
        "keywords": ["first", "top", "lines", "file", "head", "beginning"],
    },
    {
        "desc": "Show the last lines of a file",
        "cmd": "tail -n 20 <filename>",
        "keywords": ["last", "end", "lines", "file", "tail", "bottom"],
    },
    {
        "desc": "Follow a log file as it grows",
        "cmd": "tail -f <logfile>",
        "keywords": ["follow", "watch", "log", "file", "live", "tail", "stream"],
    },
    {
        "desc": "Search for text inside files recursively",
        "cmd": "grep -r <pattern> <path>",
        "keywords": ["search", "find", "text", "pattern", "inside", "files", "grep", "look"],
    },
    {
        "desc": "Find files by name",
        "cmd": "find <path> -name '<pattern>'",
        "keywords": ["find", "search", "files", "name", "locate"],
    },
    {
        "desc": "Show disk usage of the current directory",
        "cmd": "du -sh *",
        "keywords": ["disk", "usage", "size", "space", "directory", "du", "how", "big"],
    },
    {
        "desc": "Show free disk space",
        "cmd": "df -h",
        "keywords": ["free", "disk", "space", "storage", "df", "available"],
    },
    {
        "desc": "Show running processes",
        "cmd": "ps aux",
        "keywords": ["running", "processes", "tasks", "ps", "show", "programs"],
    },
    {
        "desc": "Interactively monitor processes and CPU/memory",
        "cmd": "top",
        "keywords": ["monitor", "processes", "cpu", "memory", "usage", "top", "performance"],
    },
    {
        "desc": "Kill a process by its ID",
        "cmd": "kill <pid>",
        "keywords": ["kill", "stop", "terminate", "process", "end", "pid"],
    },
    {
        "desc": "Kill a process by name",
        "cmd": "pkill <name>",
        "keywords": ["kill", "stop", "terminate", "process", "name", "pkill"],
    },
    {
        "desc": "Make a file executable",
        "cmd": "chmod +x <filename>",
        "keywords": ["make", "executable", "permission", "chmod", "run", "script"],
    },
    {
        "desc": "Change file ownership",
        "cmd": "chown <user>:<group> <filename>",
        "keywords": ["change", "owner", "ownership", "permission", "chown", "user"],
    },
    {
        "desc": "Show command history",
        "cmd": "history",
        "keywords": ["history", "previous", "commands", "past", "recent"],
    },
    {
        "desc": "Download a file from a URL",
        "cmd": "curl -O <url>",
        "keywords": ["download", "fetch", "url", "file", "internet", "curl", "web", "get"],
    },
    {
        "desc": "Check network connectivity to a host",
        "cmd": "ping <host>",
        "keywords": ["ping", "network", "connectivity", "reach", "host", "internet", "test"],
    },
    {
        "desc": "Show which program a command points to",
        "cmd": "which <command>",
        "keywords": ["which", "where", "command", "program", "path", "located"],
    },
    {
        "desc": "Compress files into a tar.gz archive",
        "cmd": "tar -czvf <archive.tar.gz> <files>",
        "keywords": ["compress", "archive", "tar", "zip", "package", "gzip", "bundle"],
    },
    {
        "desc": "Extract a tar.gz archive",
        "cmd": "tar -xzvf <archive.tar.gz>",
        "keywords": ["extract", "unpack", "decompress", "tar", "unzip", "open", "archive"],
    },
    {
        "desc": "Unzip a .zip archive",
        "cmd": "unzip <archive.zip>",
        "keywords": ["unzip", "extract", "zip", "archive", "unpack", "open"],
    },
    {
        "desc": "Initialize a new git repository",
        "cmd": "git init",
        "keywords": ["git", "init", "initialize", "repository", "repo", "start", "new"],
    },
    {
        "desc": "Check git repository status",
        "cmd": "git status",
        "keywords": ["git", "status", "changes", "repository", "repo", "state"],
    },
    {
        "desc": "Stage all changes for commit",
        "cmd": "git add .",
        "keywords": ["git", "add", "stage", "changes", "commit"],
    },
    {
        "desc": "Commit staged changes with a message",
        "cmd": "git commit -m '<message>'",
        "keywords": ["git", "commit", "save", "changes", "message"],
    },
    {
        "desc": "Push commits to the remote repository",
        "cmd": "git push",
        "keywords": ["git", "push", "upload", "remote", "send", "commits"],
    },
    {
        "desc": "Pull the latest changes from remote",
        "cmd": "git pull",
        "keywords": ["git", "pull", "update", "fetch", "remote", "download", "latest"],
    },
    {
        "desc": "Clone a git repository",
        "cmd": "git clone <url>",
        "keywords": ["git", "clone", "copy", "download", "repository", "repo"],
    },
    {
        "desc": "Show clear the terminal screen",
        "cmd": "clear",
        "keywords": ["clear", "clean", "terminal", "screen", "empty"],
    },
]

STOPWORDS = {
    "a", "an", "the", "to", "of", "in", "on", "for", "how", "do", "i",
    "my", "me", "can", "with", "and", "is", "it", "this", "that", "want",
    "please", "would", "like", "some",
}

# Vague words that shouldn't dominate ranking on their own.
GENERIC = {"folder", "file", "files", "directory", "new", "some", "thing", "stuff"}

# Common folder names we can turn into real paths from the sentence.
COMMON_PATHS = {
    "applications": "/Applications",
    "application": "/Applications",
    "apps": "/Applications",
    "app": "/Applications",
    "programs": "/Applications",
    "downloads": "~/Downloads",
    "download": "~/Downloads",
    "desktop": "~/Desktop",
    "documents": "~/Documents",
    "document": "~/Documents",
    "docs": "~/Documents",
    "doc": "~/Documents",
    "pictures": "~/Pictures",
    "picture": "~/Pictures",
    "pics": "~/Pictures",
    "pic": "~/Pictures",
    "photos": "~/Pictures",
    "photo": "~/Pictures",
    "music": "~/Music",
    "songs": "~/Music",
    "movies": "~/Movies",
    "movie": "~/Movies",
    "videos": "~/Movies",
    "video": "~/Movies",
    "library": "~/Library",
    "trash": "~/.Trash",
    "home": "~",
    "root": "/",
}

# Longer, more specific words are matched first (e.g. "applications" before "app").
_PATH_WORDS = sorted(COMMON_PATHS, key=len, reverse=True)


def tokenize(text):
    return [w for w in re.findall(r"[a-z0-9]+", text.lower()) if w not in STOPWORDS]


def infer_path(query):
    """Guess a real path from folder names in the query, tolerating typos."""
    lowered = query.lower()
    for word in _PATH_WORDS:
        if re.search(rf"\b{word}\b", lowered):
            return COMMON_PATHS[word]
    for token in re.findall(r"[a-z0-9]+", lowered):
        match = difflib.get_close_matches(token, _PATH_WORDS, n=1, cutoff=0.8)
        if match:
            return COMMON_PATHS[match[0]]
    return None


def search(query, limit=3):
    words = tokenize(query)
    scored = []
    for entry in KNOWLEDGE_BASE:
        keys = set(entry["keywords"])
        desc_words = set(tokenize(entry["desc"]))
        cmd_words = set(tokenize(entry["cmd"]))
        score = 0.0
        for w in words:
            weight = 0.5 if w in GENERIC else 1.0
            if w in cmd_words:
                # user typed the actual command name (e.g. "grep")
                score += 3.0
            if w in keys:
                score += 2.0 * weight
            elif any(w in k or k in w for k in keys):
                score += 1.0 * weight
            elif difflib.get_close_matches(w, keys, n=1, cutoff=0.8):
                score += 1.5 * weight  # typo-tolerant match
            if w in desc_words:
                score += 1.0 * weight
        if score > 0:
            scored.append((score, entry))
    scored.sort(key=lambda x: x[0], reverse=True)
    if not scored:
        return []
    top = scored[0][0]
    # only keep strong matches so a clear winner isn't buried in noise
    strong = [entry for s, entry in scored if s >= top * 0.6]
    return strong[:limit]


# --- Local LLM (Ollama) --------------------------------------------------
# Primary engine when a local Ollama server is running; the keyword search
# above is the fallback whenever the model is unavailable or fails.

_LLM_OK = None  # cached availability for the life of the process

LLM_INSTRUCTIONS = (
    "You translate a plain-English request into safe shell commands for a Unix "
    "shell (macOS/Linux). Reply with ONLY JSON of the form "
    '{"commands": [{"cmd": "...", "desc": "..."}]}. Give at most 3 commands, '
    "best first. Use <name> placeholders for values the user must fill in "
    "(e.g. <path>, <file>). Do not invent flags; prefer standard tools. No prose."
)


def ollama_available():
    """True if a local Ollama server answers quickly and LLM use is enabled."""
    global _LLM_OK
    if _LLM_OK is not None:
        return _LLM_OK
    if not CONFIG.get("use_llm", True):
        _LLM_OK = False
        return False
    try:
        urllib.request.urlopen(OLLAMA_URL + "/api/tags", timeout=0.4).read()
        _LLM_OK = True
    except Exception:  # noqa: BLE001 - any failure means "just use keywords"
        _LLM_OK = False
    return _LLM_OK


def _parse_llm_json(text, limit):
    """Pull command entries out of the model's JSON reply. Returns [] on junk."""
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return []
    if isinstance(parsed, dict):
        items = parsed.get("commands") or parsed.get("results") or []
    elif isinstance(parsed, list):
        items = parsed
    else:
        items = []
    out = []
    for it in items:
        if isinstance(it, dict) and str(it.get("cmd", "")).strip():
            out.append({
                "cmd": str(it["cmd"]).strip(),
                "desc": str(it.get("desc", "")).strip() or "AI suggestion",
                "keywords": [],
            })
    return out[:limit]


def llm_search(query, limit=3):
    """Ask local Ollama to turn the query into commands. None if unavailable."""
    if not query.strip() or not ollama_available():
        return None
    body = json.dumps({
        "model": CONFIG.get("model", "llama3.2:3b"),
        "prompt": f"{LLM_INSTRUCTIONS}\n\nRequest: {query}\nJSON:",
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.1},
    }).encode()
    try:
        req = urllib.request.Request(
            OLLAMA_URL + "/api/generate", data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.load(resp)
    except Exception:  # noqa: BLE001 - fall back to keyword search on any error
        return None
    results = _parse_llm_json(data.get("response", ""), limit)
    return results or None


# Slash commands shown when you type "/" at the query prompt.
SLASH_COMMANDS = [
    ("/back", "go back to search"),
    ("/add", "add your own command"),
    ("/settings", "change the theme"),
    ("/exit", "leave cmd-help"),
]

# User-defined commands persist here and are merged into the knowledge base.
CUSTOM_FILE = os.path.expanduser("~/.cmdhelp_commands.json")

# Vocabulary of known words, used for Tab autocomplete / spell-fix.
VOCAB = set()


def load_custom_commands():
    """Load user commands from CUSTOM_FILE and append them to the knowledge base."""
    try:
        with open(CUSTOM_FILE) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return
    for entry in data:
        if isinstance(entry, dict) and entry.get("cmd") and entry.get("desc"):
            entry.setdefault("keywords", [])
            KNOWLEDGE_BASE.append(entry)


def save_custom_command(entry):
    """Append one command to CUSTOM_FILE, preserving what's already there."""
    data = []
    try:
        with open(CUSTOM_FILE) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        data = []
    data.append(entry)
    with open(CUSTOM_FILE, "w") as fh:
        json.dump(data, fh, indent=2)


def build_vocab():
    """Collect all known words for autocomplete."""
    VOCAB.clear()
    for entry in KNOWLEDGE_BASE:
        VOCAB.update(entry["keywords"])
        VOCAB.update(tokenize(entry["desc"]))
    VOCAB.update(COMMON_PATHS.keys())


def complete_word(word):
    """Return the best completion/correction for a partial word, or None."""
    if not word:
        return None
    prefix = [w for w in VOCAB if w.startswith(word) and w != word]
    if prefix:
        return min(prefix, key=len)
    close = difflib.get_close_matches(word, VOCAB, n=1, cutoff=0.6)
    return close[0] if close and close[0] != word else None

try:
    import termios
    import tty
    _HAS_TTY = True
except ImportError:
    _HAS_TTY = False


def rich_mode():
    """True when we can drive the terminal directly (arrow keys, live input)."""
    return _HAS_TTY and sys.stdin.isatty() and sys.stderr.isatty()


@contextlib.contextmanager
def raw_mode():
    """Hold the terminal in raw mode for a whole widget (no per-key flush)."""
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd, termios.TCSANOW)
        yield
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def read_key():
    """Read one keypress. Assumes raw_mode() is already active."""
    fd = sys.stdin.fileno()
    ch = os.read(fd, 1).decode(errors="ignore")
    if ch == "\x1b":  # escape sequence (arrow keys) or a bare Esc
        if select.select([fd], [], [], 0.05)[0]:
            seq = os.read(fd, 2).decode(errors="ignore")
            return {"[A": "up", "[B": "down", "[C": "right", "[D": "left"}.get(seq, "esc")
        return "esc"
    if ch in ("\r", "\n"):
        return "enter"
    if ch == "\x03":
        raise KeyboardInterrupt
    if ch in ("\x7f", "\b"):
        return "backspace"
    return ch


def _fit(text, width):
    if width < 4:
        width = 4
    return text if len(text) <= width else text[: width - 1] + "\u2026"


def choose(options):
    """Arrow-key menu over options (list of display strings). Returns index or None."""
    idx = 0

    def draw(first):
        if not first:
            sys.stderr.write(f"\r\x1b[{len(options)}A")
        cols = shutil.get_terminal_size((80, 24)).columns
        for i, opt in enumerate(options):
            marker = ">" if i == idx else " "
            shown = _fit(opt, cols - 6)  # keep each row on one physical line
            body = f"\x1b[7m {shown} \x1b[0m" if i == idx else f" {shown} "
            sys.stderr.write(f"\x1b[2K  {marker}{body}\r\n")
        sys.stderr.flush()

    with raw_mode():
        draw(first=True)
        while True:
            try:
                key = read_key()
            except KeyboardInterrupt:
                return None
            if key == "up":
                idx = (idx - 1) % len(options)
            elif key == "down":
                idx = (idx + 1) % len(options)
            elif key == "enter":
                return idx
            elif key == "esc":
                return None
            else:
                continue
            draw(first=False)


def read_line(prompt, default=None):
    """Read a line of text. Returns the text, the default, or QUIT."""
    if not rich_mode():
        value = ask(prompt)
        if value is QUIT:
            return QUIT
        return value or (default or "")
    sys.stderr.write("  " + prompt)
    sys.stderr.flush()
    buf = ""
    with raw_mode():
        while True:
            try:
                key = read_key()
            except KeyboardInterrupt:
                return QUIT
            if key == "enter":
                sys.stderr.write("\r\n")
                return buf.strip() or (default or "")
            if key == "esc":
                sys.stderr.write("\r\n")
                return QUIT
            if key == "backspace":
                if buf:
                    buf = buf[:-1]
                    sys.stderr.write("\b \b")
                    sys.stderr.flush()
                continue
            if len(key) == 1 and key.isprintable():
                buf += key
                sys.stderr.write(key)
                sys.stderr.flush()


def short_cwd():
    home = os.path.expanduser("~")
    cwd = os.getcwd()
    return "~" + cwd[len(home):] if cwd.startswith(home) else cwd


def _pad(text, width):
    if len(text) > width:
        text = text[: width - 1] + "\u2026"
    return text + " " * (width - len(text))


def box_lines(query, items, idx, hint):
    """Build the bordered box: input line on top, suggestions grow below."""
    t = theme()
    b, r, sel, dim = t["border"], t["reset"], t["sel"], t["dim"]
    cols = shutil.get_terminal_size((80, 24)).columns
    inner = max(28, min(cols - 4, 96))
    H, V = "\u2500", "\u2502"
    TL, TR, BL, BR = "\u256d", "\u256e", "\u2570", "\u256f"
    ML, MR = "\u251c", "\u2524"
    out = [b + TL + H * inner + TR + r]
    out.append(b + V + r + _pad(" \u203a " + query + "\u2588", inner) + b + V + r)
    if items:
        out.append(b + ML + H * inner + MR + r)
        for i, it in enumerate(items):
            content = _pad("  " + it, inner)
            if i == idx:
                out.append(b + V + r + sel + content + r + b + V + r)
            else:
                out.append(b + V + r + content + b + V + r)
    out.append(b + BL + H * inner + BR + r)
    if hint:
        out.append(dim + "  " + _fit(hint, inner) + r)
    return out


def render(lines, prev):
    """Draw the box anchored to the bottom of the terminal.

    The box's bottom edge sits on the last row; as suggestions appear it grows
    upward instead of pushing content down, so the input line stays put.
    """
    rows = shutil.get_terminal_size((80, 24)).lines
    height = len(lines)
    top = max(1, rows - height + 1)
    old_top = max(1, rows - prev + 1) if prev else top
    clear_top = min(top, old_top)
    # Clear the whole region the box could occupy, then draw at the anchored top.
    sys.stderr.write(f"\x1b[{clear_top};1H\x1b[0J")
    sys.stderr.write(f"\x1b[{top};1H")
    sys.stderr.write("\r\n".join(lines))
    sys.stderr.flush()
    return height


def box_session():
    """Live box: type to search, arrows to select, enter to choose.

    Returns ("entry", entry, query), ("slash", name, query), or None (quit).
    """
    sys.stderr.write("\x1b[?25l")
    prev = 0
    query = ""
    idx = 0
    navigated = False  # True once the user arrows onto a specific suggestion

    def ask_ai():
        """Show a waiting line and ask the local LLM. Returns entries or None."""
        nonlocal prev
        if not query.strip():
            return None
        prev = render(box_lines(query, display, idx, "asking the AI\u2026  please wait"), prev)
        return llm_search(query)

    ai_on = ollama_available()
    hint = (
        "type search   up/down pick   enter ask AI   ^a force AI   / menu   esc quit"
        if ai_on else
        "type to search   up/down select   enter run   / menu   tab complete   esc quit"
    )
    try:
      with raw_mode():
        while True:
            slash = query.startswith("/")
            if slash:
                matches = [(n, d) for n, d in SLASH_COMMANDS if n.startswith(query) or query == "/"]
                display = [f"{n}   {d}" for n, d in matches]
                entries = []
            else:
                entries = search(query) if query.strip() else []
                display = [label_for(e) for e in entries]
            if idx >= len(display):
                idx = max(0, len(display) - 1)
            prev = render(box_lines(query, display, idx, hint), prev)
            try:
                key = read_key()
            except KeyboardInterrupt:
                return None
            if key == "esc":
                return None
            if key == "enter":
                if slash:
                    if not display:
                        continue
                    return ("slash", matches[idx][0], query)
                # Explicitly navigated to a known command: run it directly.
                if navigated and display:
                    return ("entry", entries[idx], query)
                # LLM primary: interpret the query; fall back to keyword hits.
                ai = ask_ai()
                if ai:
                    return ("results", ai, query) if len(ai) > 1 else ("entry", ai[0], query)
                if display:
                    return ("entry", entries[idx], query)
                continue
            if key == "\x01" and not slash:  # Ctrl+A: force the AI
                ai = ask_ai()
                if ai:
                    return ("results", ai, query) if len(ai) > 1 else ("entry", ai[0], query)
                continue
            if key == "up" and display:
                idx = (idx - 1) % len(display)
                navigated = True
            elif key == "down" and display:
                idx = (idx + 1) % len(display)
                navigated = True
            elif key == "backspace":
                query = query[:-1]
                idx = 0
                navigated = False
            elif key == "\t":
                parts = query.split(" ")
                done = complete_word(parts[-1])
                if done:
                    parts[-1] = done
                    query = " ".join(parts)
                idx = 0
                navigated = False
            elif len(key) == 1 and key.isprintable():
                query += key
                idx = 0
                navigated = False
    finally:
        # Erase the bottom-anchored box so relaunches don't stack a trail of old
        # boxes; only the chosen command's output stays, one fresh box at bottom.
        if prev:
            rows = shutil.get_terminal_size((80, 24)).lines
            top = max(1, rows - prev + 1)
            sys.stderr.write(f"\x1b[{top};1H\x1b[0J")
        sys.stderr.write("\x1b[?25h")
        sys.stderr.flush()


def fill_placeholders(cmd, query=""):
    """Fill <placeholder> tokens, guessing paths from context. Returns cmd or QUIT."""
    default_path = infer_path(query)
    for token in dict.fromkeys(re.findall(r"<[^>]+>", cmd)):
        name = token.strip("<>")
        is_pathlike = any(k in name.lower() for k in ("path", "dir", "dest", "source"))
        default = default_path if (default_path and is_pathlike) else None
        prompt = f"{name}" + (f" [{default}]: " if default else ": ")
        value = read_line(prompt, default)
        if value is QUIT:
            return QUIT
        if not value:
            ui("    (kept placeholder)")
            continue
        cmd = cmd.replace(token, value)
    return cmd


def label_for(entry):
    risk = classify_risk(entry["cmd"])
    return f"{entry['cmd']:<34} [{RISK_LABELS[risk]}]  {entry['desc']}"


EXIT_LABEL = "exit  -  quit cmd-help"


def pick_command(results):
    """Choose a command from results. Returns entry, None (go back), or QUIT."""
    if rich_mode():
        ui("")
        ui("  " + "-" * 48)
        ui("  CHOOSE A COMMAND   (up/down to move, enter to select)")
        ui("  " + "-" * 48)
        options = [label_for(e) for e in results] + [EXIT_LABEL]
        pick = choose(options)
        if pick is None:  # esc = go back to the question
            return None
        if pick == len(results):  # the exit entry
            return QUIT
        return results[pick]
    ui("\n  choose a command:")
    for i, entry in enumerate(results, 1):
        ui(f"  {i}. {label_for(entry)}")
    ui("  0. exit")
    choice = ask("\n  pick a number (Enter to go back): ")
    if choice is QUIT or choice == "0":
        return QUIT
    if not choice.isdigit():
        return None
    idx = int(choice) - 1
    return results[idx] if 0 <= idx < len(results) else None


def confirm(risk):
    """Safe runs instantly; caution/dangerous need a single 'y' keypress."""
    if risk == "safe":
        return True
    if risk == "dangerous":
        ui("  !! DANGEROUS - can delete data or change permissions/processes.")
    else:
        ui("  !  modifies files or state.")
    if rich_mode():
        sys.stderr.write("  run it? [y/N] ")
        sys.stderr.flush()
        try:
            with raw_mode():
                key = read_key()
        except KeyboardInterrupt:
            key = ""
        sys.stderr.write("\r\n")
        return key.lower() == "y"
    answer = ask("  run it? [y/N] ")
    return answer is not QUIT and answer.lower() in ("y", "yes")


def run_in_session(cmd):
    """Run a command in-process (direct mode). `cd` handled so it persists here."""
    cd_match = re.match(r"^\s*cd\s*(.*)$", cmd)
    if cd_match:
        target = os.path.expanduser(os.path.expandvars(cd_match.group(1).strip() or "~"))
        try:
            os.chdir(target)
        except OSError as exc:
            ui(f"  cd failed: {exc}")
        return
    try:
        subprocess.run(cmd, shell=True)
    except Exception as exc:  # noqa: BLE001 - surface any run failure
        ui(f"  failed: {exc}")


def deliver(cmd):
    """Hand off the command. EMIT: print for the wrapper to run in the real shell
    (so cd affects your terminal and the box reopens). Otherwise run in-process.
    Returns True when the process should exit (EMIT hand-off)."""
    if EMIT:
        print(cmd)
        return True
    run_in_session(cmd)
    return False


def settings_flow():
    """Pick a color theme or toggle the local-LLM engine; saved to CONFIG_FILE."""
    ui("\n  settings:")
    ai_state = "on" if CONFIG.get("use_llm", True) else "off"
    top = choose(["theme", f"AI engine (currently {ai_state})"])
    if top is None:
        return
    if top == 1:
        CONFIG["use_llm"] = not CONFIG.get("use_llm", True)
        global _LLM_OK
        _LLM_OK = None  # re-check availability next time
        save_config()
        ui(f"  AI engine turned {'on' if CONFIG['use_llm'] else 'off'}\n")
        return
    names = list(THEMES)
    labels = [n + ("  (current)" if n == CONFIG["theme"] else "") for n in names]
    ui("\n  choose a theme:")
    pick = choose(labels)
    if pick is None:
        return
    CONFIG["theme"] = names[pick]
    save_config()
    ui(f"  theme set to {names[pick]}\n")


def add_command_flow():
    """Interactively add a user command, saved to CUSTOM_FILE."""
    ui("\n  add your own command  (esc to cancel)")
    desc = read_line("description (what it does): ")
    if desc is QUIT or not desc:
        ui("  cancelled\n")
        return
    cmd = read_line("command (use <name> for blanks): ")
    if cmd is QUIT or not cmd:
        ui("  cancelled\n")
        return
    kw = read_line("keywords (comma separated, optional): ")
    if kw is QUIT:
        ui("  cancelled\n")
        return
    keywords = [w.strip().lower() for w in kw.split(",") if w.strip()]
    if not keywords:
        keywords = list(dict.fromkeys(tokenize(desc) + tokenize(cmd)))
    entry = {"desc": desc, "cmd": cmd, "keywords": keywords}
    KNOWLEDGE_BASE.append(entry)
    save_custom_command(entry)
    build_vocab()
    ui(f"  added: {cmd}\n")


def _run_choice(entry, query):
    """Fill placeholders, confirm, deliver. Returns True if process should exit."""
    cmd = fill_placeholders(entry["cmd"], query)
    if cmd is QUIT or ("<" in cmd and ">" in cmd):
        return False
    if not confirm(classify_risk(cmd)):
        return False
    return deliver(cmd)


def rich_loop():
    while True:
        action = box_session()
        if action is None:
            return
        kind, val, query = action
        if kind == "slash":
            if val == "/exit":
                return
            if val == "/add":
                add_command_flow()
            elif val == "/settings":
                settings_flow()
            continue
        if kind == "results":  # multiple AI suggestions: let the user pick one
            chosen = pick_command(val)
            if chosen is QUIT:
                return
            if chosen is None:
                continue
            if _run_choice(chosen, query):
                return
            continue
        if _run_choice(val, query):
            return  # EMIT hand-off: wrapper runs it and relaunches the box


def fallback_loop():
    while True:
        query = ask("  what do you want to do? (/exit) > ")
        if query is QUIT:
            return
        if query == "/add":
            add_command_flow()
            continue
        if query == "/settings":
            settings_flow()
            continue
        if not query:
            continue
        results = llm_search(query) or search(query)
        if not results:
            ui("  no match, try different words\n")
            continue
        chosen = pick_command(results)
        if chosen is QUIT:
            return
        if chosen is None:
            continue
        if _run_choice(chosen, query):
            return


def interactive():
    if rich_mode():
        rich_loop()
    else:
        fallback_loop()


def main():
    load_config()
    load_custom_commands()
    build_vocab()
    if len(sys.argv) > 1:
        results = search(" ".join(sys.argv[1:]))
        if not results:
            ui("  no match")
            return
        for i, entry in enumerate(results, 1):
            ui(f"  {i}. {label_for(entry)}")
    else:
        interactive()


if __name__ == "__main__":
    main()
