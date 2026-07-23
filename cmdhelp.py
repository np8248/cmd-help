#!/usr/bin/env python3
"""cmd-help: an offline, no-API-key helper that turns plain English into shell commands."""

import difflib
import os
import re
import select
import sys

# When run through the shell wrapper (see README), we print the chosen command
# to stdout so the user's shell can paste it onto the command line (print -z).
EMIT = bool(os.environ.get("CMDHELP_EMIT"))

# Sentinel returned by ask() when the user wants to quit from any prompt.
QUIT = object()


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


# Slash commands shown when you type "/" at the query prompt.
SLASH_COMMANDS = [
    ("/exit", "leave cmd-help"),
]

try:
    import termios
    import tty
    _HAS_TTY = True
except ImportError:
    _HAS_TTY = False


def rich_mode():
    """True when we can drive the terminal directly (arrow keys, live input)."""
    return _HAS_TTY and sys.stdin.isatty() and sys.stderr.isatty()


def read_key():
    """Read a single keypress in raw mode. Returns a name or the character."""
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
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
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def choose(options):
    """Arrow-key menu over options (list of display strings). Returns index or None."""
    idx = 0

    def draw(first):
        if not first:
            sys.stderr.write(f"\x1b[{len(options)}A")
        for i, opt in enumerate(options):
            marker = ">" if i == idx else " "
            body = f"\x1b[7m {opt} \x1b[0m" if i == idx else f" {opt} "
            sys.stderr.write(f"\x1b[2K  {marker}{body}\n")
        sys.stderr.flush()

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
    while True:
        try:
            key = read_key()
        except KeyboardInterrupt:
            return QUIT
        if key == "enter":
            sys.stderr.write("\n")
            return buf.strip() or (default or "")
        if key == "esc":
            sys.stderr.write("\n")
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


def prompt_query():
    """Query prompt. Typing '/' first opens the slash-command menu."""
    if not rich_mode():
        return ask("  what do you want to do?  (type /exit to quit) > ")
    sys.stderr.write("  what do you want to do?  (type / for commands)\n  > ")
    sys.stderr.flush()
    buf = ""
    while True:
        try:
            key = read_key()
        except KeyboardInterrupt:
            return QUIT
        if key == "enter":
            sys.stderr.write("\n")
            return buf.strip()
        if key == "esc":
            sys.stderr.write("\n")
            return QUIT
        if key == "backspace":
            if buf:
                buf = buf[:-1]
                sys.stderr.write("\b \b")
                sys.stderr.flush()
            continue
        if key == "/" and buf == "":
            sys.stderr.write("\n")
            labels = [f"{name}  -  {desc}" for name, desc in SLASH_COMMANDS]
            pick = choose(labels)
            if pick is not None and SLASH_COMMANDS[pick][0] == "/exit":
                return QUIT
            return ""  # menu dismissed, ask again
        if len(key) == 1 and key.isprintable():
            buf += key
            sys.stderr.write(key)
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


def emit(cmd):
    """Hand the command back: paste via the shell wrapper, or print it."""
    if EMIT:
        print(cmd)  # stdout -> wrapper runs `print -z` to paste onto the prompt
    else:
        ui(f"\n  ready: {cmd}")
        ui("  (add the shell wrapper from the README to auto-paste this)\n")
        print(cmd)


def interactive():
    ui("  cmd-help  -  describe what you want, get the command")
    ui("  type / for commands, esc/Ctrl+C to leave\n")
    while True:
        query = prompt_query()
        if query is QUIT:
            ui("  bye!")
            return
        if not query:
            continue
        results = search(query)
        if not results:
            ui("  no match, try different words\n")
            continue
        chosen = pick_command(results)
        if chosen is QUIT:
            ui("  bye!")
            return
        if chosen is None:
            ui("")
            continue
        cmd = fill_placeholders(chosen["cmd"], query)
        if cmd is QUIT:
            ui("  bye!")
            return
        if "<" in cmd and ">" in cmd:
            ui("  still has placeholders, skipping\n")
            continue
        emit(cmd)
        return


def main():
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
