#!/usr/bin/env python3
"""cmd-help: an offline, no-API-key helper that turns plain English into shell commands."""

import os
import re
import subprocess
import sys

# When run through the shell wrapper (see README), we print the approved
# command to stdout so the user's own shell can eval it. This is the only
# way commands like `cd` can affect the current shell.
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
    if line.lower() in ("quit", "exit", "q"):
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
    "downloads": "~/Downloads",
    "download": "~/Downloads",
    "desktop": "~/Desktop",
    "documents": "~/Documents",
    "document": "~/Documents",
    "pictures": "~/Pictures",
    "picture": "~/Pictures",
    "music": "~/Music",
    "movies": "~/Movies",
    "home": "~",
    "root": "/",
}


def tokenize(text):
    return [w for w in re.findall(r"[a-z0-9]+", text.lower()) if w not in STOPWORDS]


def infer_path(query):
    """Guess a real path from folder names mentioned in the query."""
    lowered = query.lower()
    for word, path in COMMON_PATHS.items():
        if re.search(rf"\b{word}\b", lowered):
            return path
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


def print_results(results):
    if not results:
        ui("\n  No matching command found. Try different words.\n")
        return
    ui("\n  Suggestions:\n")
    for i, entry in enumerate(results, 1):
        risk = classify_risk(entry["cmd"])
        ui(f"  {i}. {entry['desc']}   [{RISK_LABELS[risk]}]")
        ui(f"     $ {entry['cmd']}\n")


def fill_placeholders(cmd, query=""):
    """Prompt the user to fill any <placeholder> tokens, guessing paths from context.

    Returns the filled command, or QUIT if the user chose to exit.
    """
    default_path = infer_path(query)
    tokens = re.findall(r"<[^>]+>", cmd)
    for token in dict.fromkeys(tokens):
        name = token.strip("<>")
        is_pathlike = any(k in name.lower() for k in ("path", "dir", "dest", "source"))
        default = default_path if (default_path and is_pathlike) else None
        prompt = f"    {name}"
        prompt += f" [{default}]: " if default else ": "
        value = ask(prompt)
        if value is QUIT:
            return QUIT
        if not value:
            if default:
                value = default
            else:
                ui("    (nothing entered, keeping placeholder)")
                continue
        cmd = cmd.replace(token, value)
    return cmd


def approve(risk, cmd):
    """Confirm before running. Minimal typing: safe runs on Enter, others need 'y'."""
    ui(f"\n  will run: {cmd}")
    if risk == "dangerous":
        ui("  !! DANGEROUS - can delete data or change permissions/processes.")
        answer = ask("  run it? [y/N]: ")
        return answer is not QUIT and answer.lower() in ("y", "yes")
    if risk == "caution":
        ui("  !  modifies files or state.")
        answer = ask("  run it? [y/N]: ")
        return answer is not QUIT and answer.lower() in ("y", "yes")
    answer = ask("  run it? [Y/n]: ")  # safe: Enter = yes
    return answer is not QUIT and answer.lower() in ("", "y", "yes")


def run_selected(results, query=""):
    """Pick a suggestion and run it. Returns True if a command was executed/emitted."""
    if len(results) == 1:
        choice = ask("  run it? Enter = yes, or 'n' to skip: ")
        if choice is QUIT:
            return QUIT
        if choice.lower() in ("n", "no", "skip"):
            return False
        idx = 0
    else:
        choice = ask("  pick a number to run (Enter to skip): ")
        if choice is QUIT:
            return QUIT
        if not choice.isdigit():
            return False
        idx = int(choice) - 1
        if idx < 0 or idx >= len(results):
            ui("  invalid choice.\n")
            return False

    cmd = fill_placeholders(results[idx]["cmd"], query)
    if cmd is QUIT:
        return QUIT
    if "<" in cmd and ">" in cmd:
        ui("  command still has placeholders, not running.\n")
        return False
    if not approve(classify_risk(cmd), cmd):
        ui("  cancelled.\n")
        return False

    if EMIT:
        print(cmd)  # stdout -> the shell wrapper will eval this
    else:
        ui("")
        try:
            subprocess.run(cmd, shell=True)
        except Exception as exc:
            ui(f"  failed to run: {exc}")
    return True


def interactive():
    ui("=" * 52)
    ui("  cmd-help  -  offline terminal command suggester")
    ui("=" * 52)
    ui("  Describe what you want to do in plain English.")
    ui("  Type 'quit', 'exit', or press Ctrl+C to leave.\n")
    while True:
        query = ask("  what do you want to do? > ")
        if query is QUIT:
            ui("\n  bye!")
            return
        if not query:
            continue
        results = search(query)
        print_results(results)
        if not results:
            continue
        outcome = run_selected(results, query)
        if outcome is QUIT:
            ui("\n  bye!")
            return
        if outcome:  # a command ran; exit so it takes effect in the shell
            return
        ui("")


def main():
    if len(sys.argv) > 1:
        print_results(search(" ".join(sys.argv[1:])))
    else:
        interactive()


if __name__ == "__main__":
    main()
