# cmd-help

An offline terminal command helper. Describe what you want to do in plain English and it suggests the shell command. No API key, no internet, no dependencies (Python 3 only).

## Usage

Interactive menu:

```
python3 cmdhelp.py
```

One-off query:

```
python3 cmdhelp.py delete a folder
```

Type `quit`, `exit`, or `q` to leave the interactive prompt.

## Safety and approval

Each suggestion is labeled with a risk level:

- `ok safe` - read-only, no changes
- `!  caution` - modifies files or state (e.g. `mv`, `cp`, `git push`)
- `!! DANGEROUS` - can delete data or change permissions/processes (e.g. `rm -rf`, `kill`, `chmod`)

It also fills paths from context: if you say "go to my downloads folder" it
suggests `cd` and pre-fills `~/Downloads` (recognizes Downloads, Desktop,
Documents, Pictures, Music, Movies, Home). Press Enter to accept the default.

In interactive mode you can pick a suggestion to run. Before anything executes:

- placeholders like `<dirname>` are filled in by you,
- `caution` commands ask `y/N`,
- `DANGEROUS` commands require you to type `yes` in full.

Nothing runs without your explicit approval.

## How it works

It matches your words against a built-in knowledge base of common commands using keyword scoring, then ranks the best matches. To add your own commands, edit the `KNOWLEDGE_BASE` list in `cmdhelp.py`.
