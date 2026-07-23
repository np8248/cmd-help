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

## Make `cd` and shell state actually work (recommended)

A normal program can't change your shell's directory. To let commands like
`cd` take effect, add this function to your `~/.zshrc` (or `~/.bashrc`):

```sh
cmdhelp() { eval "$(CMDHELP_EMIT=1 python3 ~/cmdhelp.py "$@")"; }
```

Then reload (`source ~/.zshrc`) and just run `cmdhelp`. The menu appears,
and when you approve a command it runs in your current shell, so `cd` sticks.
Without the wrapper, `python3 cmdhelp.py` still works but `cd` won't persist.

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
- `safe` commands run when you press Enter,
- `caution` and `DANGEROUS` commands need a `y` (with a clear warning).

Nothing runs without your approval. Type `exit`, `quit`, `q`, or press Ctrl+C
at any prompt to leave. After a command runs, the tool exits.

## How it works

It matches your words against a built-in knowledge base of common commands using keyword scoring, then ranks the best matches. To add your own commands, edit the `KNOWLEDGE_BASE` list in `cmdhelp.py`.
