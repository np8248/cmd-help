# cmd-help

An offline terminal command helper. Describe what you want to do in plain English and it suggests the shell command. No API key, no internet, no dependencies (Python 3 only).

## Usage (recommended: shell wrapper)

Instead of running the command for you, cmd-help **pastes it onto your command
line**, ready to edit and run. Nothing executes on its own. To enable that, add
this function to your `~/.zshrc` (zsh is the macOS default):

```sh
cmdhelp() {
  local c
  c="$(CMDHELP_EMIT=1 python3 ~/cmdhelp.py "$@")" || return
  [ -n "$c" ] && print -z -- "$c"
}
```

Reload with `source ~/.zshrc`, then just type `cmdhelp`. Pick a command and it
appears on your prompt (with `cd`, paths, etc. already filled in) so you review
and press Enter yourself. This is why shell state like `cd` works.

You can also run it directly without the wrapper:

```
python3 cmdhelp.py                 # interactive
python3 cmdhelp.py delete a folder # one-off, just prints matches
```

## Interface

- Type your request in plain English.
- Type `/` to open the command menu (currently just `/exit`).
- Move with the **up/down arrows**, choose with **Enter**.
- Press **Esc** or **Ctrl+C** to go back / leave.
- No typing `y` or `yes`: selecting is the confirmation, and the command is only
  pasted (never auto-run), so you always get the final say.

## Risk labels and smart paths

Each suggestion is labeled so you can see the risk before choosing:

- `ok safe` - read-only, no changes
- `!  caution` - modifies files or state (e.g. `mv`, `cp`, `git push`)
- `!! DANGEROUS` - can delete data or change permissions/processes (e.g. `rm -rf`, `kill`, `chmod`)

It also fills paths from context: say "go to my downloads folder" and it
pre-fills `~/Downloads` (recognizes Downloads, Desktop, Documents, Pictures,
Music, Movies, Home). Press Enter to accept the default.

## How it works

It matches your words against a built-in knowledge base of common commands using keyword scoring, then ranks the best matches. To add your own commands, edit the `KNOWLEDGE_BASE` list in `cmdhelp.py`.
