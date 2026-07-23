# cmd-help

An offline terminal command helper. Describe what you want to do in plain English and it suggests the shell command. No API key, no internet, no dependencies (Python 3 only).

## Usage (recommended: shell wrapper)

cmd-help is a little **box at the bottom of your terminal**. You type, pick a
command, and it runs in your real shell (so `cd` moves your actual terminal),
then the box reopens so you can keep going. Add this to your `~/.zshrc`, reload
with `source ~/.zshrc`, then just type `cmdhelp`:

```sh
cmdhelp() {
  while true; do
    local c
    c="$(CMDHELP_EMIT=1 python3 ~/cmdhelp.py)" || break
    [ -z "$c" ] && break
    print -s -- "$c"
    eval "$c"
  done
}
```

You can also run it directly (`python3 cmdhelp.py`); without the wrapper it runs
commands in its own process instead of your shell.

## Interface

- A bordered box shows an input line; suggestions appear below and the box grows
  with the list. Everything stays on one line each (no wrapping glitches).
- Type your request in plain English; matches update live as you type.
- Press **Tab** to autocomplete / spell-fix the word you're typing.
- Type `/` for the command menu (`/add`, `/settings`, `/exit`). You can keep
  typing to filter it, and **Backspace** takes you back to searching.
- Move with the **up/down arrows**, run with **Enter**, quit with **Esc**.
- `safe` commands run instantly; `caution`/`DANGEROUS` need one `y` keypress.

## Adding your own commands

Pick `/add` and answer three prompts (description, command, keywords). Use
`<name>` in the command for values you'll fill in later. Your commands are saved
to `~/.cmdhelp_commands.json` and loaded every time.

## Themes

Pick `/settings` to change the color theme (minimal, cyan, green, magenta,
amber). Your choice is saved to `~/.cmdhelp_config.json`.

## Risk labels and smart paths

Each suggestion is labeled so you can see the risk before choosing:

- `ok safe` - read-only, no changes
- `!  caution` - modifies files or state (e.g. `mv`, `cp`, `git push`)
- `!! DANGEROUS` - can delete data or change permissions/processes (e.g. `rm -rf`, `kill`, `chmod`)

It also fills paths from context: say "go to my apps" and it pre-fills
`/Applications` (recognizes Applications, Downloads, Desktop, Documents,
Pictures, Music, Movies, Library, Trash, Home, and common synonyms). Typos are
tolerated too ("downlods", "aplications"). Press Enter to accept the default.

## How it works

It matches your words against a built-in knowledge base of common commands using keyword scoring, then ranks the best matches. To add your own commands, edit the `KNOWLEDGE_BASE` list in `cmdhelp.py`.
