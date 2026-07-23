# cmd-help

An offline terminal command helper. Describe what you want to do in plain English and it suggests the shell command. No API key, no internet, no dependencies (Python 3 only).

## Usage

cmd-help runs as a **persistent session**: describe what you want, pick a
command, it runs and shows the output, then drops you back at the input box to
keep going. No restart between commands.

Optional shortcut: add this to your `~/.zshrc`, reload with `source ~/.zshrc`,
then just type `cmdhelp`:

```sh
cmdhelp() { python3 ~/cmdhelp.py "$@"; }
```

Or run it directly:

```
python3 cmdhelp.py                 # interactive session
python3 cmdhelp.py delete a folder # one-off, just prints matches
```

## Interface

- Type your request in plain English, then keep typing new ones after each run.
- Type `/` to open the command menu (currently just `/exit`).
- Move with the **up/down arrows**, choose with **Enter**.
- Press **Esc** to go back, `/exit` or **Ctrl+C** to leave.
- The prompt shows your current directory. `cd` persists inside the session
  (but not your outer terminal after you quit, which a child program can't change).
- `safe` commands run instantly; `caution`/`DANGEROUS` need one `y` keypress.

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
