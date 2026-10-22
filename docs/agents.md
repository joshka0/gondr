# Instructions for coding agents

Copy this block into your `AGENTS.md` or `CLAUDE.md`.

```markdown
## Secrets

This machine uses `gondr` for secrets. You never see secret values, and you never need to.

- To see what this repo has, run `gondr status`.
- When a task needs a secret, run `gondr find <what>` (a key name, a service or a host,
  for example `gondr find stripe`). Follow the route it prints:
  - `proxied`: call the host directly. The proxy adds the key. Send no auth header.
  - `env`: run the command with `gondr run -- <cmd>`. The command reads the variable.
  - `import`: run `gondr need <KEY>`, then use `gondr run`.
  - `repo-owned`, `not-mapped` or `missing`: stop that step. Give the operator the printed command.
- Before you start an app, run `gondr check` to see which names in `.env.example` are missing.
- Never read `.env` files, never print the environment, and never put a value in a command line.
- To store a value the operator gives you, pipe it: `printf %s "$VALUE" | gondr set <KEY>`.
```
