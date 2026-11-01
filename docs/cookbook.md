# Cookbook: secrets for coding agents

This cookbook shows how to give coding agents (Claude Code, Codex, opencode and others) the secrets they need
without putting a value in their context. It uses two open-source Infisical products. You can follow it by hand
with the `infisical` and `agent-vault` CLIs. `gondr` does each recipe in one command; the last line of each
recipe names that command.

## The problem

An agent that reads `.env`, runs `env`, or pastes a key into a command line puts the value into its transcript.
Transcripts get logged, synced and sent to model providers. The goal is that the agent can use a key, but the
value never reaches its context.

## The pieces

- **Infisical** stores the values. Agents see key names only.
- **Infisical Agent Vault** is a credential proxy. An agent process runs behind it, and the proxy adds the key to
  requests for a mapped host. The value never enters the agent process.
- **A machine identity** (Universal Auth) lets your tools sign in to Infisical without a person.

## Recipe 1: one folder per repo

Give each local repo one Infisical folder that mirrors its path:

| Local | Infisical folder |
| --- | --- |
| `~/repos/acme/api` | `/repos/acme/api` |
| `~/repos/acme/web` | `/repos/acme/web` |

Any tool can then find the folder from the working directory, with no per-repo config. Map a linked Git
worktree to the folder of its main checkout, so every worktree of a repo shares one set of secrets.

By hand: create the folder in the Infisical UI, or with `infisical secrets folders create`.
With gondr: `gondr set` and `gondr need` create the folder and its missing parents.

## Recipe 2: store a shared key once

Put a key that many repos use (an OpenAI key, a GitHub token) in one folder under `/shared/<vendor>`.
In each repo folder that needs it, add a secret import of that folder. A rotation then changes one value.

By hand: add the import in the Infisical UI (**Secret Imports**), or `POST /api/v2/secret-imports`.
With gondr: `gondr where <KEY>` finds the owner folder, and `gondr need <KEY>` adds the import.

## Recipe 3: write a value without a transcript

A value in argv lands in shell history, process lists and the agent transcript. Read it from stdin instead.

By hand: type the value in the Infisical UI.
With gondr: `printf %s "$VALUE" | gondr set <KEY>`.

## Recipe 4: run a command with the folder's secrets

When a program reads a key from its environment, inject the folder's secrets into that one process:

```sh
infisical run --env=dev --path=/repos/acme/api -- <cmd>
```

The agent sees the command's output, not the environment. This does not stop an agent that runs `env` on
purpose. When the agent must not read a key at all, use recipe 5.

With gondr: `gondr run -- <cmd>`.

## Recipe 5: proxy the key instead of injecting it

Run the agent behind Agent Vault. Map each service host to a key in a vault. The agent calls the host with no
auth header, and the proxy adds it.

1. Store the key in Infisical, in a references folder such as `/repos/acme/api/agent-vault`.
2. Create a vault on the Infisical credential store:
   `agent-vault vault create acme-api-dev --credential-store infisical --infisical-project-id <id> --infisical-environment dev --infisical-path /repos/acme/api/agent-vault`
3. Grant your agent the proxy role: `agent-vault vault agent add <agent> --role proxy --vault acme-api-dev`.
4. Add each service host:
   `agent-vault vault service add --vault acme-api-dev --name openai --host api.openai.com --auth-type bearer --token-key OPENAI_API_KEY`
5. Sync the vault: `agent-vault vault credential-store sync acme-api-dev`.
6. Start the agent: `agent-vault run --vault acme-api-dev -- <agent>`.

Put the Infisical host in `NO_PROXY`, so the agent's own Infisical calls do not go through the proxy.

With gondr: `gondr onboard /repos/acme/api --admin-home DIR` does steps 1 to 5, and `gondr agent <agent>` does step 6.

## Recipe 6: keep a client's secrets apart

When you work for several clients on one machine, keep each client's secrets inside its own directories.
Give each client a folder prefix (`/repos/acme`) and a vault prefix (`acme`). A command in `~/repos/acme` then
reaches only `/repos/acme` and `acme*` vaults, and a command elsewhere reaches neither.

A tool can enforce this rule, but Infisical does not: one identity can read every folder it has access to.
For a hard limit, give each client its own machine identity and project.

With gondr: a `[[boundary]]` table in the config. See the README.

## Recipe 7: tell the agent the rules

An agent follows the route it is given. Put the rules in its `AGENTS.md` or `CLAUDE.md`:

- Never read `.env` files, never print the environment, and never put a value in a command line.
- To use a key, call the proxied host, or run the command under the secret runner.
- When a key is missing, stop that step and give the operator the command to add it.

With gondr: copy the block in [`agents.md`](agents.md). `gondr find <what>` prints the route for one secret.

## Limits

This setup keeps values out of an agent's context by accident. It does not stop an agent that wants a value:
a proxied process can still use a key through the proxy, and `infisical run -- env` prints every value.
Set a short access token TTL on the machine identity.
