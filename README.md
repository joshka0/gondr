# Cloudflare token factory

`cloudflare-token-mint` creates least-privilege, account-owned Cloudflare API
tokens for agents and CI. It keeps the parent token in the macOS Keychain and
never prints it.

## How it works

1. You run `cloudflare-token-mint` with a token name, an account, permissions,
   and an Infisical destination.
2. macOS asks you to approve with Touch ID or your password.
3. The broker reads the parent token from Keychain item
   `gondr-token.cloudflare` (account `bootstrap`).
4. It creates the child token, verifies it, and writes it to Infisical through
   stdin.
5. If verification or storage fails, it revokes the child token.

Only this binary can read the Keychain item. A child token can never manage API
tokens.

## Install

Run `bin/install`. It builds the binary, keeps the old one as
`cloudflare-token-mint.previous`, and binds the Keychain item to the new
binary. macOS asks for your login keychain password during the bind.

## Mint a child token

```sh
cloudflare-token-mint --name <token-name> --account-id <id> \
  --account-permission <name> [--account-permission ...] \
  [--zone <zone> --zone-id <id> --zone-permission <name> ...] \
  --expires-in <N>h|<N>d|never [--allow-ip <cidr> ...] \
  --infisical-project <id> --infisical-env <env> \
  --infisical-path <path> --infisical-secret CLOUDFLARE_<CAPABILITY>_API_TOKEN
```

- `--expires-in` is required. Use `never` only for a token that must outlive a
  rotation cycle.
- `--allow-ip` limits the token to up to 16 IPv4 or IPv6 addresses or CIDR
  ranges.
- Permission names resolve live from the account. A name that matches zero or
  several groups fails.

## Revoke a child token

```sh
cloudflare-token-mint --revoke <token-name> --account-id <id>
```

The broker deletes the one account token with that exact name. It fails if no
token or several tokens have that name. It does not delete the Infisical secret.

## Check the parent token

```sh
cloudflare-token-mint --check-keychain
```

This reports presence only.
