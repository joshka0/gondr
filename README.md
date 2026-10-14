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

## Check the parent token

```sh
cloudflare-token-mint --check-keychain
```

This reports presence only.
