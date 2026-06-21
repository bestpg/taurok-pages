# taurok — Cloudflare Pages + Ansible Vault

Infrastructure-as-code for the `taurok.pages.dev` Cloudflare Pages site. Secrets
live in an **encrypted** Ansible vault; only the encrypted file is committed.

## What's here

| Path | Purpose | Committed? |
|---|---|---|
| `group_vars/all/vault.yml` | AES256-encrypted vault (CF root creds, scoped deploy token, GitHub token) | ✅ yes (encrypted) |
| `make_vault.py` | Builds/reads the vault (ansible-vault 1.1 compatible) | ✅ |
| `bootstrap.sh` | One-shot: create Pages project + scoped token + repo, then push | ✅ |
| `deploy.yml` | Ansible playbook that provisions/verifies the Pages project from the vault | ✅ |
| `deploy.sh` | Deploy `./site` to Pages via Wrangler using the scoped token | ✅ |
| `site/` | The static site served at `taurok.pages.dev` | ✅ |
| `secrets.env` | Plaintext source secrets | ❌ **git-ignored** |
| `.vault_pass` | The vault password | ❌ **git-ignored** |

## Run it (on a machine with internet)

The build environment that generated this had no network access, so the live API
calls and the push are done by `bootstrap.sh` on your machine:

```bash
cd taurok-pages
./bootstrap.sh
```

That verifies the Cloudflare token, creates `taurok.pages.dev`, mints a
least-privilege deploy token, writes it into the encrypted vault, creates the
private GitHub repo, and pushes everything.

Then deploy the actual site content:

```bash
./deploy.sh          # npx wrangler pages deploy site --project-name taurok
```

## Working with the vault

```bash
ansible-vault view group_vars/all/vault.yml      # uses .vault_pass automatically
ansible-vault edit group_vars/all/vault.yml
python3 make_vault.py view                        # same, no ansible needed
ansible-playbook deploy.yml                        # consume the vault
```

## Security notes

- The repo is **private**. Even though the vault is encrypted, never put it in a
  public repo.
- `secrets.env` and `.vault_pass` are git-ignored and must stay that way — they
  are the only plaintext copies and live only on your machine.
- The vault password is kept out of every committed file.
- **Rotate the Cloudflare root token and the GitHub token** now that setup is
  done — they were transmitted in plaintext during setup, so treat them as
  exposed. The day-to-day deploy token is scoped to Pages only.
- Consider a stronger vault passphrase than a name+date; change it with
  `ansible-vault rekey group_vars/all/vault.yml`.
