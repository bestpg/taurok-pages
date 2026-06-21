#!/usr/bin/env bash
###############################################################################
# bootstrap.sh — one-shot provisioning for the "taurok" Cloudflare Pages site.
#
# Run this ON YOUR MACHINE (it needs internet access, which the build sandbox
# does not have). It will:
#   1. verify the Cloudflare root token + find your account id
#   2. create the Pages project   -> taurok.pages.dev
#   3. create a SCOPED deploy token (least privilege) from the root token
#   4. write the encrypted ansible vault (root creds + deploy token + gh token)
#   5. create a PRIVATE GitHub repo
#   6. commit everything (incl. the encrypted vault) and push
#
# Requires: bash, curl, jq, git, python3 (with the 'cryptography' module).
###############################################################################
set -euo pipefail
cd "$(dirname "$0")"

# clean up stray files the build sandbox may have left behind
rm -rf tmpcheck _probe.txt 2>/dev/null || true

for bin in curl jq git python3; do
  command -v "$bin" >/dev/null || { echo "Missing required tool: $bin" >&2; exit 1; }
done
[[ -f secrets.env ]] || { echo "secrets.env not found." >&2; exit 1; }
# shellcheck disable=SC1091
source secrets.env

CF_API="https://api.cloudflare.com/client/v4"
say() { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

cf() {  # cf METHOD PATH [json-body]   (Global API Key auth: email + key)
  local method="$1" path="$2" body="${3:-}"
  if [[ -n "$body" ]]; then
    curl -fsS -X "$method" "$CF_API$path" \
      -H "X-Auth-Email: $CF_EMAIL" \
      -H "X-Auth-Key: $CF_ROOT_TOKEN" \
      -H "Content-Type: application/json" --data "$body"
  else
    curl -fsS -X "$method" "$CF_API$path" \
      -H "X-Auth-Email: $CF_EMAIL" \
      -H "X-Auth-Key: $CF_ROOT_TOKEN" \
      -H "Content-Type: application/json"
  fi
}

# ── 1. verify token ──────────────────────────────────────────────────────────
say "Verifying Cloudflare global API key"
cf GET /user | jq -e '.success == true' >/dev/null \
  || die "Cloudflare global key did not verify. Check CF_EMAIL / CF_ROOT_TOKEN in secrets.env."

# ── 2. account id ────────────────────────────────────────────────────────────
say "Looking up account id"
CF_ACCOUNT_ID="$(cf GET /accounts | jq -r '.result[0].id')"
[[ -n "$CF_ACCOUNT_ID" && "$CF_ACCOUNT_ID" != null ]] || die "Could not read account id."
echo "    account: $CF_ACCOUNT_ID"

# ── 3. create Pages project (idempotent) ─────────────────────────────────────
say "Ensuring Pages project '$CF_PAGES_PROJECT'"
# Idempotent via existence check (a duplicate POST returns 409, and curl -f hides
# the body, so we can't rely on grepping the create response).
if cf GET "/accounts/$CF_ACCOUNT_ID/pages/projects/$CF_PAGES_PROJECT" >/dev/null 2>&1; then
  echo "    already exists -> https://$CF_PAGES_PROJECT.pages.dev"
else
  proj_body="$(jq -n --arg n "$CF_PAGES_PROJECT" '{name:$n, production_branch:"main"}')"
  cf POST "/accounts/$CF_ACCOUNT_ID/pages/projects" "$proj_body" >/dev/null 2>&1 \
    && echo "    created -> https://$CF_PAGES_PROJECT.pages.dev" \
    || die "Pages project creation failed."
fi

# ── 4. create a scoped deploy token from the root token ──────────────────────
say "Creating scoped Pages deploy token"
PG_JSON="$(cf GET '/user/tokens/permission_groups?per_page=200')"
# Prefer the exact "Pages Write" group; fall back to a pages write/edit group that
# is NOT a "Custom Pages" (error-page branding) or "Access" (Zero Trust) group.
PG_ID="$(printf '%s' "$PG_JSON" | jq -r '.result[] | select(.name=="Pages Write") | .id' | head -n1)"
if [[ -z "$PG_ID" || "$PG_ID" == null ]]; then
  PG_ID="$(printf '%s' "$PG_JSON" | jq -r '.result[] | select((.name|ascii_downcase|test("pages")) and (.name|ascii_downcase|test("write|edit")) and (.name|ascii_downcase|test("custom|access")|not)) | .id' | head -n1)"
fi
[[ -n "$PG_ID" && "$PG_ID" != null ]] || die "Could not find the 'Pages Write' permission group."

tok_body="$(jq -n --arg acct "$CF_ACCOUNT_ID" --arg pg "$PG_ID" '
  { name: "taurok-pages-deploy",
    policies: [ { effect:"allow",
                  resources: { ("com.cloudflare.api.account." + $acct): "*" },
                  permission_groups: [ { id:$pg } ] } ] }')"
CF_DEPLOY_TOKEN="$(cf POST /user/tokens "$tok_body" | jq -r '.result.value')"
[[ -n "$CF_DEPLOY_TOKEN" && "$CF_DEPLOY_TOKEN" != null ]] || die "Deploy token creation failed (the root token may lack 'API Tokens: Write')."
echo "    deploy token created (shown only once, stored in the vault)"

# persist into secrets.env so make_vault.py picks it up
if grep -q '^CF_DEPLOY_TOKEN=' secrets.env; then
  # in-place rewrite (no cross-device mv: secrets.env lives on a restricted mount)
  updated="$(sed "s|^CF_DEPLOY_TOKEN=.*|CF_DEPLOY_TOKEN=$CF_DEPLOY_TOKEN|" secrets.env)"
  printf '%s\n' "$updated" > secrets.env
else
  echo "CF_DEPLOY_TOKEN=$CF_DEPLOY_TOKEN" >> secrets.env
fi

# ── 5. build the encrypted ansible vault ─────────────────────────────────────
say "Building encrypted ansible vault"
python3 make_vault.py build

# ── 6. create the private GitHub repo ────────────────────────────────────────
say "Creating private GitHub repository '$GH_REPO'"
GH_LOGIN="$(curl -fsS -H "Authorization: token $GH_TOKEN" -H "Accept: application/vnd.github+json" https://api.github.com/user | jq -r '.login')"
[[ -n "$GH_LOGIN" && "$GH_LOGIN" != null ]] || die "GitHub token did not authenticate."
echo "    github user: $GH_LOGIN"

repo_body="$(jq -n --arg n "$GH_REPO" '{name:$n, private:true, description:"Cloudflare Pages (taurok) — IaC + encrypted ansible vault"}')"
if curl -fsS -X POST -H "Authorization: token $GH_TOKEN" -H "Accept: application/vnd.github+json" \
     https://api.github.com/user/repos --data "$repo_body" >/tmp/gh_repo.json 2>/tmp/gh_repo.err; then
  echo "    repo created"
else
  grep -q "name already exists" /tmp/gh_repo.json 2>/dev/null \
    && echo "    repo already exists (continuing)" \
    || { cat /tmp/gh_repo.err /tmp/gh_repo.json >&2; die "Repo creation failed."; }
fi

# ── 7. commit + push (with a safety net against leaking plaintext secrets) ────
say "Committing and pushing"
[[ -d .git ]] || git init -q -b main
git config user.email "${GH_LOGIN}@users.noreply.github.com"
git config user.name  "$GH_LOGIN"
git add -A

# SAFETY: refuse to commit if any plaintext token or the secret files got staged
if git ls-files --cached | grep -Eq '^(secrets\.env|\.vault_pass)$'; then
  die "secrets.env / .vault_pass are staged — aborting. Check .gitignore."
fi
if git diff --cached -U0 | grep -Eq 'cfk_[A-Za-z0-9]{20}|ghp_[A-Za-z0-9]{20}'; then
  die "A plaintext token was about to be committed — aborting."
fi

git commit -q 