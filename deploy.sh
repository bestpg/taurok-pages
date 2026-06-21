#!/usr/bin/env bash
# Deploy ./site to Cloudflare Pages using the SCOPED deploy token from the vault.
# Requires Node. Uses npx wrangler (no global install needed).
set -euo pipefail
cd "$(dirname "$0")"

read_vault_val() { python3 make_vault.py view | awk -F'"' -v k="$1" '$0 ~ k"\\:" {print $2; exit}'; }

export CLOUDFLARE_API_TOKEN="$(read_vault_val cloudflare_pages_deploy_token)"
PROJECT="$(read_vault_val cloudflare_pages_project)"

if [[ -z "$CLOUDFLARE_API_TOKEN" || "$CLOUDFLARE_API_TOKEN" == PENDING* ]]; then
  echo "No deploy token in vault yet — run ./bootstrap.sh first." >&2
  exit 1
fi

echo "Deploying ./site to Pages project '$PROJECT'…"
npx --yes wrangler@latest pages deploy site --project-name "$PROJECT" --branch main
echo "Done → https://${PROJECT}.pages.dev"
