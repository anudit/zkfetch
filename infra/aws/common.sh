# Shared setup for up.sh / down.sh. Every AWS resource carries the tag
# project=zkfetch-notary, which is how down.sh finds what to delete.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
STATE="$ROOT/.zkf/aws"
REGION=ap-south-1
NAME=zkfetch-notary
TAG="Key=project,Value=$NAME"
FILTER="Name=tag:project,Values=$NAME"

# Credentials: AWS_ACCESS_KEY / AWS_SECRET_KEY from the repo .env, unless the
# standard AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY are already set.
if [[ -z "${AWS_ACCESS_KEY_ID:-}" && -f "$ROOT/.env" ]]; then
  AWS_ACCESS_KEY_ID=$(sed -n 's/^AWS_ACCESS_KEY=//p' "$ROOT/.env" | tr -d "\"' \r")
  AWS_SECRET_ACCESS_KEY=$(sed -n 's/^AWS_SECRET_KEY=//p' "$ROOT/.env" | tr -d "\"' \r")
fi
[[ -n "${AWS_ACCESS_KEY_ID:-}" && -n "${AWS_SECRET_ACCESS_KEY:-}" ]] || {
  echo "Set AWS_ACCESS_KEY and AWS_SECRET_KEY in $ROOT/.env" >&2; exit 1; }
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
export AWS_DEFAULT_REGION=$REGION AWS_REGION=$REGION AWS_PAGER=""
unset AWS_PROFILE AWS_SESSION_TOKEN

# Prefer the native Homebrew CLI (an old Intel build may sit in /usr/local/bin).
AWS_BIN=$( [[ -x /opt/homebrew/bin/aws ]] && echo /opt/homebrew/bin/aws || command -v aws )
aws() { "$AWS_BIN" "$@"; }

log() { printf '\033[1m==>\033[0m %s\n' "$*"; }
