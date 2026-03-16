#!/bin/bash
# scripts/smoke_test.sh — Smoke test rapide avant déploiement
BASE="${1:-http://localhost:8000}"

echo "=== Smoke test $BASE ==="

check() {
  local label="$1" url="$2" expected="$3"
  code=$(curl -s -o /dev/null -w "%{http_code}" "$url")
  if [ "$code" = "$expected" ]; then
    echo "  ✓ $label ($code)"
  else
    echo "  ✗ $label — attendu $expected, obtenu $code"
  fi
}

check "health"       "$BASE/health"    200
check "health/db"    "$BASE/health/db" 200
check "landing page" "$BASE/"          200
check "login page"   "$BASE/login"     200
check "signup page"  "$BASE/signup"    200
check "version"      "$BASE/_version"  200

# Routes protégées — doivent retourner 401/403, pas 500
check "articles sans auth"  "$BASE/articles"   401
check "me sans auth"        "$BASE/me"         403

echo "=== Terminé ==="
