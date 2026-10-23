#!/bin/bash
#
# remove_emudhra_roots.sh
# Removes the two roots behind the compromised eMudhra intermediates
# (AAA Certificate Services, emSign ECC Root CA - G3) from /etc/ssl/cert.pem,
# the CA file used by /usr/bin/curl, git, python3, perl, ruby and openssl.
# Safari and apps that use Apple's system trust are already covered by Apple.
#
# Usage:  remove_emudhra_roots.sh [apply|check|rollback]
#   apply     (default) back up the file, remove the two roots, verify with curl
#   check     dry run: report what apply would do, change nothing (no root needed)
#   rollback  restore the backup that apply took on this macOS build
#
# First output line: Remediated | Already remediated | Would remediate |
#                    Rolled back | Error: <reason>
# Exit codes: 0 = success, 1 = error
# Works under bash, sh, zsh and dash. Run as root (MDM runs scripts as root).

ACTION="${1:-apply}"   # for MDM without arguments, edit to "check" or "rollback"

CERT="/etc/ssl/cert.pem"
OPENSSL="/usr/bin/openssl"
CURL="/usr/bin/curl"
ROOTS='AAA Certificate Services|emSign ECC Root CA - G3'

# One backup per macOS build: a rollback never restores a file from an older
# macOS over one that a macOS update has since replaced.
BUILD=$(sw_vers -buildVersion 2>/dev/null) || BUILD="unknown"
BACKUP="${CERT}.pre-emudhra.${BUILD}"

# Test with the system CA file, not a per-user override (see check script)
unset CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR

TMP=""
cleanup() { if [ -n "$TMP" ]; then rm -f "$TMP"; fi; }
trap cleanup EXIT

fail() { echo "Error: $*"; exit 1; }

# Subject line of every certificate in a PEM bundle. Also proves it parses.
subjects() {
  "$OPENSSL" crl2pkcs7 -nocrl -certfile "$1" 2>/dev/null |
    "$OPENSSL" pkcs7 -print_certs -noout 2>/dev/null | grep '^subject='
}

# Filter subject lines to (or, with -v, away from) the two roots
roots_only() { grep -E $1 "CN ?= ?(${ROOTS})(\$|[,/])"; }

count() { if [ -n "$1" ]; then printf '%s\n' "$1" | wc -l | tr -d ' '; else echo 0; fi; }

case "$ACTION" in
  apply|check|rollback) ;;
  *) fail "unknown action '$ACTION' (use apply, check or rollback)" ;;
esac
[ "$ACTION" = check ] || [ "$(id -u)" -eq 0 ] || fail "must run as root"
{ [ -f "$CERT" ] && [ ! -L "$CERT" ]; } || fail "$CERT is missing or not a regular file"

# ---------------------------------------------------------------- rollback
if [ "$ACTION" = rollback ]; then
  [ -f "$BACKUP" ] || fail "no backup for this macOS build ($BACKUP), nothing restored"
  TMP=$(mktemp "${CERT}.XXXXXX") || fail "cannot create a temp file in /etc/ssl"
  { cp -p "$BACKUP" "$TMP" && mv -f "$TMP" "$CERT"; } || fail "could not restore $BACKUP"
  TMP=""
  rm -f "$BACKUP"
  echo "Rolled back"
  echo "Restored $CERT from $BACKUP"
  exit 0
fi

# ---------------------------------------------------------- apply / check
before=$(subjects "$CERT")
[ -n "$before" ] || fail "could not read certificates from $CERT"
found=$(printf '%s\n' "$before" | roots_only)
if [ -z "$found" ]; then
  echo "Already remediated"
  echo "Neither root is in $CERT ($(count "$before") certificates)"
  exit 0
fi
names=$(printf '%s\n' "$found" | sed -E 's/.*CN ?= ?//' | sort -u | tr '\n' ',' | sed 's/,$//; s/,/, /g')

# Build the new file in a temp file. For apply it sits next to the original
# (same owner and permissions) so the swap below is a single atomic rename.
if [ "$ACTION" = check ]; then
  TMP=$(mktemp "${TMPDIR:-/tmp}/cert.pem.XXXXXX") || fail "cannot create a temp file"
else
  { TMP=$(mktemp "${CERT}.XXXXXX") && cp -p "$CERT" "$TMP"; } ||
    fail "cannot create a temp file in /etc/ssl"
fi

# Same edit as the incident write-up: drop each cert block whose header is
# one of the two roots.
awk '/^(###|===) /{skip=0}
  /^=== .*\/CN=(AAA Certificate Services|emSign ECC Root CA - G3)$/{skip=1}
  !skip' "$CERT" > "$TMP" || fail "awk failed, $CERT not changed"

# Safety check: the new file must hold exactly the old certificates minus the
# two roots. Anything else (unexpected file layout, a parse error) aborts.
after=$(subjects "$TMP")
expected=$(printf '%s\n' "$before" | roots_only -v)
if [ "$(printf '%s\n' "$after" | sort)" != "$(printf '%s\n' "$expected" | sort)" ]; then
  fail "edited file did not match expectations, $CERT not changed"
fi

if [ "$ACTION" = check ]; then
  echo "Would remediate"
  echo "Would remove: $names"
  echo "Certificates: $(count "$before") -> $(count "$after")"
  exit 0
fi

if [ ! -f "$BACKUP" ]; then
  cp -p "$CERT" "$BACKUP" || fail "could not back up $CERT, not changed"
fi
mv -f "$TMP" "$CERT" || fail "could not replace $CERT, not changed"
TMP=""

# Confirm /usr/bin/curl now rejects the test sites
trusted=""
rejected=0
for host in dv-g3b-emudhra dv-g3b-aaa-emudhra dv-g3b-noct-emudhra dv-g3b-aaa-noct-emudhra; do
  code=$("$CURL" -q -s -o /dev/null -w '%{http_code}' --connect-timeout 10 \
          --max-time 20 "https://${host}.we-have-a-problem.com/" 2>/dev/null)
  rc=$?
  if [ "$rc" -eq 60 ] || [ "$rc" -eq 51 ]; then
    rejected=$((rejected + 1))
  elif [ -n "$code" ] && [ "$code" != "000" ]; then
    trusted="${trusted} ${host}"
  fi
done

if [ -n "$trusted" ]; then
  echo "Error: roots removed but /usr/bin/curl still trusts:${trusted}"
  result=1
elif [ "$rejected" -eq 4 ]; then
  echo "Remediated"
  result=0
else
  echo "Remediated (curl test incomplete: $rejected of 4 test sites reachable)"
  result=0
fi
echo "Removed: $names"
echo "Certificates: $(count "$before") -> $(count "$after")"
echo "Backup: $BACKUP"
exit $result