#!/bin/sh
# tests/tf-init.test.sh — contract test for scripts/tf-init.sh (Task T6).
#
# Plain POSIX sh; runs on macOS /bin/sh and Ubuntu dash. No bats.
#
# Safety: the script under test is only ever invoked with -n (dry run) and a
# fake `terraform` shim is placed first on PATH so that any accidental real
# invocation fails the test loudly. The non-dry-run (exec) path is never
# exercised here.
#
# Usage: sh tests/tf-init.test.sh   (exit 0 iff every assertion passes)

SELF_DIR=$(dirname -- "$0")
REPO_ROOT=$(CDPATH=; cd -- "$SELF_DIR/.." && pwd) || exit 2
SRC_SCRIPT="$REPO_ROOT/scripts/tf-init.sh"
FIXTURE="$REPO_ROOT/tests/fixtures/tfvars/terraform.tfvars"

PASS=0
FAIL=0

pass() {
    PASS=$((PASS + 1))
    printf 'PASS: %s\n' "$1"
}

fail() {
    FAIL=$((FAIL + 1))
    printf 'FAIL: %s\n' "$1"
    if [ $# -ge 3 ]; then
        printf '      expected: %s\n' "$2"
        printf '      actual:   %s\n' "$3"
    fi
    return 0
}

assert_eq() { # desc expected actual
    if [ "$2" = "$3" ]; then
        pass "$1"
    else
        fail "$1" "$2" "$3"
    fi
}

assert_contains() { # desc haystack needle
    case "$2" in
    *"$3"*) pass "$1" ;;
    *) fail "$1" "output containing '$3'" "$2" ;;
    esac
}

assert_nonzero() { # desc status
    if [ "$2" -ne 0 ]; then
        pass "$1"
    else
        fail "$1" 'nonzero exit' 'exit 0'
    fi
}

assert_exit() { # desc expected-status actual-status
    if [ "$2" = "$3" ]; then
        pass "$1"
    else
        fail "$1" "exit $2" "exit $3"
    fi
}

# --- sandbox ----------------------------------------------------------------
# The script derives its repo root from its own location, so copying it into
# a temp tree keeps assertions hermetic (the developer's real untracked
# terraform/bootstrap/terraform.tfvars and any real local tfstate files
# cannot influence results).

if [ ! -f "$SRC_SCRIPT" ]; then
    printf 'FAIL: script under test missing: %s\n' "$SRC_SCRIPT"
    exit 1
fi
if [ ! -f "$FIXTURE" ]; then
    printf 'FAIL: fixture missing: %s\n' "$FIXTURE"
    exit 1
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/tf-init-test.XXXXXXXX") || exit 2
trap 'rm -rf "$WORK"' EXIT
trap 'rm -rf "$WORK"; exit 129' HUP INT TERM

SB="$WORK/sandbox"
mkdir -p "$SB/scripts" \
    "$SB/terraform/bootstrap" \
    "$SB/terraform/infrastructure" ||
    exit 2
cp "$SRC_SCRIPT" "$SB/scripts/tf-init.sh" || exit 2
chmod +x "$SB/scripts/tf-init.sh" || exit 2

# terraform shim: any invocation is a test failure mode we can observe.
mkdir -p "$WORK/bin" || exit 2
cat >"$WORK/bin/terraform" <<'EOF'
#!/bin/sh
echo "TERRAFORM-SHIM-INVOKED: $*" >&2
exit 42
EOF
chmod +x "$WORK/bin/terraform" || exit 2

# --- runner -----------------------------------------------------------------
# Caller sets some of:
#   T_REGION          value for AWS_REGION (unset when empty)
#   T_DEFAULT_REGION  value for AWS_DEFAULT_REGION (unset when empty)
#   T_TFVARS          value for TFVARS_FILE
# Sets OUT (stdout), ERR (stderr), STATUS (exit status).

run_case() {
    OUT=$(
        cd "$SB" || exit 99
        unset AWS_REGION AWS_DEFAULT_REGION
        [ -n "${T_REGION-}" ] && AWS_REGION="$T_REGION" && export AWS_REGION
        [ -n "${T_DEFAULT_REGION-}" ] && AWS_DEFAULT_REGION="$T_DEFAULT_REGION" &&
            export AWS_DEFAULT_REGION
        TFVARS_FILE="${T_TFVARS-}" PATH="$WORK/bin:$PATH" \
            "$SB/scripts/tf-init.sh" "$@"
    ) && STATUS=0 || STATUS=$?
    ERR=$(cat "$WORK/err" 2>/dev/null)
}

# Redirect stderr through a file so run_case can capture both streams.
run() { run_case "$@" 2>"$WORK/err"; }

# --- expected command lines -------------------------------------------------

E_BOOT_AP="terraform -chdir=terraform/bootstrap init -backend-config=bucket=fixture-tfstate-bucket -backend-config=key=bootstrap/terraform.tfstate -backend-config=region=ap-southeast-2 -backend-config=use_lockfile=true"

E_INFRA_AP="terraform -chdir=terraform/infrastructure init -backend-config=bucket=fixture-tfstate-bucket -backend-config=key=infrastructure/terraform.tfstate -backend-config=region=ap-southeast-2 -backend-config=use_lockfile=true"

E_BOOT_EU="terraform -chdir=terraform/bootstrap init -backend-config=bucket=fixture-tfstate-bucket -backend-config=key=bootstrap/terraform.tfstate -backend-config=region=eu-west-1 -backend-config=use_lockfile=true"

# --- cases: dry-run output --------------------------------------------------

T_REGION=ap-southeast-2
T_DEFAULT_REGION=
T_TFVARS="$FIXTURE"
run bootstrap -n
assert_exit 'bootstrap -n exits 0' 0 "$STATUS"
assert_eq 'bootstrap -n prints exact command (no local state, no -migrate-state)' \
    "$E_BOOT_AP" "$OUT"
assert_eq 'bootstrap -n writes nothing to stderr' '' "$ERR"

run infrastructure -n
assert_exit 'infrastructure -n exits 0' 0 "$STATUS"
assert_eq 'infrastructure -n prints exact command (no local state, no -migrate-state)' \
    "$E_INFRA_AP" "$OUT"

# -migrate-state appears only when terraform/<stack>/terraform.tfstate exists.

echo '{}' >"$SB/terraform/bootstrap/terraform.tfstate"
run bootstrap -n
assert_eq 'bootstrap -n appends -migrate-state when local bootstrap state exists' \
    "$E_BOOT_AP -migrate-state" "$OUT"
rm -f "$SB/terraform/bootstrap/terraform.tfstate"

run bootstrap -n
assert_eq 'bootstrap -n omits -migrate-state after local state is gone' \
    "$E_BOOT_AP" "$OUT"

echo '{}' >"$SB/terraform/infrastructure/terraform.tfstate"
run infrastructure -n
assert_eq 'infrastructure -n appends -migrate-state when local infrastructure state exists' \
    "$E_INFRA_AP -migrate-state" "$OUT"
rm -f "$SB/terraform/infrastructure/terraform.tfstate"

# AWS_DEFAULT_REGION fallback and AWS_REGION precedence.

T_REGION=
T_DEFAULT_REGION=eu-west-1
run bootstrap -n
assert_eq 'AWS_DEFAULT_REGION is accepted when AWS_REGION is unset' \
    "$E_BOOT_EU" "$OUT"

T_REGION=ap-southeast-2
T_DEFAULT_REGION=eu-west-1
run bootstrap -n
assert_eq 'AWS_REGION takes precedence over AWS_DEFAULT_REGION' \
    "$E_BOOT_AP" "$OUT"

# --- cases: errors ----------------------------------------------------------

T_REGION=
T_DEFAULT_REGION=
run bootstrap -n
assert_nonzero 'missing AWS_REGION and AWS_DEFAULT_REGION exits nonzero' "$STATUS"
assert_contains 'region error names AWS_REGION' "$ERR" 'AWS_REGION'

T_REGION=ap-southeast-2
T_DEFAULT_REGION=
T_TFVARS="$WORK/does-not-exist.tfvars"
run bootstrap -n
assert_nonzero 'missing TFVARS_FILE exits nonzero' "$STATUS"
assert_contains 'missing tfvars error names the file' "$ERR" 'does-not-exist.tfvars'

printf 'other_value = 1\n' >"$WORK/no-bucket.tfvars"
T_TFVARS="$WORK/no-bucket.tfvars"
run bootstrap -n
assert_nonzero 'tfvars without bucket_name exits nonzero' "$STATUS"
assert_contains 'no-bucket error names bucket_name' "$ERR" 'bucket_name'

# --- cases: usage -----------------------------------------------------------

T_REGION=ap-southeast-2
T_DEFAULT_REGION=
T_TFVARS="$FIXTURE"
run nonsense -n
assert_exit 'unknown stack exits 2' 2 "$STATUS"

run bootstrap --bogus
assert_exit 'unknown option exits 2' 2 "$STATUS"

run
assert_exit 'missing stack argument exits 2' 2 "$STATUS"

# --- summary ----------------------------------------------------------------

printf '%s passed, %s failed\n' "$PASS" "$FAIL"
if [ "$FAIL" -ne 0 ]; then
    exit 1
fi
exit 0
