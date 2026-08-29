#!/bin/sh
# audit.sh — scan the repository for secrets and user/machine-identifying
# values (SPEC §27, Plan T7).
#
# Usage:
#   scripts/audit.sh              audit repo; exit 1 on any finding, 0 if clean
#   scripts/audit.sh --selftest   run the same detection engine over the
#                                 synthetic fixtures in tests/fixtures/audit/;
#                                 exit 0 iff every fixture class is detected
#
# What the default audit scans:
#   * tracked text files (git ls-files), and
#   * every commit, all refs: commit message body plus patch (git show),
#   * the values `whoami` and `hostname` return locally (tracked files only),
#   * the bucket_name from the local untracked terraform/bootstrap/
#     terraform.tfvars, if that file exists (tracked files and history).
#
# Exclusions (deliberate, see SPEC §27's synthetic-fixture design):
#   * tests/fixtures/audit/ — synthetic fixtures that trip every detector by
#     construction; excluded from both worktree and history scanning.
#   * scripts/audit.sh — this file itself. It necessarily contains the
#     detector patterns (and their text is itself a pattern-shaped string),
#     so it is excluded entirely: both from tracked-file scanning and from
#     history scanning. Every other file in the repository is scanned.
#
# KNOWN-SAFE ALLOWLIST: the string noreply@anthropic.com appears in this
# repository's commit-trailer footers (Co-Authored-By) and is not a person's
# address. It is stripped from every line before the email detector runs and
# therefore never counts as a finding.
#
# Git's own Author:/Committer: metadata lines are not scanned: every commit
# carries the committing identity's email as git metadata, which is not
# content under audit (and cannot be scrubbed here). Commit message bodies
# ARE scanned; the allowlist above keeps the standard trailer out of the
# findings.
#
# The whoami check skips a small set of generic usernames (root, runner, …):
# CI runners execute as users whose names are ordinary words appearing in
# this repository's own prose (e.g. "Terraform runner" in SPEC.md) and carry
# no identifying information.
#
# The SSO start-URL detector requires a host label before awsapps.com
# (`https://d-xxxxxxxxx.awsapps.com/start`). Real AWS IAM Identity Center
# start URLs always have one, while the plan text in SPEC.md that merely
# describes this pattern (`https://…awsapps.com/start`, Unicode ellipsis)
# does not, so the specification's self-reference is not a finding.
#
# Limitation: file paths containing newline characters are not supported.

LC_ALL=C
export LC_ALL

SCRIPT_NAME=audit.sh

SELF_DIR=$(dirname -- "$0")
ROOT=$(CDPATH=; cd -- "$SELF_DIR/.." && pwd) || {
    printf '%s: error: cannot locate repository root\n' "$SCRIPT_NAME" >&2
    exit 2
}

FIXTURE_DIR=tests/fixtures/audit
GENERIC_USERS=' root admin administrator user users runner ubuntu ci build builder jenkins github actions deploy deployer test tests vagrant ec2-user staff daemon nobody operator '

# ---------------------------------------------------------------------------
# Detection engine (used by both the default audit and --selftest)
# ---------------------------------------------------------------------------

# Detectors: one per line, `name:ERE`, split on the first colon (names never
# contain a colon). A line is a finding when it matches the ERE.
# Optional quote character before a value (secret keys are quoted in HCL).
QUOTE_CLASS="[\"']?"
DETECTORS="aws-access-key-id:AKIA[0-9A-Z]{16}
aws-session-key-id:ASIA[0-9A-Z]{16}
aws-secret-access-key:aws_secret_access_key[[:space:]]*=[[:space:]]*${QUOTE_CLASS}[A-Za-z0-9/+=]{35,45}
managed-node-id:mi-[a-f0-9]{8,}
uuid-literal:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}
sso-start-url:https://[A-Za-z0-9-][A-Za-z0-9.-]*[.]awsapps[.]com/start
email-address:[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+[.][A-Za-z]{2,}
account-id-arn:arn:aws[a-z-]*:iam::[0-9]{12}"

# Compound detector: a 12-digit AWS account ID on a line that also names an
# account variable (a bare 12-digit number alone is too generic to flag).
ACCOUNT_ID_ERE='[0-9]{12}'
ACCOUNT_CONTEXT_ERE='account_id|aws_account|AccountId|AWS_ACCOUNT'

# Allowlisted address stripped from all input before email detection.
ALLOWLIST_SED='s/noreply@anthropic[.]com//g'

# emit_hits NAME LABEL HITS — HITS is grep -n output; first field is a line
# number. Prints one `FINDING` record per hit.
emit_hits() {
    _eh_name=$1
    _eh_label=$2
    _eh_hits=$3
    [ -n "$_eh_hits" ] || return 0
    printf '%s\n' "$_eh_hits" |
        while IFS= read -r _eh_hit; do
            printf 'FINDING %s:%s: %s\n' "$_eh_label" "${_eh_hit%%:*}" "$_eh_name"
        done
    return 0
}

# scan_matches NAME LABEL ERE FILE [ERE2] — lines of FILE matching ERE (and
# ERE2 too, when given) are findings. The email detector runs on input with
# the allowlisted address removed.
scan_matches() {
    _sm_name=$1
    _sm_label=$2
    _sm_ere=$3
    _sm_file=$4
    _sm_ere2=${5-}
    if [ -n "$_sm_ere2" ]; then
        _sm_hits=$(grep -nE -- "$_sm_ere" "$_sm_file" 2>/dev/null |
            grep -E -- "$_sm_ere2")
    elif [ "$_sm_name" = 'email-address' ]; then
        _sm_hits=$(sed "$ALLOWLIST_SED" "$_sm_file" | grep -nE -- "$_sm_ere")
    else
        _sm_hits=$(grep -nE -- "$_sm_ere" "$_sm_file" 2>/dev/null)
    fi
    emit_hits "$_sm_name" "$_sm_label" "$_sm_hits"
    return 0
}

# scan_literal NAME LABEL FILE NEEDLE [ic] — fixed-string search for runtime
# values (bucket name, username, hostname); `ic` = case-insensitive.
scan_literal() {
    _sl_name=$1
    _sl_label=$2
    _sl_file=$3
    _sl_needle=$4
    _sl_ic=${5-}
    [ -n "$_sl_needle" ] || return 0
    if [ "$_sl_ic" = ic ]; then
        _sl_hits=$(grep -inF -- "$_sl_needle" "$_sl_file" 2>/dev/null)
    else
        _sl_hits=$(grep -nF -- "$_sl_needle" "$_sl_file" 2>/dev/null)
    fi
    emit_hits "$_sl_name" "$_sl_label" "$_sl_hits"
    return 0
}

# scan_stream LABEL FILE — run every detector (including the compound
# account-id one) over FILE.
scan_stream() {
    _ss_label=$1
    _ss_file=$2
    while IFS= read -r _ss_det; do
        [ -n "$_ss_det" ] || continue
        scan_matches "${_ss_det%%:*}" "$_ss_label" "${_ss_det#*:}" "$_ss_file"
    done <<EOF
$DETECTORS
EOF
    scan_matches account-id-context "$_ss_label" \
        "$ACCOUNT_ID_ERE" "$_ss_file" "$ACCOUNT_CONTEXT_ERE"
    return 0
}

# scan_file PATH — scan one tracked file (label = path). Skips the audit
# script itself and the fixtures (also excluded at the git-pathspec level;
# kept here so direct callers cannot bypass the exclusion), and skips
# binary/empty files.
scan_file() {
    _sf_path=$1
    case "$_sf_path" in
    scripts/audit.sh | tests/fixtures/audit | tests/fixtures/audit/*) return 0 ;;
    esac
    grep -Iq . "$_sf_path" 2>/dev/null || return 0
    scan_stream "$_sf_path" "$_sf_path"
    return 0
}

# tracked_files — newline-separated tracked files, excluding the audit script
# and the fixtures. (Paths containing newlines are not supported.)
tracked_files() {
    git -C "$ROOT" ls-files -z -- \
        ':(exclude)scripts/audit.sh' \
        ':(exclude)tests/fixtures/audit' |
        tr '\0' '\n'
}

# scan_history BUCKET — scan every commit's message body and patch (all
# refs), excluding the audit script and fixtures from the patches.
scan_history() {
    _sh_bucket=${1-}
    _sh_tmp=$(mktemp "${TMPDIR:-/tmp}/audit-history.XXXXXXXX") || return 0
    git -C "$ROOT" rev-list --abbrev-commit --all |
        while IFS= read -r _sh_sha; do
            [ -n "$_sh_sha" ] || continue
            git -C "$ROOT" show --no-color --patch --format=%B "$_sh_sha" -- \
                ':(exclude)scripts/audit.sh' \
                ':(exclude)tests/fixtures/audit' \
                >"$_sh_tmp" 2>/dev/null || continue
            [ -s "$_sh_tmp" ] || continue
            _sh_label="git-history $_sh_sha"
            scan_stream "$_sh_label" "$_sh_tmp"
            scan_literal state-bucket-name "$_sh_label" "$_sh_tmp" "$_sh_bucket"
        done
    rm -f "$_sh_tmp"
    return 0
}

# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

usage() {
    printf 'usage: scripts/%s [--selftest]\n' "$SCRIPT_NAME" >&2
    exit 2
}

default_audit() {
    git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1 || {
        printf '%s: error: not a git repository: %s\n' "$SCRIPT_NAME" "$ROOT" >&2
        exit 2
    }

    _results=$(mktemp "${TMPDIR:-/tmp}/audit-results.XXXXXXXX") || exit 2

    # Runtime values whose presence in tracked files/history is a finding.
    _bucket=
    if [ -f "$ROOT/terraform/bootstrap/terraform.tfvars" ]; then
        _bucket=$(sed -n 's/^[[:space:]]*bucket_name[[:space:]]*=[[:space:]]*"\([^"]*\)".*$/\1/p' \
            "$ROOT/terraform/bootstrap/terraform.tfvars" | head -n 1)
    fi

    _user=$(whoami 2>/dev/null) || _user=
    _host=$(hostname 2>/dev/null) || _host=
    _host_short=${_host%%.*}

    case "$GENERIC_USERS" in
    *" $_user "*)
        printf 'audit: note: skipping username check for generic CI/user name "%s"\n' "$_user"
        _user=
        ;;
    esac
    # Hostname: also checked case-insensitively; very short values are noise.
    [ ${#_host} -ge 4 ] 2>/dev/null || _host=
    [ ${#_host_short} -ge 4 ] 2>/dev/null || _host_short=

    # 1. Tracked text files.
    tracked_files |
        while IFS= read -r _f; do
            [ -n "$_f" ] || continue
            [ -f "$ROOT/$_f" ] || continue
            scan_file "$_f"
            scan_literal state-bucket-name "$_f" "$_f" "$_bucket"
            scan_literal username "$_f" "$_f" "$_user"
            scan_literal hostname "$_f" "$_f" "$_host" ic
            scan_literal hostname "$_f" "$_f" "$_host_short" ic
        done >"$_results"

    # 2. Full history (message bodies and patches).
    scan_history "$_bucket" >>"$_results"

    if [ -s "$_results" ]; then
        printf 'audit: FAIL - %s finding(s)\n' "$(grep -c . "$_results")"
        cat "$_results"
        rm -f "$_results"
        exit 1
    fi
    printf 'audit: clean (tracked files and full history scanned)\n'
    rm -f "$_results"
    exit 0
}

selftest() {
    _dir="$ROOT/$FIXTURE_DIR"
    if [ ! -d "$_dir" ]; then
        printf '%s: error: selftest fixture directory missing: %s\n' \
            "$SCRIPT_NAME" "$FIXTURE_DIR" >&2
        exit 2
    fi

    # Same engine as the default audit, applied to the synthetic fixtures.
    _found=$(find "$_dir" -type f |
        LC_ALL=C sort |
        while IFS= read -r _fx; do
            scan_stream "$FIXTURE_DIR/${_fx#"$_dir"/}" "$_fx"
        done)

    _detected=$(printf '%s\n' "$_found" | sed -n 's/^FINDING .*: //p' | LC_ALL=C sort -u)
    _nl='
'
    _status=0

    # Every detector must fire somewhere in the fixture corpus.
    for _name in $(printf '%s\n' "$DETECTORS" | sed 's/:.*//') account-id-context; do
        case "$_nl$_detected$_nl" in
        *"$_nl$_name$_nl"*)
            printf 'selftest: PASS  %-22s detected\n' "$_name"
            ;;
        *)
            printf 'selftest: FAIL  %-22s not detected in %s\n' "$_name" "$FIXTURE_DIR"
            _status=1
            ;;
        esac
    done

    # Every fixture file must produce at least one finding.
    for _fx in $(find "$_dir" -type f | LC_ALL=C sort); do
        _rel="$FIXTURE_DIR/${_fx#"$_dir"/}"
        case "$_nl$_found$_nl" in
        *"$_rel:"*)
            printf 'selftest: PASS  %-44s detected\n' "$_rel"
            ;;
        *)
            printf 'selftest: FAIL  %-44s produced no finding\n' "$_rel"
            _status=1
            ;;
        esac
    done

    if [ "$_status" -eq 0 ]; then
        printf 'selftest: all pattern classes detected\n'
    else
        printf 'selftest: FAIL\n' >&2
    fi
    exit "$_status"
}

case "${1-}" in
'') default_audit ;;
--selftest) selftest ;;
-h | --help)
    printf 'usage: scripts/%s [--selftest]\n' "$SCRIPT_NAME"
    exit 0
    ;;
*)
    printf '%s: error: unknown argument: %s\n' "$SCRIPT_NAME" "$1" >&2
    usage
    ;;
esac
