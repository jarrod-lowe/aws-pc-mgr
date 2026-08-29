#!/bin/sh
# audit.sh — scan the repository for secrets and user/machine-identifying
# values (SPEC §27, Plan T7).
#
# Usage:
#   scripts/audit.sh              audit repo; exit 1 on any finding, 0 if clean
#   scripts/audit.sh --selftest   run the same detection engine over the
#                                 synthetic fixtures in tests/fixtures/audit/;
#                                 exit 0 iff every fixture class is detected
#                                 as expected, including the two marker
#                                 fixtures: synthetic values carrying the
#                                 suppression marker stay silent, and an
#                                 AKIA key shape carrying the marker is still
#                                 detected (hard rule below)
#
# What the default audit scans:
#   * tracked files (git ls-files) — text files directly, UTF-16 files
#     (BOM or NUL-interleaved bytes, e.g. Windows PowerShell `>` redirection
#     output) decoded to UTF-8 and scanned in decoded form — by every
#     detector AND by the runtime-value literal scans below, so a UTF-16
#     file is not a blind spot for the bucket/username/hostname checks, and
#   * every commit, all refs: commit message body plus patch. The message
#     body is scanned for EVERY commit independently of the patch: the patch
#     stream is path-filtered (audit script and fixtures excluded), and a
#     commit whose changed paths are all excluded — including an empty
#     commit — makes `git show --patch -- <paths>` emit nothing at all,
#     message included. Message bodies therefore get their own unfiltered
#     `git show -s --format=%B` pass.
#   * the values `whoami` and `hostname` return locally (tracked files and
#     history — both the message-body and the patch stream),
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
# SUPPRESSION MARKER `# audit-allow:synthetic`:
#   A line carrying the marker comment `# audit-allow:synthetic` — normally
#   as a trailing comment on the very line that holds the value — is skipped
#   by every suppressible detector, in BOTH file mode and history mode.
#   History mode checks the raw patch line, so a `+value # audit-allow:
#   synthetic` line produced by `git log -p`/`git show` is skipped the same
#   way. The marker exists ONLY for two kinds of known-safe line:
#   * SYNTHETIC test/doc values: invented fixture literals such as
#     `mi-0123456789abcdef0` registration JSON or example UUIDs in comment
#     help.
#   * LABEL-SHAPE COLLISIONS in code: the label detectors are deliberately
#     broad (over-detection is the safe direction — a PowerShell line
#     `$activationCode = '<real code>'` is exactly what a leak looks like),
#     so an ordinary assignment whose matched "value" is itself code — a
#     function invocation or identifier, not a credential literal, e.g.
#     `$activationCode = Read-ActivationCode` in scripts/windows/setup.ps1
#     — matches too. Such a line carries the marker rather than narrowing
#     the detector and re-opening a miss.
#   SPEC §27 is otherwise unchanged:
#   runtime-discovered values (real activation IDs/codes, keys, account,
#   bucket, machine or person identifiers) must never be committed, and the
#   marker does not make committing one acceptable.
#
#   HARD RULE (no exception, by construction): the marker NEVER suppresses
#   real AWS key material. A line matching an AKIA…/ASIA… access or session
#   key ID, or a secret-key assignment in any spelling — in ANY CASE VARIANT
#   (lowercase HCL `aws_secret_access_key = …`, uppercase env
#   `AWS_SECRET_ACCESS_KEY=…`, camelCase `SecretAccessKey=…`, JSON
#   `"SecretAccessKey": "…"`, spaced `Secret Access Key = …`) and any
#   separator spelling, because the label detectors match a lowercased copy
#   of each line — is ALWAYS a finding, even when the marker is present on
#   that line. These detector classes
#   (aws-access-key-id, aws-session-key-id, aws-secret-access-key) cannot
#   be silenced by any marker. The runtime per-machine value checks
#   (state-bucket-name, username, hostname) are likewise never
#   suppressible: those values are real by definition, never synthetic.
#   The aws-activation-code class is deliberately OUTSIDE that hard rule:
#   synthetic activation-code literals occur in tests and documentation,
#   and the marker exists precisely to exempt them, while a real
#   activation code in a labeled assignment (no marker) is a finding.
#   The aws-session-token class is outside the hard rule too, but its
#   16-plus value anchor already keeps every known synthetic spelling
#   (`Session Token: EXAMPLE`, 7 characters) far below it, so no line in
#   this repository needs a marker to stay silent.
#
#   History equivalence: commits made before the marker existed cannot
#   carry it, and this repository does not rewrite history. A history
#   finding is therefore also skipped when the byte-identical line (git
#   diff +/-/space prefix and trailing whitespace ignored) exists in the
#   current tracked tree carrying the marker — the same synthetic line,
#   annotated today, also covers its already-committed copies. Only
#   suppressible classes receive this treatment; the hard-rule classes
#   above never do.
#
# Binary content fails CLOSED — it is never silently skipped. A tracked file
# with binary content that is not decodable UTF-16 (or when iconv is
# unavailable), and any commit whose patch carries git's `Binary files ...
# differ` marker (content not shown, so not content-scanned), each produce an
# explicit `unscannable-binary-content` finding: decode the file, commit
# text, or verify manually. The audit does not pass over content it could
# not scan. (No binary files are tracked in this repository, so a clean
# audit contains no such finding.)
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
# Fixtures (paths relative to the repository root) that must produce NO
# findings: synthetic values carrying the suppression marker. Everything
# else under $FIXTURE_DIR must produce at least one finding — including
# marker-ignored-akia.txt, whose AKIA key shape must survive the marker
# (hard rule, see header).
SILENT_FIXTURES='tests/fixtures/audit/synthetic-suppressed.txt'
GENERIC_USERS=' root admin administrator user users runner ubuntu ci build builder jenkins github actions deploy deployer test tests vagrant ec2-user staff daemon nobody operator '

# ---------------------------------------------------------------------------
# Detection engine (used by both the default audit and --selftest)
# ---------------------------------------------------------------------------

# Detectors come in TWO classes, split so that case and separator handling
# is a property of the engine rather than of hand-enumerated spellings (a
# detector that lists `SecretAccessKey` will always be missing the next
# variant someone types; matching a lowercased line cannot be):
#
#   * LABEL detectors (LABEL_DETECTORS) anchor on a multi-word credential
#     LABEL. They are matched against a LOWERCASED copy of each line
#     (scan_stream below), so their EREs are written lowercase-only and
#     match every case variant of the label — lowercase, UPPER, camelCase,
#     MiXeD — without enumerating any of them. Between the words of a
#     label, `[[:space:]_-]*` accepts every separator spelling: none
#     (camelCase), `-`, `_`, a space, or any run mixing them, so
#     `activation_code`, `ACTIVATION-CODE`, `Activation Code` and
#     `activationcode` are all the same pattern.
#   * SHAPE detectors (SHAPE_DETECTORS) anchor on the VALUE's shape, whose
#     grammar is case-bearing — AKIA…/ASIA… key IDs are uppercase, UUIDs
#     and managed-node IDs are lowercase hex, SSO start URLs and email
#     addresses carry their own case, and an ARN is lowercase up to its
#     12-digit account field — so they are matched against the ORIGINAL
#     line unchanged; lowercasing the line would destroy exactly the
#     thing they anchor on.
#
# Both lists: one detector per line, `name:ERE`, split on the first colon
# (names never contain a colon). A line is a finding when it matches the
# ERE. QUOTE_CLASS is an optional quote character around a value: after the
# separator it opens the value (secret keys are quoted in HCL and JSON),
# and before the separator it closes a quoted JSON key.
#
# The label detectors keep the assignment+value anchors that make prose
# safe: the label must be split from its value by `=` or `:` (with optional
# quotes and whitespace on either side) and the value is length-anchored —
# 35-45 base64-ish chars for a secret key, 8-plus for an activation code,
# 16-plus for a session token — so a sentence, comment, or output-block key
# merely CONTAINING the label words never matches, while short synthetic
# literals such as `SecretAccessKey=EXAMPLE` or `Session Token: EXAMPLE`
# in the Windows-tier tests cannot false-positive. The aws- prefix on the
# secret-key and session-token labels stays optional, so a bare
# `SecretAccessKey:` (the SSM agent log spelling) and a bare
# `SessionToken:` match too.
QUOTE_CLASS="[\"']?"
LABEL_DETECTORS="aws-secret-access-key:(aws[[:space:]_-]*)?secret[[:space:]_-]*access[[:space:]_-]*key[[:space:]]*${QUOTE_CLASS}[[:space:]]*[=:][[:space:]]*${QUOTE_CLASS}[A-Za-z0-9/+=]{35,45}
aws-activation-code:activation[[:space:]_-]*code[[:space:]]*${QUOTE_CLASS}[[:space:]]*[=:][[:space:]]*${QUOTE_CLASS}[A-Za-z0-9/+_-]{8,}
aws-session-token:(aws[[:space:]_-]*)?session[[:space:]_-]*token[[:space:]]*${QUOTE_CLASS}[[:space:]]*[=:][[:space:]]*${QUOTE_CLASS}[A-Za-z0-9/+_=]{16,}"
SHAPE_DETECTORS="aws-access-key-id:AKIA[0-9A-Z]{16}
aws-session-key-id:ASIA[0-9A-Z]{16}
managed-node-id:mi-[a-f0-9]{8,}
uuid-literal:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}
sso-start-url:https://[A-Za-z0-9-][A-Za-z0-9.-]*[.]awsapps[.]com/start
email-address:[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+[.][A-Za-z]{2,}
account-id-arn:arn:aws[a-z-]*:[a-z0-9-]*(:[a-z0-9-]*)?:[0-9]{12}"

# Suppression marker (see header): a raw line containing this string is
# skipped by every suppressible detector, in file mode and in history mode.
MARKER='# audit-allow:synthetic'

# Detector classes the marker can NEVER silence (see header):
#   * the three AWS key-material classes — hard rule, no exception;
#   * the runtime per-machine value classes — real values, never synthetic.
NEVER_SUPPRESSED=' aws-access-key-id aws-session-key-id aws-secret-access-key state-bucket-name username hostname '

# ANNOTATED_LINES, when non-empty, names a file holding the content of every
# current tracked line that carries the marker (marker and trailing
# whitespace stripped). History findings on byte-identical lines are
# suppressed against it (history equivalence, see header). It is filled by
# scan_history and removed when the history scan completes.
ANNOTATED_LINES=

# Compound detector: a 12-digit AWS account ID on a line that also names an
# account variable (a bare 12-digit number alone is too generic to flag;
# an account ID inside an ARN is the account-id-arn SHAPE detector's job —
# any service, region field empty as in iam:: or populated as in
# ssm:us-east-1: — not this one's).
ACCOUNT_ID_ERE='[0-9]{12}'
ACCOUNT_CONTEXT_ERE='account_id|aws_account|AccountId|AWS_ACCOUNT'

# Allowlisted address stripped from all input before email detection.
ALLOWLIST_SED='s/noreply@anthropic[.]com//g'

# emit_hits NAME LABEL HITS — HITS is grep -n output; first field is a line
# number. Prints one `FINDING` record per surviving hit. Suppression (see
# header): a hit whose raw line carries the marker is skipped for
# suppressible classes; in history mode a hit is additionally skipped when
# the byte-identical line exists in the current tracked tree carrying the
# marker (git diff +/-/space prefix stripped). NEVER_SUPPRESSED classes
# never skip — the marker cannot silence AWS key material or runtime
# per-machine values.
emit_hits() {
    _eh_name=$1
    _eh_label=$2
    _eh_hits=$3
    [ -n "$_eh_hits" ] || return 0
    case "$NEVER_SUPPRESSED" in
    *" $_eh_name "*) _eh_gate=no ;;
    *) _eh_gate=yes ;;
    esac
    case "$_eh_label" in
    'git-history '*) _eh_hist=yes ;;
    *) _eh_hist=no ;;
    esac
    printf '%s\n' "$_eh_hits" |
        while IFS= read -r _eh_hit; do
            [ -n "$_eh_hit" ] || continue
            if [ "$_eh_gate" = yes ]; then
                _eh_line=${_eh_hit#*:}
                case "$_eh_line" in
                *"$MARKER"*) continue ;;
                esac
                if [ "$_eh_hist" = yes ] && [ -n "$ANNOTATED_LINES" ] &&
                    [ -s "$ANNOTATED_LINES" ]; then
                    _eh_body=$_eh_line
                    case "$_eh_line" in
                    '+'* | '-'* | ' '*) _eh_body=${_eh_line#?} ;;
                    esac
                    if printf '%s\n' "$_eh_body" | sed 's/[[:space:]]*$//' |
                        grep -qxF -f "$ANNOTATED_LINES"; then
                        continue
                    fi
                fi
            fi
            printf 'FINDING %s:%s: %s\n' "$_eh_label" "${_eh_hit%%:*}" "$_eh_name"
        done
    return 0
}

# scan_matches NAME LABEL ERE FILE [ERE2 [MODE]] — lines of FILE matching
# ERE (and ERE2 too, when given) are findings. MODE 'lower' (the label
# class) matches a LOWERCASED copy of FILE's lines — grep numbers the copy's
# lines exactly as FILE's — and then restores each hit's line text from
# FILE, so a finding carries (and the suppression machinery in emit_hits
# judges: marker, history equivalence) the ORIGINAL line, never the
# lowercased matching copy; any other MODE (or none) matches FILE unchanged.
# The email detector runs on input with the allowlisted address removed.
scan_matches() {
    _sm_name=$1
    _sm_label=$2
    _sm_ere=$3
    _sm_file=$4
    _sm_ere2=${5-}
    _sm_mode=${6-}
    if [ "$_sm_mode" = 'lower' ]; then
        _sm_hits=$(
            tr '[:upper:]' '[:lower:]' <"$_sm_file" 2>/dev/null |
                grep -nE -- "$_sm_ere" 2>/dev/null |
                awk -v f="$_sm_file" '
                    BEGIN {
                        while ((getline _sm_line < f) > 0) _sm_orig[++_sm_n] = _sm_line
                    }
                    {
                        _sm_no = $0
                        sub(/:.*/, "", _sm_no)
                        print _sm_no ":" _sm_orig[_sm_no]
                    }
                '
        )
    elif [ -n "$_sm_ere2" ]; then
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
# account-id one) over FILE: the label detectors against a lowercased copy
# of FILE's lines (case-insensitive by construction, with the original line
# text restored onto every finding — see scan_matches), the shape detectors
# and the compound account-id detector against FILE unchanged.
scan_stream() {
    _ss_label=$1
    _ss_file=$2
    while IFS= read -r _ss_det; do
        [ -n "$_ss_det" ] || continue
        scan_matches "${_ss_det%%:*}" "$_ss_label" "${_ss_det#*:}" \
            "$_ss_file" '' lower
    done <<EOF
$LABEL_DETECTORS
EOF
    while IFS= read -r _ss_det; do
        [ -n "$_ss_det" ] || continue
        scan_matches "${_ss_det%%:*}" "$_ss_label" "${_ss_det#*:}" "$_ss_file"
    done <<EOF
$SHAPE_DETECTORS
EOF
    scan_matches account-id-context "$_ss_label" \
        "$ACCOUNT_ID_ERE" "$_ss_file" "$ACCOUNT_CONTEXT_ERE"
    return 0
}

# has_nul_bytes FILE — succeed when FILE contains at least one NUL byte.
# This is grep's own C-locale test for binary input, done explicitly because
# `grep -Iq .` cannot be used as the oracle here: -q exits at the first
# matching line, before any NUL further into the file is seen, so a UTF-16
# file whose BOM bytes already match `.` is reported as text — and its
# NUL-interleaved content then matches no (ASCII-shaped) detector, a silent
# pass. od prints exactly two lowercase hex digits per byte, space-separated
# with a leading space per line, so ' 00' matches a NUL byte and nothing
# else.
has_nul_bytes() {
    od -An -v -t x1 -- "$1" 2>/dev/null | grep -q ' 00'
    return $?
}

# effective_scan_path FILE [LABEL] — decide ONCE per file which path holds
# the content the detectors must grep, and set EFFECTIVE_PATH to it: FILE
# itself when FILE is plain text, or a fresh temp file holding the UTF-8
# decode when FILE is binary-looking and decodable UTF-16. LABEL, defaulting
# to FILE, names FILE in findings. Binary-looking means NUL bytes or `grep
# -I` calling it binary. The encoding is chosen from the first two bytes
# (BOM, or a NUL interleaved with ASCII says the byte order) and the
# head-derived guess is tried BEFORE the BOM-less default, because
# `iconv -f UTF-16` on BOM-less input assumes an endianness and happily
# decodes the wrong one into garbage. EFFECTIVE_PATH is empty when FILE is
# empty (nothing to scan) or binary and not decodable — including when
# iconv is unavailable — and the undecodable case fails closed with an
# explicit finding instead of a silent pass (see header). A caller that
# scans EFFECTIVE_PATH must afterwards drop_scan_temp EFFECTIVE_PATH FILE:
# only a decoded temp is removed, never the tracked file itself.
effective_scan_path() {
    _es_path=$1
    _es_label=${2-$_es_path}
    EFFECTIVE_PATH=
    [ -s "$_es_path" ] || return 0
    if ! has_nul_bytes "$_es_path" && grep -Iq . "$_es_path" 2>/dev/null; then
        EFFECTIVE_PATH=$_es_path
        return 0
    fi
    _es_head=$(od -An -N2 -t x1 -- "$_es_path" 2>/dev/null | tr -d ' \n')
    _es_encs=
    case "$_es_head" in
    fffe) _es_encs='UTF-16 UTF-16LE' ;;
    feff) _es_encs='UTF-16 UTF-16BE' ;;
    00*) _es_encs='UTF-16BE UTF-16' ;;
    ??00) _es_encs='UTF-16LE UTF-16' ;;
    esac
    if [ -n "$_es_encs" ] && command -v iconv >/dev/null 2>&1; then
        _es_tmp=$(mktemp "${TMPDIR:-/tmp}/audit-utf16.XXXXXXXX") || _es_tmp=
        if [ -n "$_es_tmp" ]; then
            for _es_enc in $_es_encs; do
                if iconv -f "$_es_enc" -t UTF-8 -- "$_es_path" \
                    >"$_es_tmp" 2>/dev/null; then
                    EFFECTIVE_PATH=$_es_tmp
                    return 0
                fi
            done
            rm -f "$_es_tmp"
        fi
    fi
    printf 'FINDING %s: unscannable-binary-content (file skipped by detectors — decode, commit text, or verify manually)\n' \
        "$_es_label"
    return 0
}

# drop_scan_temp SCAN_PATH FILE_PATH — remove SCAN_PATH when it is a decoded
# temp, i.e. when it differs from FILE_PATH, the tracked file itself (never
# touched). Called after the last scan of that content, so a decoded temp
# never outlives its file's iteration.
drop_scan_temp() {
    [ "$1" = "$2" ] || rm -f -- "$1"
    return 0
}

# scan_file PATH [LABEL] — scan one tracked file. PATH is the file to open
# (absolute, or relative to the caller's cwd); LABEL, defaulting to PATH, is
# the repo-relative name reported in findings and checked against the
# exclusions below. Keeping them apart lets the default audit open files via
# $ROOT/<path> from any cwd while findings still name repo-relative paths.
# Skips the audit script itself and the fixtures (also excluded at the
# git-pathspec level; kept here so direct callers cannot bypass the
# exclusion), and skips empty files. Binary-looking content (NUL bytes, a
# UTF-16 BOM, or `grep -I` reporting binary) is handled fail-closed by
# effective_scan_path: decoded and scanned when it is UTF-16, otherwise an
# explicit unscannable-binary-content finding. PATH may itself be the path
# effective_scan_path already produced for the file — its decoded temp —
# which is plain text, so the decision re-runs as a no-op and no second
# temp is created.
scan_file() {
    _sf_path=$1
    _sf_label=${2-$_sf_path}
    case "$_sf_label" in
    scripts/audit.sh | tests/fixtures/audit | tests/fixtures/audit/*) return 0 ;;
    esac
    effective_scan_path "$_sf_path" "$_sf_label"
    [ -n "$EFFECTIVE_PATH" ] || return 0
    scan_stream "$_sf_label" "$EFFECTIVE_PATH"
    drop_scan_temp "$EFFECTIVE_PATH" "$_sf_path"
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

# annotated_current_lines FILE — fill FILE with the content of every line in
# the current tracked tree that carries the suppression marker, with the
# marker and trailing whitespace removed. One entry per annotated line; used
# for the history-equivalence rule (see header).
annotated_current_lines() {
    _acl_file=$1
    tracked_files |
        while IFS= read -r _acl_f; do
            [ -n "$_acl_f" ] || continue
            [ -f "$ROOT/$_acl_f" ] || continue
            grep -hF -- "$MARKER" "$ROOT/$_acl_f" 2>/dev/null
        done |
        sed -e 's/[[:space:]]*'"$MARKER"'[[:space:]]*$//' \
            -e 's/[[:space:]]*$//' |
        grep -v '^$' >"$_acl_file" 2>/dev/null
    return 0
}

# scan_history BUCKET USER HOST HOST_SHORT — scan every commit's message
# body and patch (all refs), excluding the audit script and fixtures from
# the patches. Message bodies are scanned separately from the patches: a
# pathspec-filtered `git show --patch` emits NOTHING — message included —
# for a commit whose changed paths are all excluded (or an empty commit),
# so a credential in such a message would otherwise go unscanned. Binary
# content in a patch appears only as a `Binary files ... differ` marker and
# is therefore not content-scanned: that fails closed with an explicit
# finding. The runtime values (bucket name, username, hostname including
# its short form) are scanned against BOTH streams, with the same
# scan_literal calls the tracked-file loop makes — same needles, hostname
# case-insensitive as there — so a value that only ever reached history
# (a file later removed, a commit message naming the machine) is still a
# finding. The values arrive already carrying default_audit's guards
# (generic-user skip, short-hostname minimum), the same guarded forms the
# tracked-file loop scans.
scan_history() {
    _sh_bucket=${1-}
    _sh_user=${2-}
    _sh_host=${3-}
    _sh_host_short=${4-}
    # Temp allocation failures fail CLOSED: returning success here would let
    # default_audit report "clean (tracked files and full history scanned)"
    # without having scanned any history (unwritable TMPDIR, full disk).
    _sh_tmp=$(mktemp "${TMPDIR:-/tmp}/audit-history.XXXXXXXX") || {
        printf '%s: error: cannot create history temp file (TMPDIR writable? disk full?) - failing closed\n' "$SCRIPT_NAME" >&2
        exit 1
    }
    _sh_msg=$(mktemp "${TMPDIR:-/tmp}/audit-history-msg.XXXXXXXX") || {
        rm -f "$_sh_tmp"
        printf '%s: error: cannot create history message temp file - failing closed\n' "$SCRIPT_NAME" >&2
        exit 1
    }
    _sh_revs=$(mktemp "${TMPDIR:-/tmp}/audit-history-revs.XXXXXXXX") || {
        rm -f "$_sh_tmp" "$_sh_msg"
        printf '%s: error: cannot create history rev-list temp file - failing closed\n' "$SCRIPT_NAME" >&2
        exit 1
    }
    # History-equivalence set: current tracked lines carrying the marker.
    ANNOTATED_LINES=$(mktemp "${TMPDIR:-/tmp}/audit-annotated.XXXXXXXX") || {
        rm -f "$_sh_tmp" "$_sh_msg" "$_sh_revs"
        printf '%s: error: cannot create annotated-lines temp file - failing closed\n' "$SCRIPT_NAME" >&2
        exit 1
    }
    annotated_current_lines "$ANNOTATED_LINES"
    # The commit list is produced BEFORE the scan loop and its failure is
    # fatal, in the mktemp style above: piping a failing `git rev-list`
    # straight into the loop would leave it iterating over ZERO commits
    # while default_audit still reports "full history scanned" — a false
    # clean (corrupt or unreadable history, a failing git).
    if ! git -C "$ROOT" rev-list --abbrev-commit --all >"$_sh_revs"; then
        rm -f "$_sh_tmp" "$_sh_msg" "$_sh_revs" "$ANNOTATED_LINES"
        ANNOTATED_LINES=
        printf '%s: error: git rev-list failed (corrupt or unreadable history?) - failing closed, no clean result\n' "$SCRIPT_NAME" >&2
        exit 1
    fi
    while IFS= read -r _sh_sha; do
        [ -n "$_sh_sha" ] || continue
        _sh_label="git-history $_sh_sha"
        # Message body: fetched unfiltered, scanned for its own sake.
        if git -C "$ROOT" show -s --no-color --format=%B "$_sh_sha" \
            >"$_sh_msg" 2>/dev/null && [ -s "$_sh_msg" ]; then
            scan_stream "$_sh_label" "$_sh_msg"
            scan_literal state-bucket-name "$_sh_label" "$_sh_msg" \
                "$_sh_bucket"
            scan_literal username "$_sh_label" "$_sh_msg" "$_sh_user"
            scan_literal hostname "$_sh_label" "$_sh_msg" "$_sh_host" ic
            scan_literal hostname "$_sh_label" "$_sh_msg" \
                "$_sh_host_short" ic
        fi
        # Patch content, with the audit script and fixtures excluded.
        git -C "$ROOT" show --no-color --patch --format= "$_sh_sha" -- \
            ':(exclude)scripts/audit.sh' \
            ':(exclude)tests/fixtures/audit' \
            >"$_sh_tmp" 2>/dev/null || continue
        [ -s "$_sh_tmp" ] || continue
        if grep -Eq '^Binary files .* differ' "$_sh_tmp" 2>/dev/null; then
            printf 'FINDING %s: unscannable-binary-content (binary content changed in history — not content-scanned; verify manually)\n' \
                "$_sh_label"
        fi
        scan_stream "$_sh_label" "$_sh_tmp"
        scan_literal state-bucket-name "$_sh_label" "$_sh_tmp" \
            "$_sh_bucket"
        scan_literal username "$_sh_label" "$_sh_tmp" "$_sh_user"
        scan_literal hostname "$_sh_label" "$_sh_tmp" "$_sh_host" ic
        scan_literal hostname "$_sh_label" "$_sh_tmp" "$_sh_host_short" ic
    done <"$_sh_revs"
    rm -f "$_sh_tmp" "$_sh_msg" "$_sh_revs" "$ANNOTATED_LINES"
    ANNOTATED_LINES=
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

    # 1. Tracked files. Opened via $ROOT/<path> so the audit works from any
    # cwd; findings keep the repo-relative name as their label. The literal
    # scans run over the SAME content the detectors scan: effective_scan_path
    # decides once per file — plain text scans as itself, a UTF-16 file as
    # its decoded form — so a decoded file is not a blind spot for the
    # runtime values either; an undecodable file has already failed closed.
    # _scan snapshots that one decision (scan_file re-runs it as a no-op on
    # the already-effective path) and the decoded temp is dropped after the
    # file's scans, never leaking across iterations.
    tracked_files |
        while IFS= read -r _f; do
            [ -n "$_f" ] || continue
            [ -f "$ROOT/$_f" ] || continue
            effective_scan_path "$ROOT/$_f" "$_f"
            _scan=$EFFECTIVE_PATH
            [ -n "$_scan" ] || continue
            scan_file "$_scan" "$_f"
            scan_literal state-bucket-name "$_f" "$_scan" "$_bucket"
            scan_literal username "$_f" "$_scan" "$_user"
            scan_literal hostname "$_f" "$_scan" "$_host" ic
            scan_literal hostname "$_f" "$_scan" "$_host_short" ic
            drop_scan_temp "$_scan" "$ROOT/$_f"
        done >"$_results"

    # 2. Full history (message bodies and patches). The guarded runtime
    # values pass through so history gets the same literal scans the
    # tracked-file loop above applies.
    scan_history "$_bucket" "$_user" "$_host" "$_host_short" >>"$_results"

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

    # Every detector — both classes — must fire somewhere in the fixture
    # corpus.
    for _name in $(printf '%s\n%s\n' "$LABEL_DETECTORS" "$SHAPE_DETECTORS" |
        sed 's/:.*//') account-id-context; do
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

    # Every fixture file must produce at least one finding, except the
    # fixtures that exist to prove the marker suppresses synthetic values.
    for _fx in $(find "$_dir" -type f | LC_ALL=C sort); do
        _rel="$FIXTURE_DIR/${_fx#"$_dir"/}"
        case " $SILENT_FIXTURES " in
        *" $_rel "*) continue ;;
        esac
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

    # Marker fixtures: synthetic values carrying the marker must produce NO
    # finding (a), and a real AWS key-ID shape carrying the marker must STILL
    # be detected as aws-access-key-id (b) — the hard rule in the header.
    for _rel in $SILENT_FIXTURES; do
        if [ ! -f "$ROOT/$_rel" ]; then
            printf 'selftest: FAIL  %-44s fixture missing\n' "$_rel"
            _status=1
            continue
        fi
        case "$_nl$_found$_nl" in
        *"$_rel:"*)
            printf 'selftest: FAIL  %-44s marker did not suppress\n' "$_rel"
            _status=1
            ;;
        *)
            printf 'selftest: PASS  %-44s suppressed by marker\n' "$_rel"
            ;;
        esac
    done

    _rel="$FIXTURE_DIR/marker-ignored-akia.txt"
    if [ ! -f "$ROOT/$_rel" ]; then
        printf 'selftest: FAIL  %-44s fixture missing\n' "$_rel"
        _status=1
    elif printf '%s\n' "$_found" |
        grep -q "^FINDING $_rel:[0-9]*: aws-access-key-id\$"; then
        printf 'selftest: PASS  %-44s AKIA still detected with marker\n' "$_rel"
    else
        printf 'selftest: FAIL  %-44s AKIA not detected with marker\n' "$_rel"
        _status=1
    fi

    if [ "$_status" -eq 0 ]; then
        printf 'selftest: all classes detected (or suppressed) as expected\n'
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
