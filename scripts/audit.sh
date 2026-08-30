#!/bin/sh
# audit.sh — scan the repository for secrets and user/machine-identifying
# values (SPEC §27, Plan T7).
#
# Usage:
#   scripts/audit.sh              audit repo; exit 1 on any finding, 0 if clean
#   scripts/audit.sh --selftest   run the same detection engine over the
#                                 synthetic fixtures in tests/fixtures/audit/
#                                 AND over three generated checks (see the
#                                 harness section above selftest()): a
#                                 generative spelling matrix, per-detector
#                                 value must/must-not tables, and a SPEC §27
#                                 coverage map. Exit 0 iff every fixture class
#                                 is detected as expected, every generated
#                                 variant fires (or stays silent) as expected,
#                                 and the §27 bullet list maps onto the
#                                 detector classes — including the two marker
#                                 fixtures: synthetic values carrying the
#                                 suppression marker stay silent, and an
#                                 AKIA key shape carrying the marker is still
#                                 detected (hard rule below)
#   scripts/audit.sh --scan-file NAME PATH
#                              [INTERNAL TEST HOOK] run the full engine
#                                 (every detector, the emit_hits marker /
#                                 generic-profile gates) over ONE file, with
#                                 the standard exclusions (a NAME naming
#                                 this script or the fixture directory is
#                                 skipped silently), and print the FINDING
#                                 lines. ALWAYS exits 0 — findings do not
#                                 change the status — so an external harness
#                                 can assert on the printed records. This
#                                 exists so test harnesses drive the REAL
#                                 engine instead of sed-extracting a copy of
#                                 it (which breaks whenever the script's
#                                 shape changes); the selftest below uses
#                                 the internal functions directly and keeps
#                                 one CLI smoke test on this mode so the
#                                 hook itself cannot rot. Wrong argument
#                                 count is a usage error (exit 2); a missing
#                                 PATH prints an error and exits 0 with no
#                                 findings (the caller's own count asserts
#                                 then fail, loudly).
#   scripts/audit.sh --message-file FILE
#                              PRE-COMMIT GATE for commit-message text:
#                                 the full engine (label + shape detectors)
#                                 over a proposed message file, findings
#                                 printed, exit 1 on any. The marker and
#                                 history-equivalence suppressions are OFF
#                                 — uncommitted text has no standing
#                                 annotations, so a tripping line must be
#                                 reworded — and the runtime per-machine
#                                 value checks are skipped (they describe
#                                 this machine, not proposed content). The
#                                 default audit scans commit message bodies
#                                 too, but only AFTER the commit exists;
#                                 this mode is how a message is checked
#                                 BEFORE it needs history surgery to fix.
#                                 scripts/hooks/pre-push runs the full
#                                 audit as the last pre-push gate (while
#                                 --amend is still free) and points here
#                                 for messages.
#
# What the default audit scans:
#   * tracked files (git ls-files) — text files directly, UTF-16 files
#     (BOM or NUL-interleaved bytes, e.g. Windows PowerShell `>` redirection
#     output) decoded to UTF-8 and scanned in decoded form — by every
#     detector AND by the runtime-value literal scans below, so a UTF-16
#     file is not a blind spot for the bucket/username/hostname checks, and
#   * every commit, all refs: commit message body, changed-path list and
#     patch. The message body is scanned for EVERY commit independently of
#     the patch: the patch stream is path-filtered (audit script and
#     fixtures excluded), and a commit whose changed paths are all excluded
#     — including an empty commit — makes `git show --patch -- <paths>`
#     emit nothing at all, message included. Message bodies therefore get
#     their own unfiltered `git show -s --format=%B` pass. The
#     changed-path list (same pathspec exclusions, read fail-closed like
#     every other per-commit git call) carries the path-level
#     Terraform-state check into HISTORY: a *.tfstate / *.tfstate.* path
#     touched by any commit is a finding even when the file's content is
#     minimal and even when the file was later deleted from the tree.
#   * the values `whoami` and `hostname` return locally (tracked files and
#     history — both the message-body and the patch stream),
#   * this account's display name — the GECOS/full-name field, via
#     `id -F` (macOS) or `getent passwd` field 5 (Linux) — when the
#     platform exposes one that is name-shaped (two-plus word runs,
#     8-plus characters). Like the username, a real person's name must
#     never be committed; the finding class display-name is never
#     suppressible, and empty/unshaped discoveries are skipped with a
#     note (tracked files and history, case-insensitive),
#   * the bucket_name from the local untracked terraform/bootstrap/
#     terraform.tfvars, if that file exists (tracked files and history),
#   * a path-level Terraform-state check: any TRACKED file matching
#     *.tfstate or *.tfstate.* is an explicit terraform-state-tracked
#     finding (SPEC §27 "Terraform state"), mirroring .gitignore — the
#     check fires on the PATH alone, so even a minimal state file
#     (`{"version":4,...}`) with no detector-tripping content is caught.
#     The history pass carries the same check over every commit's
#     changed-path list (see above). The marker never applies to it — a
#     state file is never synthetic, and the finding is about the path,
#     not a line. History is ALSO covered content-wise: a state file's
#     patch text goes through every detector like any other patch, so
#     its ARNs, account IDs and credentials still fire there.
#   * the value of AWS_PROFILE, when it is set to a specific-enough profile
#     name (tracked files and history, both streams): the SSO/IAM Identity
#     Center profile this machine selects is a committed-content item of
#     SPEC §27 exactly like the username and hostname, and is scanned the
#     same way.
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
# The labeled-identifier detectors (windows-username-labeled,
# hostname-labeled) are SPEC §27's "Windows username" and "hostname" items
# as COMMITTED CONTENT: a labeled identifier on the audited machine
# (`Windows username: alice.smith`, `Windows hostname: ALICE-PC`) is a
# finding even though the runtime whoami/hostname checks only describe
# the machine RUNNING the audit — on the documented Unix Terraform/CI
# runner those runtime values can never be the Windows machine's. The
# username label is the bare two-word `user…name` (the label matches a
# span, so `Windows username` needs no prefix handling of its own; the
# bare `user` is deliberately not a label), the hostname label alternates
# `host…name` and the Windows-UI `computer…name`, and each value anchor is
# a single identifier run of ANY length (one-character profile, account
# and computer names are real; review round 29 removed the 4-plus floors)
# — spaces break the run, which is the prose brake —
# with doc-filler sets (GENERIC_LABELED_USERS / GENERIC_LABELED_HOSTS)
# excluded after the match. A pre-flight walk over the tracked tree and
# full history with maximally loosened anchors found zero label-adjacent
# values, so no tracked line depends on those sets today.
#
# The personal-name detector (personal-name) covers SPEC §27's "personal
# name" item directly: the identifying name-field labels — `personal
# name`, `full name`, `real name` in every case/separator spelling, never
# the bare `name` key of ordinary code — anchored to a two-run name shape
# (each run 3-plus, totalling 8-plus), with a small GENERIC_NAMES
# form-boilerplate set (Not Applicable, John Doe, …) excluded by a gate in
# emit_hits after the match. Very short real names (Jan Li) stay silent —
# a documented miss; over-detection stays the safe direction. The runtime
# display-name check above is the same item's local-value carrier.
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
# The SSO-profile label detector (aws-sso-profile) is prose-safe through its
# VALUE anchor rather than its label: profile names are short arbitrary
# strings, and letter-only ones are real (`AWS_PROFILE=production`), so no
# character-class shape can separate a name from an ordinary word. The value
# run is therefore unconstrained in length — one unbroken run (any length,
# including a single character), whose class
# the `<profile>` placeholder's angle bracket cannot enter — and the
# documentation boilerplate a shape restriction used to keep out is excluded
# by an explicit GENERIC_PROFILES set instead: a hit whose every captured
# value (lowercased) is exactly `default`, `example`, `examples`,
# `placeholder`, `value`, `name`, `profile`, `none` or `test` — words that
# name the SLOT, not a profile anyone selected — is skipped by a
# generic-value gate in emit_hits. The bare `profile` label is deliberately
# NOT matched: Terraform/HCL documentation writes `profile = "…"` as an
# ordinary key, so only the aws-prefixed label (AWS_PROFILE, aws_profile,
# AwsProfile, spaced `AWS PROFILE = …`) is a finding. The runtime
# $AWS_PROFILE guard in default_audit applies the same rule and the same
# set.
#
# The machine-serial-number detector anchors on a PROPERTY, not a
# positional pattern: after the serial label and assignment anchor, the
# value must be a single post-label token of 8-plus characters
# (SERIAL_VALUE), and emit_hits's serial-property gate then requires that
# token to contain BOTH at least one letter and at least one digit. The
# detector ERE deliberately only proves "one 8-plus token after the
# label" — earlier revisions enumerated positional alternatives
# (letters-then-digits, digit-then-letter-plus-tail, ...) and each new
# hardware-serial interleaving (`ABCDEFG1`, `ABC1234Z`) found in review
# was another miss; a property cannot be misspelled. What the property
# keeps out: free text (`serial number: see the underside of the device`
# — no single 8-plus token after the separator at all), pure-digit runs
# (a Terraform state file's `"serial": 123456789` growth counter — a
# digit-only token has no letter), and pure-letter words (`serial:
# rotation` — no digit). A token that carries both, however sparse the
# interleaving (`9mtxaaaaaa`, `ABC-12345`, `1A2B3C4D5E`), is a finding.
# The gate follows the profile gate's empty-capture rule: an empty
# re-anchored capture keeps the finding — over-detection remains the
# safe direction — and only a capture in which NO token holds both a
# letter and a digit is skipped.
#
# The user-home-path shape detector (Windows drive-letter form, macOS
# /Users form, Linux /home form) anchors on the ORIGINAL line: the username
# segment is the identity and its case is part of it. `Users` is matched
# case-insensitively letter-by-letter, like the SSO start URL's host,
# because Windows and default-macOS filesystems are case-insensitive —
# `c:\users\` names the same directory as `C:\Users\` and the identity
# lives in the username segment, not the directory's spelling — while
# `/home` stays literal lowercase: Linux filesystems are case-sensitive and
# that is its only spelling. A left boundary (line start, or any character
# that is not a letter, digit or slash) keeps `https://example.com/home/
# page` — a URL path, not a filesystem path — from tripping. The username
# segment carries no generic-word exclusion: this repository's placeholders
# are angle-bracket (`C:\Users\<username>\.aws\config`), which the segment
# class already cannot match, while excluding the remaining generic words
# in ERE means excluding whole length classes of REAL usernames (`john`,
# `bob`, six-letter given names); over-detection stays the safe direction
# and the suppression marker covers a genuinely synthetic doc path.
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
#   SYNTHETIC-KEY CONVENTION (learned from GitHub push protection, which
#   rejected a push of this repository): server-side secret scanners do
#   not honor this script's path exclusions — any synthetic key material
#   pushed in ANY file is pattern-matched as real. Therefore ALL synthetic
#   key material anywhere in this repository — fixtures, the selftest
#   harness's generator value pools, selftest messages, documentation
#   examples — must be DETERMINISTIC SEQUENTIAL PATTERNS with zero
#   apparent entropy, so no scanner's confidence model can mistake it for
#   a real credential: access-key bodies are alphabet wraps
#   (`AKIAQRSTUVWXYZHIJKLMNOP`) or ascending digits (`0123456789012345`),
#   secret-key bodies are EXAMPLE repetition or an alphabet wrap,
#   session/activation/token values carry a SYNTHETIC… word prefix with
#   sequential padding. Pseudo-random-looking synthetic values (mixed
#   random case and digit runs) are FORBIDDEN, even inside the harness's
#   temp-file generators and even though this script itself is excluded
#   from its own scan: the literals still get pushed. The value pools in
#   MATRIX_LABEL_SETS, st_shape_matrix, st_value_tables, st_hook_smoke and
#   st_message_file are the enforcement points of this rule.
#
#   HARD RULE (no exception, by construction): the marker NEVER suppresses
#   real AWS key material. A line matching an AKIA…/ASIA… access or session
#   key ID, or a secret-key or session-token assignment in any spelling —
#   in ANY CASE VARIANT (lowercase HCL `aws_secret_access_key = …`,
#   uppercase env `AWS_SECRET_ACCESS_KEY=…`, camelCase `SecretAccessKey=…`,
#   JSON `"SecretAccessKey": "…"`, spaced `Secret Access Key = …`) and any
#   separator spelling, because the label detectors match a lowercased copy
#   of each line — is ALWAYS a finding, even when the marker is present on
#   that line. A session-token match therefore always carries a real token:
#   the detector's 16-plus value anchor keeps every known synthetic
#   spelling (`Session Token: EXAMPLE`, 7 characters) from matching at all,
#   so no marker exemption is needed for one. These detector classes
#   (aws-access-key-id, aws-session-key-id, aws-secret-access-key,
#   aws-session-token) cannot be silenced by any marker. The runtime
#   per-machine value checks (state-bucket-name, username, hostname,
#   aws-profile-name) are likewise never suppressible: those values are
#   real by definition, never
#   synthetic. The aws-activation-code class is deliberately OUTSIDE that
#   hard rule: synthetic activation-code literals occur in tests and
#   documentation, and the marker exists precisely to exempt them, while a
#   real activation code in a labeled assignment (no marker) is a finding.
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
# Failed reads fail CLOSED the same way. A `git show` that exits nonzero for
# an individual commit — corrupt object or blob, an I/O error, a failing
# git — is an explicit `unreadable-commit-content` finding naming that
# commit, never a silent skip; only exit 0 with empty output is a legitimate
# skip (an empty commit message, or a commit whose changed paths are all
# excluded). And the enumerations the verdict rests on are fatal when they
# fail: `git rev-list` (the commit list), `git ls-files` (the tracked-file
# list) and every temp allocation abort the audit with an error instead of
# letting it report clean over zero commits or zero files.
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
# marker-ignored-akia.txt and marker-ignored-session-token.txt, whose
# hard-rule credential shapes must survive the marker (see header).
SILENT_FIXTURES='tests/fixtures/audit/synthetic-suppressed.txt'
GENERIC_USERS=' root admin administrator user users runner ubuntu ci build builder jenkins github actions deploy deployer test tests vagrant ec2-user staff daemon nobody operator '
# Generic AWS_PROFILE VALUES (lowercased, space-delimited, matched whole-word
# by the `*" word "*` case idiom GENERIC_USERS uses): documentation
# boilerplate that names the SLOT a profile fills, never a profile anyone
# selected on a machine. Each is justified:
#   default     the AWS CLI's built-in profile; the standard doc line
#   example(s) documentation filler value
#   placeholder self-describing documentation filler
#   value, name generic doc nouns (`aws_profile = name` in a description)
#   profile     self-referential filler (`AWS_PROFILE=profile`)
#   none        documentation/CI "leave unset" spelling
#   test        CI example value
# The aws-sso-profile value anchor is a shape-free run of any length
# (letter-only
# names are real), so emit_hits's generic-value gate excludes these AFTER the
# match, and default_audit's runtime AWS_PROFILE guard skips the same set.
GENERIC_PROFILES=' default example examples placeholder value name profile none test '
# Generic personal-name VALUES (lowercased, matched whole by the same
# `*" word "*` idiom): form boilerplate a name-shaped value can carry
# without naming anyone. The personal-name VALUE anchor is name-shaped by
# design, so emit_hits's generic-name gate excludes these AFTER the match,
# mirroring the profile gate: each justified:
#   not applicable / not provided  the standard empty form-field values
#   unknown / anonymous            self-describing absent data
#   test user / sample user        QA filler
#   first last / john doe / jane doe / your name  documentation examples
GENERIC_NAMES=' not applicable not provided unknown anonymous test user sample user first last john doe jane doe your name '
# Generic LABELED-username values (lowercased, whole-token): prose and doc
# filler that can follow a `username:` label without naming an account.
# Deliberately NOT GENERIC_USERS: root/administrator/ec2-user are REAL
# accounts (especially on Windows) and a labeled occurrence of one is a
# finding, not filler. Each is justified:
#   the, your, this, name, value  ordinary doc words after a colon
#   none, unknown                 self-describing absent data
#   example, placeholder          documentation filler
GENERIC_LABELED_USERS=' the your this name value none unknown example placeholder '
# Generic LABELED-hostname values: doc filler a `hostname:`/`computer
# name:` label can carry without naming a machine: localhost and the
# self-referential hostname/computer/name words, the RFC-2606 example
# domains documentation uses, and `test`.
GENERIC_LABELED_HOSTS=' localhost hostname computer name your the example.com example.invalid test '

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
#     label, LABEL_WORD_SEP (`[[:space:]_.-]*`) accepts every separator
#     spelling: none (camelCase), `-`, `_`, `.`, a space, or any run
#     mixing them, so `activation_code`, `ACTIVATION-CODE`,
#     `Activation Code`, `activation.code` and `activationcode` are all
#     the same pattern. The `.` member was added by the selftest matrix
#     (dotted config keys — Java properties, TOML dotted keys, dotted
#     .env — are a real-world spelling the class originally missed:
#     `aws.account.id=123456789012` used to pass silently). The
#     assignment separator LABEL_ASSIGN (`[=:]` or the Makefile/Go
#     `:=`) was widened by the same matrix: `account_id := 123456789012`
#     in a Makefile used to pass silently too. Both widenings keep the
#     prose safety exactly where it always lived — in the value anchors
#     and the requirement that an assignment separator be present — so
#     a sentence merely containing the label words still never matches.
#   * SHAPE detectors (SHAPE_DETECTORS) anchor on the VALUE's shape, whose
#     grammar is case-bearing — AKIA…/ASIA… key IDs are uppercase, UUIDs
#     and managed-node IDs are lowercase hex, SSO start URLs and email
#     addresses carry their own case, and an ARN's identity is its
#     12-digit account field — so they are matched against the ORIGINAL
#     line unchanged; lowercasing the line would destroy exactly the
#     thing they anchor on. Two detectors still bracket
#     case-insensitive spans inside that original-line match: the SSO
#     start URL's scheme and DNS labels ([hH][tT]…, [aA][wW]…), and the
#     ARN's `arn:aws` prefix through its partition-suffix, service and
#     region spans. Those spans are canonical-lowercase (RFC 3986/1035
#     for URI scheme and hostname, AWS's canonical ARN spelling for the
#     namespace fields), so the identity being detected does not live
#     in their case — a hand-retyped `ARN:AWS:IAM:US-EAST-1:…` is the
#     same ARN — unlike the AKIA/UUID shapes, where the case IS the
#     grammar. The SSO /start path stays literal: paths ARE
#     case-sensitive.
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
# 16-plus for a session token, a 12-digit run for an account ID — so a
# sentence, comment, or output-block key
# merely CONTAINING the label words never matches, while short synthetic
# literals such as `SecretAccessKey=EXAMPLE` or `Session Token: EXAMPLE`
# in the Windows-tier tests cannot false-positive. The aws- prefix on the
# secret-key and session-token labels stays optional, so a bare
# `SecretAccessKey:` (the SSM agent log spelling) and a bare
# `SessionToken:` match too. The session-token detector also takes
# `security` as an alternative first word: temporary credentials ride the
# signed-request header `X-Amz-Security-Token` and the JSON `SecurityToken`
# key as often as the session-token spelling, and since the label matches a
# span inside the lowcased line the `x-amz-` prefix needs no case of its own.
#
# The account-id-context detector is the same machinery with a one-word
# label — `account`, its `id` suffix optional — so snake_case `account_id`,
# camelCase `accountId`, UPPER `ACCOUNT`, the `aws_account` prefix (the
# label matches inside the longer name) and the JSON `"Account"` key an STS
# GetCallerIdentity dump prints are all the one pattern, in every case and
# separator spelling. Its 12-digit value anchor is what keeps prose safe:
# a bare `Account:` label whose value is an account NAME or free text never
# fires — only a label separated (`=`/`:`, optional quotes) from a 12-digit
# run does. It replaces a hand-enumerated, case-sensitive context-word list
# (`account_id|aws_account|AccountId|AWS_ACCOUNT`) matched anywhere on the
# original line — exactly the spelling-enumeration approach this engine
# exists to avoid — and tightens it: the label and the 12-digit value must
# be adjacent on the line, not merely co-occur. A 12-digit account ID
# inside an ARN stays the account-id-arn SHAPE detector's job (any service,
# region field empty as in iam:: or populated as in ssm:us-east-1:), and a
# bare 12-digit number with no account label stays unflagged (too generic).
#
# The SSO-profile and machine-serial detectors are the same label machinery
# with value anchors chosen for values that are SHORT arbitrary strings —
# there, prose safety cannot come from value length alone: a serial value
# is a PROPERTY, not a positional pattern (see the header notes: one
# post-label token of 8-plus carrying both a letter and a digit, enforced
# by the serial-property gate in emit_hits), while a profile value cannot
# be shaped at all (letter-only names are real), so it is only
# length-floored (AWS_PROFILE_VALUE) and the prose safety lives in the
# generic-value gate emit_hits applies to that detector (GENERIC_PROFILES;
# see header). The profile label is aws-prefixed only — bare `profile` is
# a documented HCL key — while the serial label needs no `machine` prefix
# of its own: the label matches a span, so `MachineSerialNumber` is
# covered by `serial…number` inside it.
#
# The user-home-path detector is a SHAPE detector because what it anchors
# on — a username inside a filesystem path — is case-bearing free text with
# no grammar of its own; the path AROUND it supplies the shape (drive
# letter + Users, /Users, /home), and the case of `Users` itself carries no
# identity (case-insensitive filesystems), so only that span is
# letter-bracketed, the same treatment the SSO start URL's scheme and host
# get. `/home` stays literal: on the case-sensitive Linux filesystems that
# use it, that is its only spelling.
# PATH_SEP_CLASS is a backslash or a slash: the two separators a Windows
# path may be written with and the one a Unix path uses. It is
# single-quoted so grep receives TWO backslashes — a lone `\/` inside a
# bracket expression is read as an escaped slash (not a backslash) by some
# grep implementations (BSD grep on macOS), while `\\` is a literal
# backslash under every regcomp.
PATH_SEP_CLASS='[\\/]'
QUOTE_CLASS="[\"']?"
# LABEL_WORD_SEP is the inter-word separator span of every label detector and
# LABEL_ASSIGN its assignment separator; both are shared by every ERE below
# (and by AWS_PROFILE_LABEL, hence by the generic-value gate in emit_hits), so
# the spelling grammar lives in exactly one place and the selftest matrix can
# regenerate its variant cross-product from these definitions' documented
# grammar. See the engine notes above each list for what each class member is
# for; the matrix in the selftest harness asserts the closure.
LABEL_WORD_SEP='[[:space:]_.-]*'
LABEL_ASSIGN='([=:]|:=)'
# AWS_PROFILE_LABEL is the label+separator+quote anchor of the aws-sso-profile
# detector, AWS_PROFILE_VALUE its value anchor. Both are shared between the
# detector ERE in LABEL_DETECTORS and the generic-value gate in emit_hits
# (GENERIC_PROFILES), so the gate always re-anchors EXACTLY the value tokens
# the detector matched and the two can never drift apart. The value anchor is
# deliberately shape-free — one unbroken run of any length, because
# letter-only profile names (`production`) are real — so the prose/placeholder
# safety lives in the gate, not here.
AWS_PROFILE_LABEL="aws${LABEL_WORD_SEP}profile[[:space:]]*${QUOTE_CLASS}[[:space:]]*${LABEL_ASSIGN}[[:space:]]*${QUOTE_CLASS}"
AWS_PROFILE_VALUE='[A-Za-z0-9][A-Za-z0-9._-]*'
# SERIAL_LABEL/SERIAL_VALUE are the machine-serial-number detector's label
# and value anchors, shared between the detector ERE and the serial-property
# gate in emit_hits for the same reason AWS_PROFILE_LABEL/AWS_PROFILE_VALUE
# are shared: the gate re-anchors exactly the tokens the detector matched.
# The value anchor proves only "one 8-plus token after the label" — the
# letter-and-digit property is the gate's job (see header).
SERIAL_LABEL="serial(${LABEL_WORD_SEP}number)?[[:space:]]*${QUOTE_CLASS}[[:space:]]*${LABEL_ASSIGN}[[:space:]]*${QUOTE_CLASS}"
SERIAL_VALUE='[A-Za-z0-9][A-Za-z0-9-]{7,}'
# PERSONAL_NAME_LABEL/PERSONAL_NAME_VALUE are the personal-name detector's
# anchors, shared with the generic-name gate in emit_hits. The label is the
# genuinely identifying name-field family — `personal name`, `full name`,
# `real name` in every case/separator spelling via the shared machinery —
# and deliberately NOT bare `name`, which is an ordinary key everywhere in
# code and HCL. The value anchor is a NAME SHAPE, not a positional pattern:
# two-or-more consecutive word runs of name characters whose combined
# length is at least 8 with each run at least 3 — expressed as the three
# ERE regions (>=5+>=3, >=4+>=4, >=3+>=5). Case cannot carry the shape
# (labels match a lowercased copy), so prose pairs like `the name` (3+4=7)
# and `of the` stay silent while `Alice Smith` (5+5), `Mary Jane Watson`
# (4+4 from the first two runs) and `Jean-Pierre Blanc` fire; very short
# real names (`Jan Li`, 3+2) stay silent — a documented, acceptable miss,
# over-detection being the safe direction and the length rule the only
# prose brake that survives lowercasing. Single tokens (`Smith`), and
# placeholders (`<your name>` — the angle bracket is outside the class)
# cannot match at all.
PERSONAL_NAME_LABEL="(personal|full|real)${LABEL_WORD_SEP}name[[:space:]]*${QUOTE_CLASS}[[:space:]]*${LABEL_ASSIGN}[[:space:]]*${QUOTE_CLASS}"
PERSONAL_NAME_VALUE="([A-Za-z][A-Za-z'.-]{4,}[[:space:]]+[A-Za-z][A-Za-z'.-]{2,}|[A-Za-z][A-Za-z'.-]{3,}[[:space:]]+[A-Za-z][A-Za-z'.-]{3,}|[A-Za-z][A-Za-z'.-]{2,}[[:space:]]+[A-Za-z][A-Za-z'.-]{4,})"
# WINUSER/HOSTNAME labels are the labeled-identifier detectors for SPEC §27's
# "Windows username" and "hostname" bullets (review thread 3888208297: a
# LABELED identifier on the Windows machine is committed content —
# `Windows username: alice.smith`, `Windows hostname: ALICE-PC` — and the
# runtime whoami/hostname checks only describe the machine RUNNING the
# audit, so a Unix CI runner never sees the Windows values). The label
# matches a span, so `Windows username:`/`Win10 hostname:` need no prefix
# handling of their own; the bare two-word forms cover `user_name`,
# `UserName`, `USER-NAME`, `user.name`, `hostname`, `host_name`,
# `ComputerName` in every case and separator spelling. Values are single
# unbroken runs (spaces break the run — the prose brake): usernames carry
# dots/underscores/hyphens (alice.smith), hostnames dots/hyphens
# (ALICE-PC, ci-host.example.internal), of any length. Prose/boilerplate is
# excluded AFTER the match by generic-value gates (eh_all_generic): these
# are deliberately NOT the runtime GENERIC_USERS set — root/administrator
# are REAL Windows accounts and stay findings — but doc-word sets
# (GENERIC_LABELED_USERS / GENERIC_LABELED_HOSTS), justified inline. A
# pre-flight walk (tracked tree + full history, messages and patches, the
# standard exclusions, maximally loosened anchors) found ZERO label-adjacent
# values, so nothing in this repository gates on them; the sets exist for
# future prose. Both classes are marker-suppressible label classes.
# LABEL VOCABULARY TABLE (review round 30, thread 3888296684): the label
# words these two detectors accept, each alternative decided explicitly —
# the third vocabulary addition (security token, computer name, Windows
# user/account) made the dimension a table so every future proposal has a
# landing place. Windows-username class:
#   user…name            INCLUDE  core (UserName, user_name, USER-NAME)
#   windows/win…user     INCLUDE  reviewer's line — the Windows qualifier
#                                  makes the bare noun specific enough
#   windows/win…account  INCLUDE  ditto (`Windows account: bob`)
#   local…user/account   INCLUDE  `net user`/LocalAccount-style tooling
#                                  output; LocalAccount matches via the
#                                  empty separator
#   sam…account(…name)?  INCLUDE  AD/PowerShell `SamAccountName : alice`
#                                  dumps; the optional name suffix is the
#                                  same (sep*word)? shape account-id and
#                                  serial use
#   logon…name           INCLUDE  Windows whoami/audit dump spelling
#                                  (Windows-only word, not a schema column)
#   login…name           EXCLUDE  cross-platform schema/form column
#                                  (login_name) whose values are app-level
#                                  usernames, not machine accounts
#   bare user / account  EXCLUDE  ordinary nouns — code and prose
#                                  everywhere; the qualifier is load-bearing
#   computer account     EXCLUDE  identifies a MACHINE and its value
#                                  carries a trailing `$` outside the value
#                                  class; machine…name (below) carries the
#                                  same identifier
# Hostname class:
#   host…name            INCLUDE  core
#   computer…name        INCLUDE  Windows-UI Computer Name
#   machine…name         INCLUDE  round 30: `Machine Name: ALICE-PC`
#                                  sysinfo-style output
WINUSER_LABEL="((user|logon)${LABEL_WORD_SEP}name|(windows|win|local)${LABEL_WORD_SEP}(user|account)|sam${LABEL_WORD_SEP}account(${LABEL_WORD_SEP}name)?)[[:space:]]*${QUOTE_CLASS}[[:space:]]*${LABEL_ASSIGN}[[:space:]]*${QUOTE_CLASS}"
WINUSER_VALUE='[A-Za-z0-9][A-Za-z0-9._-]*'
HOSTNAME_LABEL="(host|computer|machine)${LABEL_WORD_SEP}name[[:space:]]*${QUOTE_CLASS}[[:space:]]*${LABEL_ASSIGN}[[:space:]]*${QUOTE_CLASS}"
HOSTNAME_VALUE='[A-Za-z0-9][A-Za-z0-9.-]*'
LABEL_DETECTORS="aws-secret-access-key:(aws${LABEL_WORD_SEP})?secret${LABEL_WORD_SEP}access${LABEL_WORD_SEP}key[[:space:]]*${QUOTE_CLASS}[[:space:]]*${LABEL_ASSIGN}[[:space:]]*${QUOTE_CLASS}[A-Za-z0-9/+=]{35,45}
aws-activation-code:activation${LABEL_WORD_SEP}code[[:space:]]*${QUOTE_CLASS}[[:space:]]*${LABEL_ASSIGN}[[:space:]]*${QUOTE_CLASS}[A-Za-z0-9/+_-]{8,}
aws-session-token:(aws${LABEL_WORD_SEP})?(session|security)${LABEL_WORD_SEP}token[[:space:]]*${QUOTE_CLASS}[[:space:]]*${LABEL_ASSIGN}[[:space:]]*${QUOTE_CLASS}[A-Za-z0-9/+_=]{16,}
account-id-context:account(${LABEL_WORD_SEP}id)?[[:space:]]*${QUOTE_CLASS}[[:space:]]*${LABEL_ASSIGN}[[:space:]]*${QUOTE_CLASS}[[:space:]]*[0-9]{12}
aws-sso-profile:${AWS_PROFILE_LABEL}${AWS_PROFILE_VALUE}
machine-serial-number:${SERIAL_LABEL}${SERIAL_VALUE}
personal-name:${PERSONAL_NAME_LABEL}${PERSONAL_NAME_VALUE}
windows-username-labeled:${WINUSER_LABEL}${WINUSER_VALUE}
hostname-labeled:${HOSTNAME_LABEL}${HOSTNAME_VALUE}"
SHAPE_DETECTORS="aws-access-key-id:AKIA[0-9A-Z]{16}
aws-session-key-id:ASIA[0-9A-Z]{16}
managed-node-id:mi-[a-f0-9]{8,}
uuid-literal:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}
sso-start-url:[hH][tT][tT][pP][sS]://[A-Za-z0-9-][A-Za-z0-9.-]*[aA][wW][sS][aA][pP][pP][sS][.][cC][oO][mM]/start
email-address:[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+[.][A-Za-z]{2,}
account-id-arn:[aA][rR][nN]:[aA][wW][sS][A-Za-z-]*:[A-Za-z0-9-]*(:[A-Za-z0-9-]*)?:[0-9]{12}
user-home-path:(^|[^A-Za-z0-9/])([A-Za-z]:${PATH_SEP_CLASS}{1,2}|/)[Uu][sS][eE][rR][sS]${PATH_SEP_CLASS}{1,2}[A-Za-z0-9._-]+|(^|[^A-Za-z0-9/])/home/[A-Za-z0-9._-]+"

# Suppression marker (see header): a raw line containing this string is
# skipped by every suppressible detector, in file mode and in history mode.
MARKER='# audit-allow:synthetic'

# Detector classes the marker can NEVER silence (see header):
#   * the four AWS key-material classes — hard rule, no exception;
#   * the runtime per-machine value classes — real values, never synthetic.
# display-name is the runtime GECOS/full-name literal (see default_audit):
# a real person's name on this machine, never synthetic — same rule as the
# other runtime per-machine values.
NEVER_SUPPRESSED=' aws-access-key-id aws-session-key-id aws-secret-access-key aws-session-token state-bucket-name username hostname aws-profile-name display-name '

# ANNOTATED_LINES, when non-empty, names a file holding the content of every
# current tracked line that carries the marker (marker and trailing
# whitespace stripped). History findings on byte-identical lines are
# suppressed against it (history equivalence, see header). It is filled by
# scan_history and removed when the history scan completes.
ANNOTATED_LINES=

# Allowlisted address stripped from all input before email detection.
ALLOWLIST_SED='s/noreply@anthropic[.]com//g'

# eh_all_generic SET ERE TRIM — the post-match generic-value gate shared by
# the set-based label detectors (aws-sso-profile, windows-username-labeled,
# hostname-labeled): re-anchor the hit's ORIGINAL line (lowercased) with the
# detector's own label+value ERE, strip the label through the assignment
# separator plus leading quotes, apply the TRIM sed program to each captured
# value, and return 0 only when EVERY captured value (there is at least one)
# is a member of SET. These detectors' values are single tokens (no spaces),
# so word-split comparison is exact — the personal-name gate compares whole
# multi-word values and keeps its own loop, and the serial gate checks a
# property, not a set. An empty capture returns 1: over-detection stays the
# safe direction.
eh_all_generic() {
    _ag_set=$1
    _ag_ere=$2
    _ag_trim=$3
    _ag_vals=$(printf '%s\n' "${_eh_hit#*:}" |
        tr '[:upper:]' '[:lower:]' |
        grep -oE -- "$_ag_ere" |
        sed -e 's/^[^=:]*:=//' -e 's/^[^=:]*[=:][[:space:]]*//' \
            -e "s/^[\"']*//" -e "$_ag_trim")
    [ -n "$_ag_vals" ] || return 1
    for _ag_val in $_ag_vals; do
        case "$_ag_set" in
        *" $_ag_val "*) ;;
        *) return 1 ;;
        esac
    done
    return 0
}

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
    # MARKER_GATE_OFF (set by --message-file): proposed commit-message text
    # is UNCOMMITTED — it has no standing annotations, so the marker and
    # history-equivalence suppressions are switched off entirely and every
    # detector, suppressible or not, reports. See the header's --message-file
    # notes.
    if [ "${MARKER_GATE_OFF:-}" = yes ]; then
        _eh_gate=no
    else
        case "$NEVER_SUPPRESSED" in
        *" $_eh_name "*) _eh_gate=no ;;
        *) _eh_gate=yes ;;
        esac
    fi
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
            # Generic-value gate (aws-sso-profile): the detector's value
            # anchor is shape-free — letter-only profile names
            # (`production`) are real — so the documentation boilerplate a
            # shape restriction used to keep out is excluded HERE instead,
            # by the shared eh_all_generic helper: every captured value,
            # lowercased and trimmed of leading quotes and trailing
            # dot/underscore/dash (`aws_profile = "default."` is
            # boilerplate, not a finding), must be one of GENERIC_PROFILES
            # or the finding stands. An empty extraction also stands —
            # over-detection stays the safe direction — and the marker and
            # history rules above are untouched. The
            # windows-username-labeled and hostname-labeled gates below
            # share the helper.
            if [ "$_eh_name" = 'aws-sso-profile' ] &&
                eh_all_generic "$GENERIC_PROFILES" \
                    "${AWS_PROFILE_LABEL}${AWS_PROFILE_VALUE}" 's/[._-]*$//'; then
                continue
            fi
            # Serial-property gate (machine-serial-number only), mirroring
            # the generic-value gate's structure: the detector's value
            # anchor deliberately proves only "one 8-plus token after the
            # serial label" (SERIAL_LABEL + SERIAL_VALUE), because serials
            # have no positional grammar — every positional pattern so far
            # (letters-then-digits, digit-then-letter, hyphenated) missed
            # the next interleaving someone found in review. The gate
            # re-anchors the original line with the very ERE the detector
            # matched, captures the token(s), and requires at least ONE
            # captured token to contain BOTH a letter and a digit — that
            # is the serial PROPERTY. Pure-digit tokens (a Terraform state
            # file's growth counter) and pure-letter words (`rotation`)
            # have no such token and are skipped; an empty capture keeps
            # the finding (over-detection stays the safe direction); the
            # marker and history rules above are untouched.
            if [ "$_eh_name" = 'machine-serial-number' ]; then
                _eh_vals=$(printf '%s\n' "${_eh_hit#*:}" |
                    tr '[:upper:]' '[:lower:]' |
                    grep -oE -- "${SERIAL_LABEL}${SERIAL_VALUE}" |
                    sed -e 's/^[^=:]*:=//' -e 's/^[^=:]*[=:][[:space:]]*//' \
                        -e "s/^[\"']*//")
                _eh_keep=no
                if [ -z "$_eh_vals" ]; then
                    _eh_keep=yes
                else
                    for _eh_val in $_eh_vals; do
                        case $_eh_val in
                        *[A-Za-z]*)
                            case $_eh_val in
                            *[0-9]*) _eh_keep=yes ;;
                            esac
                            ;;
                        esac
                    done
                fi
                if [ "$_eh_keep" != yes ]; then
                    continue
                fi
            fi
            # Generic-name gate (personal-name only), mirroring the
            # generic-value gate: the value anchor is name-SHAPED, so the
            # form boilerplate a shape restriction cannot distinguish
            # (`Full Name: Not Applicable` in real dumps) is excluded HERE,
            # by exact lowercased match against GENERIC_NAMES, after the
            # match. Any other value stands, an empty capture stands
            # (over-detection stays the safe direction), and the marker and
            # history rules above are untouched.
            if [ "$_eh_name" = 'personal-name' ]; then
                _eh_nvals=$(printf '%s\n' "${_eh_hit#*:}" |
                    tr '[:upper:]' '[:lower:]' |
                    grep -oE -- "${PERSONAL_NAME_LABEL}${PERSONAL_NAME_VALUE}" |
                    sed -e 's/^[^=:]*:=//' \
                        -e 's/^[^=:]*[=:][[:space:]]*//' -e "s/^[\"']*//")
                _eh_ngeneric=no
                if [ -n "$_eh_nvals" ]; then
                    _eh_ngeneric=yes
                    # Captured name values contain spaces, so they are
                    # compared WHOLE (one grep -oE match per line), not
                    # word-split; the heredoc keeps the loop in this shell.
                    while IFS= read -r _eh_nval; do
                        [ -n "$_eh_nval" ] || continue
                        case "$GENERIC_NAMES" in
                        *" $_eh_nval "*) ;;
                        *) _eh_ngeneric=no ;;
                        esac
                    done <<EOF
$_eh_nvals
EOF
                fi
                if [ "$_eh_ngeneric" = yes ]; then
                    continue
                fi
            fi
            # Labeled-identifier generic-value gates (windows-username-labeled,
            # hostname-labeled): single-token value anchors, so doc filler
            # after the label — GENERIC_LABELED_USERS / GENERIC_LABELED_HOSTS,
            # deliberately NOT the runtime GENERIC_USERS set, since root or
            # administrator behind a label is a REAL account and a finding —
            # is excluded after the match by the same shared helper.
            if [ "$_eh_name" = 'windows-username-labeled' ] &&
                eh_all_generic "$GENERIC_LABELED_USERS" \
                    "${WINUSER_LABEL}${WINUSER_VALUE}" 's/[._-]*$//'; then
                continue
            fi
            if [ "$_eh_name" = 'hostname-labeled' ] &&
                eh_all_generic "$GENERIC_LABELED_HOSTS" \
                    "${HOSTNAME_LABEL}${HOSTNAME_VALUE}" 's/[._-]*$//'; then
                continue
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

# scan_stream LABEL FILE — run every detector over FILE: the label
# detectors against a lowercased copy of FILE's lines (case-insensitive by
# construction, with the original line text restored onto every finding —
# see scan_matches), the shape detectors against FILE unchanged.
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

# tracked_files FILE — write to FILE the tracked files, one per line,
# excluding the audit script and the fixtures. (Paths containing newlines are
# not supported.) Fails closed: returns nonzero when `git ls-files` itself
# fails, because a caller that swallowed that would iterate over ZERO files
# while the audit still reported "tracked files and full history scanned" —
# a false clean over an unreadable index or a failing git. git's -z output is
# captured to its own temp first: piping it straight through `tr` would hide
# git's exit status, since the pipe reports tr's.
tracked_files() {
    _tf_z=$(mktemp "${TMPDIR:-/tmp}/audit-lsfiles.XXXXXXXX") || return 1
    if ! git -C "$ROOT" ls-files -z -- \
        ':(exclude)scripts/audit.sh' \
        ':(exclude)tests/fixtures/audit' >"$_tf_z"; then
        rm -f "$_tf_z"
        return 1
    fi
    tr '\0' '\n' <"$_tf_z" >"$1"
    _tf_rc=$?
    rm -f "$_tf_z"
    return "$_tf_rc"
}

# annotated_current_lines FILE — fill FILE with the content of every line in
# the current tracked tree that carries the suppression marker, with the
# marker and trailing whitespace removed. One entry per annotated line; used
# for the history-equivalence rule (see header). Returns nonzero only when
# the tracked-file enumeration itself fails (tracked_files), which the caller
# treats as fatal: an empty-but-successful run merely means no annotated
# lines exist, while a failed one means the equivalence set could not be
# built at all.
annotated_current_lines() {
    _acl_file=$1
    _acl_list=$(mktemp "${TMPDIR:-/tmp}/audit-annotated-src.XXXXXXXX") ||
        return 1
    if ! tracked_files "$_acl_list"; then
        rm -f "$_acl_list"
        return 1
    fi
    while IFS= read -r _acl_f; do
        [ -n "$_acl_f" ] || continue
        [ -f "$ROOT/$_acl_f" ] || continue
        grep -hF -- "$MARKER" "$ROOT/$_acl_f" 2>/dev/null
    done <"$_acl_list" |
        sed -e 's/[[:space:]]*'"$MARKER"'[[:space:]]*$//' \
            -e 's/[[:space:]]*$//' |
        grep -v '^$' >"$_acl_file" 2>/dev/null
    rm -f "$_acl_list"
    return 0
}

# scan_history BUCKET USER HOST HOST_SHORT PROFILE DISPLAY — scan every
# commit's message body, changed-path list and patch (all refs), excluding
# the audit script and fixtures from the patches and path lists. Message bodies are scanned separately from the
# patches: a pathspec-filtered `git show --patch` emits NOTHING — message
# included — for a commit whose changed paths are all excluded (or an empty
# commit), so a credential in such a message would otherwise go unscanned.
# Binary content in a patch appears only as a `Binary files ... differ`
# marker and is therefore not content-scanned: that fails closed with an
# explicit finding, and so does any per-commit `git show` that exits
# nonzero — empty output is a legitimate skip, a failed read never is (see
# the loop). The runtime values (bucket name, username, hostname including
# its short form, AWS profile name, display name) are scanned against BOTH
# streams, with the same scan_literal calls the tracked-file loop makes —
# same needles, hostname and display name case-insensitive as there — so a
# value that only ever reached history (a file later removed, a commit
# message naming the machine) is still a finding. The values arrive
# already carrying default_audit's guards (generic-user skip,
# short-hostname minimum, generic-profile skip, name-shape skip), the same
# guarded forms the tracked-file loop scans.
scan_history() {
    _sh_bucket=${1-}
    _sh_user=${2-}
    _sh_host=${3-}
    _sh_host_short=${4-}
    _sh_profile=${5-}
    _sh_display=${6-}
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
    _sh_paths=$(mktemp "${TMPDIR:-/tmp}/audit-history-paths.XXXXXXXX") || {
        rm -f "$_sh_tmp" "$_sh_msg" "$_sh_revs"
        printf '%s: error: cannot create history paths temp file - failing closed\n' "$SCRIPT_NAME" >&2
        exit 1
    }
    # History-equivalence set: current tracked lines carrying the marker.
    ANNOTATED_LINES=$(mktemp "${TMPDIR:-/tmp}/audit-annotated.XXXXXXXX") || {
        rm -f "$_sh_tmp" "$_sh_msg" "$_sh_revs"
        printf '%s: error: cannot create annotated-lines temp file - failing closed\n' "$SCRIPT_NAME" >&2
        exit 1
    }
    if ! annotated_current_lines "$ANNOTATED_LINES"; then
        rm -f "$_sh_tmp" "$_sh_msg" "$_sh_revs" "$_sh_paths" "$ANNOTATED_LINES"
        ANNOTATED_LINES=
        printf '%s: error: cannot enumerate tracked files for the history-equivalence set (git ls-files failed?) - failing closed, no clean result\n' \
            "$SCRIPT_NAME" >&2
        exit 1
    fi
    # The commit list is produced BEFORE the scan loop and its failure is
    # fatal, in the mktemp style above: piping a failing `git rev-list`
    # straight into the loop would leave it iterating over ZERO commits
    # while default_audit still reports "full history scanned" — a false
    # clean (corrupt or unreadable history, a failing git).
    if ! git -C "$ROOT" rev-list --abbrev-commit --all >"$_sh_revs"; then
        rm -f "$_sh_tmp" "$_sh_msg" "$_sh_revs" "$_sh_paths" "$ANNOTATED_LINES"
        ANNOTATED_LINES=
        printf '%s: error: git rev-list failed (corrupt or unreadable history?) - failing closed, no clean result\n' "$SCRIPT_NAME" >&2
        exit 1
    fi
    while IFS= read -r _sh_sha; do
        [ -n "$_sh_sha" ] || continue
        _sh_label="git-history $_sh_sha"
        # Per-commit reads fail CLOSED, with the exit status captured before
        # any [ -s ] test: emptiness and failure are different facts. Exit 0
        # with empty output is legitimate (an empty commit message here, a
        # commit whose changed paths are all excluded below) and stays a
        # skip; a nonzero exit means git could not read that commit's content
        # at all — corrupt object or blob, an I/O error, a failing git — and
        # becomes an explicit finding naming the commit, so the audit cannot
        # report clean over a commit it could not scan.
        git -C "$ROOT" show -s --no-color --format=%B "$_sh_sha" \
            >"$_sh_msg" 2>/dev/null
        _sh_msg_rc=$?
        if [ "$_sh_msg_rc" -ne 0 ]; then
            printf 'FINDING %s: unreadable-commit-content (git show failed — corrupt object or I/O error; verify manually)\n' \
                "$_sh_label"
        elif [ -s "$_sh_msg" ]; then
            scan_stream "$_sh_label" "$_sh_msg"
            scan_literal state-bucket-name "$_sh_label" "$_sh_msg" \
                "$_sh_bucket"
            scan_literal username "$_sh_label" "$_sh_msg" "$_sh_user"
            scan_literal hostname "$_sh_label" "$_sh_msg" "$_sh_host" ic
            scan_literal hostname "$_sh_label" "$_sh_msg" \
                "$_sh_host_short" ic
            scan_literal aws-profile-name "$_sh_label" "$_sh_msg" \
                "$_sh_profile"
            scan_literal display-name "$_sh_label" "$_sh_msg" \
                "$_sh_display" ic
        fi
        # Changed-path list, with the SAME exclusions as the patch stream.
        # The path is itself audit content: a *.tfstate / *.tfstate.* path
        # changed by this commit is a terraform-state-tracked finding even
        # when the file's content is minimal (`{"version":4,...}`) and even
        # when the file was later deleted from the tree — SPEC §27 requires
        # Terraform state in Git HISTORY to be detected, which content
        # scanning alone cannot do (review thread 3888113063: a
        # committed-then-deleted old.tfstate audited clean). Same fail-closed
        # rule as every other per-commit read: nonzero exit is a finding
        # naming the commit, never a silent skip; exit 0 with empty output
        # is a legitimate skip (a commit whose changed paths are all
        # excluded, or an empty commit).
        git -C "$ROOT" show --no-color --name-only --format= "$_sh_sha" -- \
            ':(exclude)scripts/audit.sh' \
            ':(exclude)tests/fixtures/audit' \
            >"$_sh_paths" 2>/dev/null
        _sh_paths_rc=$?
        if [ "$_sh_paths_rc" -ne 0 ]; then
            printf 'FINDING %s: unreadable-commit-content (git show failed — corrupt object or I/O error; verify manually)\n' \
                "$_sh_label"
        else
            while IFS= read -r _sh_path; do
                [ -n "$_sh_path" ] || continue
                case "$_sh_path" in
                *.tfstate | *.tfstate.*)
                    printf 'FINDING %s %s: terraform-state-tracked (Terraform state path changed in history - SPEC §27; purge the history)\n' \
                        "$_sh_label" "$_sh_path"
                    ;;
                esac
            done <"$_sh_paths"
        fi
        # Patch content, with the audit script and fixtures excluded. Same
        # rule: a failing read is a finding, not a skip. The message form is
        # still attempted above even when this one fails (and vice versa),
        # because one can fail while the other succeeds.
        git -C "$ROOT" show --no-color --patch --format= "$_sh_sha" -- \
            ':(exclude)scripts/audit.sh' \
            ':(exclude)tests/fixtures/audit' \
            >"$_sh_tmp" 2>/dev/null
        _sh_patch_rc=$?
        if [ "$_sh_patch_rc" -ne 0 ]; then
            printf 'FINDING %s: unreadable-commit-content (git show failed — corrupt object or I/O error; verify manually)\n' \
                "$_sh_label"
            continue
        fi
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
        scan_literal aws-profile-name "$_sh_label" "$_sh_tmp" \
            "$_sh_profile"
        scan_literal display-name "$_sh_label" "$_sh_tmp" \
            "$_sh_display" ic
    done <"$_sh_revs"
    rm -f "$_sh_tmp" "$_sh_msg" "$_sh_revs" "$_sh_paths" "$ANNOTATED_LINES"
    ANNOTATED_LINES=
    return 0
}

# ---------------------------------------------------------------------------
# Selftest harness: generative spelling matrix, value must/must-not
# tables, SPEC §27 coverage map
# ---------------------------------------------------------------------------
# Three classes of regression kept recurring in review rounds 19-23 —
# spelling variance (one more case/separator form of a label someone
# types), anchor over/under-matching (a value shape matching prose, or a
# real value slipping under a floor), and SPEC §27 coverage drift (a new
# §27 bullet with no detector behind it). The fixtures pin one instance
# each; the three checks below retire the CLASSES:
#
#   * st_label_matrix — a closure proof over the label spelling grammar:
#     for every LABEL detector, every word set it accepts, the cross
#     product of per-word case forms × inter-word separators × assignment
#     separators × quote styles × value alternatives, every generated
#     line asserted to fire its detector. Generated, not sampled: a new
#     spelling the engine mishandles fails the matrix the moment it is
#     added to the grammar below (and the matrix registry fails loudly if
#     a detector is added without one).
#   * st_shape_matrix / st_value_tables — the same must/must-not
#     discipline for SHAPE detectors (case products that must match and
#     lookalikes that must not) and, per detector, value tables asserting
#     BOTH directions: values that must fire and near-miss values (prose
#     words, pure digits where excluded, sub-floor lengths, Unicode
#     ellipsis, angle-bracket placeholders, generic profile values,
#     quoted generics with trailing punctuation) that must stay silent.
#   * st_spec27_map — SPEC.md §27's bullet list is PARSED at selftest
#     runtime and every bullet must map to at least one detector class or
#     documented runtime check; a mapping naming a class that does not
#     exist, a §27 bullet with no mapping, a detector with no §27 anchor,
#     or a §27 edit that renames the section all FAIL the selftest.
#
# Everything drives the REAL engine (scan_file / scan_stream) with the
# standard exclusions; nothing re-implements a detector. POSIX sh only:
# no arrays, no local, no process substitution, no GNU-only flags.

# Work directory created by selftest() and removed by it; every harness
# function below reads and writes its scratch files in here.
ST_WORK=

# st_form WORD INDEX — print WORD in case form INDEX (0 lower, 1 UPPER,
# 2 Title). A static table: no per-call subprocesses (the matrix builds
# ~10^5 lines), and a MATRIX_LABEL_SETS word missing here yields an empty
# form, a broken spelling, and the count assertion's own FAIL — the
# harness cannot drift silently.
st_form() {
    case "$1 $2" in
    'aws 0') printf 'aws' ;;
    'aws 1') printf 'AWS' ;;
    'aws 2') printf 'Aws' ;;
    'secret 0') printf 'secret' ;;
    'secret 1') printf 'SECRET' ;;
    'secret 2') printf 'Secret' ;;
    'access 0') printf 'access' ;;
    'access 1') printf 'ACCESS' ;;
    'access 2') printf 'Access' ;;
    'key 0') printf 'key' ;;
    'key 1') printf 'KEY' ;;
    'key 2') printf 'Key' ;;
    'activation 0') printf 'activation' ;;
    'activation 1') printf 'ACTIVATION' ;;
    'activation 2') printf 'Activation' ;;
    'code 0') printf 'code' ;;
    'code 1') printf 'CODE' ;;
    'code 2') printf 'Code' ;;
    'session 0') printf 'session' ;;
    'session 1') printf 'SESSION' ;;
    'session 2') printf 'Session' ;;
    'security 0') printf 'security' ;;
    'security 1') printf 'SECURITY' ;;
    'security 2') printf 'Security' ;;
    'token 0') printf 'token' ;;
    'token 1') printf 'TOKEN' ;;
    'token 2') printf 'Token' ;;
    'account 0') printf 'account' ;;
    'account 1') printf 'ACCOUNT' ;;
    'account 2') printf 'Account' ;;
    'id 0') printf 'id' ;;
    'id 1') printf 'ID' ;;
    'id 2') printf 'Id' ;;
    'profile 0') printf 'profile' ;;
    'profile 1') printf 'PROFILE' ;;
    'profile 2') printf 'Profile' ;;
    'serial 0') printf 'serial' ;;
    'serial 1') printf 'SERIAL' ;;
    'serial 2') printf 'Serial' ;;
    'number 0') printf 'number' ;;
    'number 1') printf 'NUMBER' ;;
    'number 2') printf 'Number' ;;
    'personal 0') printf 'personal' ;;
    'personal 1') printf 'PERSONAL' ;;
    'personal 2') printf 'Personal' ;;
    'full 0') printf 'full' ;;
    'full 1') printf 'FULL' ;;
    'full 2') printf 'Full' ;;
    'real 0') printf 'real' ;;
    'real 1') printf 'REAL' ;;
    'real 2') printf 'Real' ;;
    'name 0') printf 'name' ;;
    'name 1') printf 'NAME' ;;
    'name 2') printf 'Name' ;;
    'user 0') printf 'user' ;;
    'user 1') printf 'USER' ;;
    'user 2') printf 'User' ;;
    'host 0') printf 'host' ;;
    'host 1') printf 'HOST' ;;
    'host 2') printf 'Host' ;;
    'computer 0') printf 'computer' ;;
    'computer 1') printf 'COMPUTER' ;;
    'computer 2') printf 'Computer' ;;
    'windows 0') printf 'windows' ;;
    'windows 1') printf 'WINDOWS' ;;
    'windows 2') printf 'Windows' ;;
    'win 0') printf 'win' ;;
    'win 1') printf 'WIN' ;;
    'win 2') printf 'Win' ;;
    'local 0') printf 'local' ;;
    'local 1') printf 'LOCAL' ;;
    'local 2') printf 'Local' ;;
    'sam 0') printf 'sam' ;;
    'sam 1') printf 'SAM' ;;
    'sam 2') printf 'Sam' ;;
    'logon 0') printf 'logon' ;;
    'logon 1') printf 'LOGON' ;;
    'logon 2') printf 'Logon' ;;
    'machine 0') printf 'machine' ;;
    'machine 1') printf 'MACHINE' ;;
    'machine 2') printf 'Machine' ;;
    *)
        printf 'selftest: internal: st_form: no case form for word "%s"\n' \
            "$1" >&2
        return 1
        ;;
    esac
    return 0
}

# st_spellings WORDS OUT MODE — write to OUT every label spelling for
# the space-separated WORDS: the product of per-word case forms ×
# inter-word separators ('' space '_' '-' '.'). Iterative prefix
# expansion, one word per round over a scratch file — deliberately NOT
# recursive: POSIX sh has no local variables, so a recursive generator's
# globals are clobbered by its own children (the first draft of this
# function dropped each spelling's last word exactly that way). Each
# intermediate line carries its case STATE before the spelling
# ('u awsSecret', states separated by a space from the spelling, which
# never contains one). MODE picks the case assignments generated:
#   f  free — every word independently lower/UPPER/Title (full 3^n);
#      used for word sets of at most three words.
#   u  uniform-so-far — all-lower, or an all-UPPER / all-Title suffix
#      from any one word on (2n+1 assignments); used for the one
#      four-word set, where the full 3^4 would triple the matrix for no
#      information: label matching runs against a LOWERCASED copy of the
#      line (scan_matches), so per-word case cannot interact with any
#      other dimension — the u/U/T set still exercises every word in
#      every case form crossed with every separator, assignment and
#      quote spelling, and the all-UPPER/all-Title spellings pin the
#      lowercasing architecture itself (drop the lowercasing and the
#      matrix fails instantly).
st_spellings() {
    _sw_words=$1
    _sw_out=$2
    _sw_mode=$3
    _sw_first=yes
    printf '%s \n' "$_sw_mode" >"$ST_WORK/sw-cur"
    while [ -n "$_sw_words" ]; do
        _sw_word=${_sw_words%% *}
        case $_sw_words in
        *" "*) _sw_words=${_sw_words#* } ;;
        *) _sw_words= ;;
        esac
        _sw_f0=$(st_form "$_sw_word" 0)
        _sw_f1=$(st_form "$_sw_word" 1)
        _sw_f2=$(st_form "$_sw_word" 2)
        : >"$ST_WORK/sw-next"
        while IFS= read -r _sw_entry; do
            [ -n "$_sw_entry" ] || continue
            _sw_state=${_sw_entry%% *}
            _sw_prefix=${_sw_entry#* }
            case $_sw_state in
            u) _sw_pairs='0-u 1-U 2-T' ;;
            U) _sw_pairs='1-U' ;;
            T) _sw_pairs='2-T' ;;
            *) _sw_pairs='0-f 1-f 2-f' ;;
            esac
            for _sw_pair in $_sw_pairs; do
                _sw_ci=${_sw_pair%-*}
                _sw_next=${_sw_pair#*-}
                case $_sw_ci in
                0) _sw_form=$_sw_f0 ;;
                1) _sw_form=$_sw_f1 ;;
                *) _sw_form=$_sw_f2 ;;
                esac
                if [ "$_sw_first" = yes ]; then
                    # A separator goes BETWEEN words only: the first
                    # word takes none (a leading one is not a spelling
                    # the grammar has, and it would multiply the whole
                    # product by 5 per word set).
                    printf '%s %s%s\n' "$_sw_next" "$_sw_prefix" \
                        "$_sw_form" >>"$ST_WORK/sw-next"
                else
                    for _sw_sep in '' ' ' '_' '-' '.'; do
                        printf '%s %s%s%s\n' "$_sw_next" "$_sw_prefix" \
                            "$_sw_sep" "$_sw_form" >>"$ST_WORK/sw-next"
                    done
                fi
            done
        done <"$ST_WORK/sw-cur"
        mv -- "$ST_WORK/sw-next" "$ST_WORK/sw-cur"
        _sw_first=no
    done
    sed 's/^[A-Za-z] //' "$ST_WORK/sw-cur" >>"$_sw_out"
    return 0
}

# st_expand SPELLS OUT VALUES — for every label spelling in SPELLS,
# append to OUT one variant line per assignment separator ('=', ':',
# ':=') × open quote (none, ", ') × close quote (none, ", '), rotating
# the space-separated VALUE alternatives across the emitted lines.
# Rotation rather than product: the value grammars share no character
# class with the quote/assignment spans, so pair-closure needs every
# spelling to MEET every value (27 variants per spelling, every value
# appears in each spelling's run), not every (spelling, value) pair —
# which keeps the matrix ~10^5 lines instead of ~10^6. Quote open/close
# are independent because QUOTE_CLASS appears twice in every label ERE
# (closing a quoted JSON key, opening a quoted value).
st_expand() {
    _ex_spells=$1
    _ex_out=$2
    _ex_vals=$3
    _ex_nvals=$(printf '%s' "$_ex_vals" | awk -F, '{print NF}')
    while IFS= read -r _ex_spell; do
        [ -n "$_ex_spell" ] || continue
        for _ex_assign in '=' ':' ':='; do
            for _ex_qopen in '' '"' "'"; do
                for _ex_qclose in '' '"' "'"; do
                    _ex_val=${_ex_vals%%,*}
                    printf '%s\n' \
                        "${_ex_spell}${_ex_qopen}${_ex_assign}${_ex_qclose}${_ex_val}"
                    if [ "$_ex_nvals" -gt 1 ]; then
                        _ex_vals="${_ex_vals#*,},${_ex_val}"
                    fi
                done
            done
        done
    done <"$_ex_spells" >>"$_ex_out"
    return 0
}

# st_assert_all WHAT CLASS WANT INFILE OUTFILE — OUTFILE holds the
# engine's FINDING records for INFILE; assert every one of INFILE's WANT
# lines fired CLASS. grep -n reports a line at most once per ERE per
# scan, so CLASS hits each line at most once: a count of WANT proves
# every line fired (none twice, none missed). On failure, name the
# offending input lines.
st_assert_all() {
    _aa_what=$1
    _aa_class=$2
    _aa_want=$3
    _aa_in=$4
    _aa_out=$5
    _aa_got=$(grep -c ": ${_aa_class}\$" "$_aa_out")
    if [ "$_aa_got" -eq "$_aa_want" ]; then
        printf 'selftest: PASS  %-44s %s variants fired\n' \
            "$_aa_what" "$_aa_want"
        return 0
    fi
    printf 'selftest: FAIL  %-44s %s of %s fired\n' \
        "$_aa_what" "$_aa_got" "$_aa_want"
    sed -n "s/^FINDING [^:]*:\\([0-9]*\\): ${_aa_class}\$/\\1/p" \
        "$_aa_out" >"$ST_WORK/aa-fired"
    awk 'NR==FNR{_h[$1]=1;next}!_h[FNR]{printf "         silent input line %d: %s\n",FNR,$0}' \
        "$ST_WORK/aa-fired" "$_aa_in" | head -n 3
    return 1
}

# st_assert_none WHAT CLASS INFILE OUTFILE — assert no line of INFILE
# fired CLASS; on violation, show the offending FINDING records.
st_assert_none() {
    _an_what=$1
    _an_class=$2
    _an_in=$3
    _an_out=$4
    if ! grep -q ": ${_an_class}\$" "$_an_out"; then
        printf 'selftest: PASS  %-44s %s lines silent\n' \
            "$_an_what" "$(grep -c . "$_an_in")"
        return 0
    fi
    printf 'selftest: FAIL  %-44s fired on must-silent input\n' "$_an_what"
    grep ": ${_an_class}\$" "$_an_out" | head -n 3 |
        sed 's/^/         /'
    return 1
}

# st_check WHAT CLASS MUSTFILE MUSTNOTFILE — scan both files through the
# real engine (standard exclusions; the labels carry no colon so FINDING
# records stay one-colon-parseable) and assert both directions.
st_check() {
    _ck_what=$1
    _ck_class=$2
    _ck_must=$3
    _ck_mustnot=$4
    scan_file "$_ck_must" "harness-${_ck_class}-must" >"$ST_WORK/ck-must.out"
    scan_file "$_ck_mustnot" "harness-${_ck_class}-silent" \
        >"$ST_WORK/ck-silent.out"
    st_assert_all "$_ck_what must" "$_ck_class" \
        "$(grep -c . "$_ck_must")" "$_ck_must" "$ST_WORK/ck-must.out" &&
        st_assert_none "$_ck_what silent" "$_ck_class" \
            "$_ck_mustnot" "$ST_WORK/ck-silent.out"
}

# Label-matrix registry: `detector|word set|value alternatives` per line.
# The word sets are the label's mandatory words plus its optional prefix
# (`aws`) or suffix (`id`, `number`) in every combination the ERE accepts;
# values are COMMA-separated (name values contain spaces) and are taken
# from the detector's own value grammar (length floors included, and every
# alternative of a multi-alternative grammar) — and,
# for key material, from the SYNTHETIC-KEY CONVENTION in the header:
# every value a generator can emit is a deterministic sequential pattern
# (EXAMPLE repetition, alphabet wrap, SYNTHETIC-word prefix, ascending
# digits) so no server-side secret scanner can mistake it for entropy.
# The first check below fails if this registry and LABEL_DETECTORS ever
# name different detectors, in either direction. Word-set rows cover every
# label word and both label shapes; the optional-suffix three-word form
# (sam…account…name) is pinned by value-table rows — a full matrix row
# for it costs 18k variants of machinery every other row already sweeps.
MATRIX_LABEL_SETS='aws-secret-access-key|secret access key|EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE,EXAMPLEEXAMPLEEXAMPLEEXAMPLE+/==ABC,ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk
aws-secret-access-key|aws secret access key|EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE,EXAMPLEEXAMPLEEXAMPLEEXAMPLE+/==ABC,ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk
aws-activation-code|activation code|SYNTHETICACTIVATIONCODE01234567,aaaa/bbbb+
aws-session-token|session token|SYNTHETICSESSIONTOKEN0123456789,SYNTHETICSESSIONTOKEN+/==ABCDEF
aws-session-token|security token|SYNTHETICSESSIONTOKEN0123456789,SYNTHETICSESSIONTOKEN+/==ABCDEF
aws-session-token|aws session token|SYNTHETICSESSIONTOKEN0123456789,SYNTHETICSESSIONTOKEN+/==ABCDEF
aws-session-token|aws security token|SYNTHETICSESSIONTOKEN0123456789,SYNTHETICSESSIONTOKEN+/==ABCDEF
account-id-context|account|123456789012,000000000000
account-id-context|account id|123456789012,000000000000
aws-sso-profile|aws profile|mxprod7,9prod.name-x,MX-Prod_99
machine-serial-number|serial|mtx1aaaaaa,9mtxaaaaaa,ABC12345,ABC-12345,ABCDEFG1,ABC1234Z
machine-serial-number|serial number|mtx1aaaaaa,9mtxaaaaaa,ABC12345,ABC-12345,ABCDEFG1,ABC1234Z
personal-name|personal name|Alice Smith,Jean-Pierre Blanc,Mary Jane Watson
personal-name|full name|Alice Smith,Jean-Pierre Blanc,Mary Jane Watson
personal-name|real name|Alice Smith,Jean-Pierre Blanc,Mary Jane Watson
windows-username-labeled|user name|alice.smith,svc-win-ci,LocalAdmin1
hostname-labeled|host name|ALICE-PC,build-runner-01,ci-host.example.internal
hostname-labeled|computer name|ALICE-PC,build-runner-01,ci-host.example.internal
hostname-labeled|machine name|ALICE-PC,build-runner-01,ci-host.example.internal
windows-username-labeled|windows user|alice.smith,svc-win-ci,LocalAdmin1
windows-username-labeled|windows account|alice.smith,svc-win-ci,LocalAdmin1
windows-username-labeled|win account|alice.smith,svc-win-ci,LocalAdmin1
windows-username-labeled|local account|alice.smith,svc-win-ci,LocalAdmin1
windows-username-labeled|sam account|alice.smith,svc-win-ci,LocalAdmin1
windows-username-labeled|logon name|alice.smith,svc-win-ci,LocalAdmin1'

st_label_matrix() {
    _lm_status=0
    _lm_dets=
    printf '%s\n' "$MATRIX_LABEL_SETS" >"$ST_WORK/lm-reg"
    # Registry closure: matrix word sets exist for every label detector
    # and nothing else.
    sed 's/|.*//' "$ST_WORK/lm-reg" | LC_ALL=C sort -u >"$ST_WORK/lm-a"
    printf '%s\n' "$LABEL_DETECTORS" | sed 's/:.*//' | LC_ALL=C sort -u \
        >"$ST_WORK/lm-b"
    _lm_diff=$(comm -3 "$ST_WORK/lm-a" "$ST_WORK/lm-b")
    if [ -n "$_lm_diff" ]; then
        printf 'selftest: FAIL  label matrix registry out of sync with LABEL_DETECTORS (only-in-matrix / only-in-detectors):\n'
        printf '%s\n' "$_lm_diff" | sed 's/^/         /'
        return 1
    fi
    while IFS='|' read -r _lm_det _lm_words _lm_vals; do
        [ -n "$_lm_det" ] || continue
        case " $_lm_dets " in
        *" $_lm_det "*) ;;
        *)
            _lm_dets="$_lm_dets $_lm_det"
            : >"$ST_WORK/lm-$_lm_det"
            ;;
        esac
        if [ "$(printf '%s\n' "$_lm_words" | wc -w | tr -d ' ')" -le 3 ]; then
            _lm_mode=f
        else
            _lm_mode=u
        fi
        : >"$ST_WORK/lm-spells"
        st_spellings "$_lm_words" "$ST_WORK/lm-spells" "$_lm_mode"
        # Runaway guard: a grammar bug in the generator must fail loudly,
        # not expand a bogus product to disk-filling size.
        if [ "$(grep -c . "$ST_WORK/lm-spells")" -gt 15000 ]; then
            printf 'selftest: FAIL  spelling generator runaway for %s (%s spellings; harness grammar bug - refusing to expand)\n' \
                "$_lm_det" "$(grep -c . "$ST_WORK/lm-spells")"
            _lm_status=1
            continue
        fi
        st_expand "$ST_WORK/lm-spells" "$ST_WORK/lm-$_lm_det" "$_lm_vals"
    done <"$ST_WORK/lm-reg"
    for _lm_det in $_lm_dets; do
        scan_file "$ST_WORK/lm-$_lm_det" "matrix-$_lm_det" \
            >"$ST_WORK/lm-out" ||
            {
                printf 'selftest: FAIL  matrix scan failed for %s\n' "$_lm_det"
                _lm_status=1
                continue
            }
        st_assert_all "label matrix $_lm_det" "$_lm_det" \
            "$(grep -c . "$ST_WORK/lm-$_lm_det")" \
            "$ST_WORK/lm-$_lm_det" "$ST_WORK/lm-out" || _lm_status=1
    done
    return "$_lm_status"
}

# st_shape_matrix — case products that MUST match and lookalikes that
# MUST NOT, per SHAPE detector, against the original (non-lowercased)
# line. The products cover every case-bearing span each detector treats
# as insensitive (SSO scheme + awsapps.com host, ARN arn:aws prefix
# through partition/service/region, Windows drive + Users, Users in
# /Users) and the must-not side pins the case-bearing grammar (path
# /start, lowercase akia/mi, uppercase hex bodies, /home literal).
st_shape_matrix() {
    _sh_status=0

    # aws-access-key-id / aws-session-key-id: the AKIA/ASIA prefix is
    # uppercase by AWS's own grammar; the body is [0-9A-Z]{16,}. Every
    # body follows the SYNTHETIC-KEY CONVENTION (header): alphabet wraps
    # and ascending digits only, and never the exact fixture bodies at
    # new sites — push protection flags per-secret, so new literals stay
    # new patterns.
    : >"$ST_WORK/shp-akia-m"
    : >"$ST_WORK/shp-akia-x"
    cat >>"$ST_WORK/shp-akia-m" <<'EOF'
variable = "AKIAQRSTUVWXYZHIJKLMNOP"
AKIA0123456789012345
AKIAQRSTUVWXYZABCDEFGHIJKLMNOP
key AKIAQRSTUVWXYZHIJKLMNOP end
AKIA012345678901234567890123
EOF
    cat >>"$ST_WORK/shp-akia-x" <<'EOF'
akiaqrstuvwxyzhijklmnop
AkiaQRSTUVWXYZHIJKLMNOP
aKIAQRSTUVWXYZHIJKLMNOP
AKIAABCDEFGHIJKLMNO
AKIA-0123456789012345
AKIA QRSTUVWXYZHIJKLMNOP
EOF
    st_check 'shape aws-access-key-id' aws-access-key-id \
        "$ST_WORK/shp-akia-m" "$ST_WORK/shp-akia-x" || _sh_status=1

    : >"$ST_WORK/shp-asia-m"
    : >"$ST_WORK/shp-asia-x"
    cat >>"$ST_WORK/shp-asia-m" <<'EOF'
variable = "ASIAQRSTUVWXYZHIJKLMNOP"
ASIA0123456789012345
ASIAQRSTUVWXYZABCDEFGHIJKLMNOP
key ASIAQRSTUVWXYZHIJKLMNOP end
EOF
    cat >>"$ST_WORK/shp-asia-x" <<'EOF'
asiaqrstuvwxyzhijklmnop
AsiaQRSTUVWXYZHIJKLMNOP
aSIAQRSTUVWXYZHIJKLMNOP
ASIAABCDEFGHIJKLMNO
ASIA-0123456789012345
ASIA QRSTUVWXYZHIJKLMNOP
variable = "AKIAQRSTUVWXYZHIJKLMNOP"
EOF
    st_check 'shape aws-session-key-id' aws-session-key-id \
        "$ST_WORK/shp-asia-m" "$ST_WORK/shp-asia-x" || _sh_status=1

    # managed-node-id: lowercase mi- scheme, lowercase hex body, 8+.
    : >"$ST_WORK/shp-mi-m"
    : >"$ST_WORK/shp-mi-x"
    cat >>"$ST_WORK/shp-mi-m" <<'EOF'
managed_node_id = "mi-abcdef0123456789"
mi-0123456789abcdef0
node=mi-1234abcd5678ef90
mi-1234abcd
mi-deadbeefcafe0123
EOF
    cat >>"$ST_WORK/shp-mi-x" <<'EOF'
MI-abcdef0123456789
Mi-abcdef0123456789
mi-ABCDEF0123
mi-abc1234
mi_abcdef01
EOF
    st_check 'shape managed-node-id' managed-node-id \
        "$ST_WORK/shp-mi-m" "$ST_WORK/shp-mi-x" || _sh_status=1

    # uuid-literal: hex case-insensitive, group structure exact.
    : >"$ST_WORK/shp-uuid-m"
    : >"$ST_WORK/shp-uuid-x"
    cat >>"$ST_WORK/shp-uuid-m" <<'EOF'
activation_id = "123e4567-e89b-12d3-a456-426614174000"
123E4567-E89B-12D3-A456-426614174000
123e4567-E89b-12D3-a456-426614174000
EOF
    cat >>"$ST_WORK/shp-uuid-x" <<'EOF'
123e4567-e89b-12d3-a456-42661417400
123e4567-e89b-12d3-a456_426614174000
g23e4567-e89b-12d3-a456-426614174000
123E4567e89b12d3a456426614174000
123e4567-e89b-12d3-a456
EOF
    st_check 'shape uuid-literal' uuid-literal \
        "$ST_WORK/shp-uuid-m" "$ST_WORK/shp-uuid-x" || _sh_status=1

    # sso-start-url: scheme × host-label case × awsapps.com case product
    # (36 must lines); /start stays case-sensitive, a host label is
    # required, https is required, and the Unicode-ellipsis host of
    # SPEC.md's own self-reference stays silent.
    : >"$ST_WORK/shp-url-m"
    for _sh_scheme in https HTTPS Https hTtPs; do
        for _sh_host in d-a1b2c3d4e5f6g7h8i D-A1B2C3D4E5F6G7H8I D-a1B2c3D4; do
            for _sh_apps in awsapps.com AWSAPPS.COM AwsApps.Com; do
                printf 'start_url = "%s://%s.%s/start"\n' \
                    "$_sh_scheme" "$_sh_host" "$_sh_apps" \
                    >>"$ST_WORK/shp-url-m"
            done
        done
    done
    : >"$ST_WORK/shp-url-x"
    cat >>"$ST_WORK/shp-url-x" <<'EOF'
https://…awsapps.com/start
https://awsapps.com/start
http://d-x.awsapps.com/start
https://d-x.awsapps.com/Start
https://d-x.awsapps.com/START
https://d-x.awsapps.co/start
EOF
    st_check 'shape sso-start-url' sso-start-url \
        "$ST_WORK/shp-url-m" "$ST_WORK/shp-url-x" || _sh_status=1

    # email-address: allowlisted commit-trailer address never a finding.
    : >"$ST_WORK/shp-email-m"
    : >"$ST_WORK/shp-email-x"
    cat >>"$ST_WORK/shp-email-m" <<'EOF'
contact = "user@example.invalid"
first.last+tag@sub.example.co.uk
UPPER@EXAMPLE.COM
user%plus@my-host.example.org
EOF
    cat >>"$ST_WORK/shp-email-x" <<'EOF'
user@localhost
a@b.c
user@example…com
 @example.com
Co-Authored-By: Claude <noreply@anthropic.com>
EOF
    st_check 'shape email-address' email-address \
        "$ST_WORK/shp-email-m" "$ST_WORK/shp-email-x" || _sh_status=1

    # account-id-arn: prefix case × partition × service case × region
    # presence product (72 must lines); the identity is the 12-digit
    # account field.
    : >"$ST_WORK/shp-arn-m"
    for _sh_pre in 'arn:aws' 'ARN:AWS' 'Arn:Aws' 'aRn:aWs'; do
        for _sh_part in '' '-us-gov' '-cn'; do
            for _sh_svc in iam IAM Iam; do
                for _sh_reg in '' ':us-east-1'; do
                    printf 'arn_link = "%s%s:%s%s:123456789012:role/mx"\n' \
                        "$_sh_pre" "$_sh_part" "$_sh_svc" "$_sh_reg" \
                        >>"$ST_WORK/shp-arn-m"
                done
            done
        done
    done
    : >"$ST_WORK/shp-arn-x"
    cat >>"$ST_WORK/shp-arn-x" <<'EOF'
arn:aws:iam::12345678901:role/x
arn:azure:iam::123456789012
arn aws iam 123456789012
EOF
    st_check 'shape account-id-arn' account-id-arn \
        "$ST_WORK/shp-arn-m" "$ST_WORK/shp-arn-x" || _sh_status=1

    # user-home-path: drive-letter case × Users case × separator
    # direction product, double separators, /Users case product, /home.
    # Backslashes live in the printf FORMAT (where \\ is one literal
    # backslash), never in shell variables.
    : >"$ST_WORK/shp-home-m"
    for _sh_drive in C d; do
        for _sh_users in Users users USERS; do
            printf '%s:\\%s\\mx.user1\n' "$_sh_drive" "$_sh_users" \
                >>"$ST_WORK/shp-home-m"
            printf '%s:/%s/mx.user1\n' "$_sh_drive" "$_sh_users" \
                >>"$ST_WORK/shp-home-m"
        done
    done
    {
        printf 'C:\\\\Users\\\\mx.user1\n'
        printf 'D://Users//mx.user1\n'
        printf '/Users/mx.user1\n/users/Mx.User_1\n/USERS/mxuser2\n'
        printf '/home/mx.user1\n/home/ec2-user/sub\n/home/mx_user-2\n'
        # Short username segments: one-character names are real (review
        # round 29 removed the {2,} floor). Length sweep, segments 1..4
        # across all four path forms (Windows backslash, Windows slash,
        # macOS /Users, Linux /home).
        _sh_seg=
        _sh_segp=wxyz
        _sh_li=1
        while [ "$_sh_li" -le 4 ]; do
            _sh_seg=${_sh_seg}${_sh_segp%"${_sh_segp#?}"}
            _sh_segp=${_sh_segp#?}
            printf 'C:\\Users\\%s\nC:/Users/%s\n/Users/%s\n/home/%s\n' \
                "$_sh_seg" "$_sh_seg" "$_sh_seg" "$_sh_seg" \
                >>"$ST_WORK/shp-home-m"
            _sh_li=$((_sh_li + 1))
        done
    } >>"$ST_WORK/shp-home-m"
    : >"$ST_WORK/shp-home-x"
    cat >>"$ST_WORK/shp-home-x" <<'EOF'
C:\Users\<username>\.aws\config
copy "%USERPROFILE%\.aws\config" D:\
~/.aws/config and $HOME/.aws/config identify nobody
https://example.com/home/page
/Home/mxuser
EOF
    st_check 'shape user-home-path' user-home-path \
        "$ST_WORK/shp-home-m" "$ST_WORK/shp-home-x" || _sh_status=1

    return "$_sh_status"
}

# st_serial_table_line LEN POS SIZE DIGITBLOCK FLAG — append one
# machine-serial-number value-table line to the harness table: a token of
# LEN characters whose positions POS..POS+SIZE-1 come from the digit pool
# when DIGITBLOCK is yes (letter pool otherwise) and whose remaining
# positions come from the other pool. Pools advance per consumed
# character and wrap when exhausted, so no two generated tokens repeat.
# FLAG is the table's M (must fire) or X (must stay silent) column — a
# SIZE covering the whole length builds the pure-digit / pure-letter
# silent tokens. The label spelling cycles across three canonical
# anchors so the tokens are not all generated behind one spelling.
# Everything is parameter expansion: ~200 tokens, zero subprocesses.
st_serial_table_line() {
    _st_len=$1
    _st_pos=$2
    _st_size=$3
    _st_dig=$4
    _st_flag=$5
    _st_letters=ABCDEFGHIJKLMNOPQRSTUVWXYZ
    _st_digits=0123456789
    _st_tok=
    _st_i=1
    while [ "$_st_i" -le "$_st_len" ]; do
        if [ "$_st_i" -ge "$_st_pos" ] &&
            [ "$_st_i" -lt "$((_st_pos + _st_size))" ]; then
            _st_want=$_st_dig
        elif [ "$_st_dig" = yes ]; then
            _st_want=no
        else
            _st_want=yes
        fi
        if [ "$_st_want" = yes ]; then
            [ -n "$_st_digits" ] || _st_digits=0123456789
            _st_c=${_st_digits%"${_st_digits#?}"}
            _st_digits=${_st_digits#?}
        else
            [ -n "$_st_letters" ] ||
                _st_letters=ABCDEFGHIJKLMNOPQRSTUVWXYZ
            _st_c=${_st_letters%"${_st_letters#?}"}
            _st_letters=${_st_letters#?}
        fi
        _st_tok=${_st_tok}${_st_c}
        _st_i=$((_st_i + 1))
    done
    case $((_sv_count % 3)) in
    0) _st_spell='serial_number =' ;;
    1) _st_spell='Serial Number:' ;;
    2) _st_spell='serial:=' ;;
    esac
    _sv_count=$((_sv_count + 1))
    printf 'machine-serial-number|%s|%s "%s"\n' \
        "$_st_flag" "$_st_spell" "$_st_tok" >>"$ST_WORK/vt-table"
    return 0
}

# st_value_tables — per-LABEL-detector value must/must-not tables
# (anchor class): values that must fire through a plain canonical
# spelling, and near-miss values that must stay silent — prose words,
# pure digits where excluded, sub-floor lengths, Unicode ellipsis,
# angle-bracket placeholders, generic profile values, quoted generics
# with trailing punctuation. The round-19..23 regression values are all
# here (`production`, `corp-admin-prod`, `ABC12345`, `C02ZQ0ABC123`,
# the X-Amz-Security-Token forms, `default`, `EXAMPLE`), alongside the
# spellings the matrix itself found missing (dotted keys, ':='
# assignment, hyphenated serials). The
# tab-indented assignment forms are appended by printf after the heredoc
# because heredocs make a literal tab invisible to review. Note
# `aws_profile = "default,"` sits on the SILENT side: the profile value
# anchor stops at the comma (not in its class), so the generic-value
# gate still sees plain `default` — the gate trims trailing dot,
# underscore and dash only, and a trailing comma changes nothing.
st_value_tables() {
    _vt_status=0
    cat >"$ST_WORK/vt-table" <<'EOF'
aws-secret-access-key|M|aws_secret_access_key = "EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE"
aws-secret-access-key|M|SecretAccessKey=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk
aws-secret-access-key|M|"SecretAccessKey": "EXAMPLEEXAMPLEEXAMPLEEXAMPLE+/==ABC"
aws-secret-access-key|M|Secret Access Key = EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE
aws-secret-access-key|M|aws.secret.access.key = EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE
aws-secret-access-key|M|secret_access_key := ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk
aws-secret-access-key|M|awsSecretAccessKey='EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE'
aws-secret-access-key|X|secret_access_key = EXAMPLE
aws-secret-access-key|X|SecretAccessKey = <secret-key>
aws-secret-access-key|X|secret access key rotation is mandatory
aws-secret-access-key|X|secret_access_key_length = 40
aws-secret-access-key|X|secret_access_key = "…"
aws-secret-access-key|X|the secret access key: see the runbook
aws-secret-access-key|X|secret-key = "EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE"
aws-activation-code|M|activation_code = "SYNTHETICACTIVATIONCODE0123456789AB"
aws-activation-code|M|ACTIVATION_CODE=SYNTHETICACTIVATIONCODE0123456789AB
aws-activation-code|M|"ActivationCode": "SYNTHETICACTIVATIONCODE0123456789AB"
aws-activation-code|M|activation.code := SYNTHETICACTIVATIONCODE01234567
aws-activation-code|M|$activationCode = 'abcdefgh'
aws-activation-code|M|ACTIVATION CODE: 01234567
aws-activation-code|X|activation_code = ABC1234
aws-activation-code|X|activation code: <code>
aws-activation-code|X|activation code: …
aws-activation-code|X|terraform output -raw activation_code
aws-activation-code|X|activation_code is displayed once at enrollment
aws-activation-code|X|activation_id = 123e4567-e89b-12d3-a456-426614174000
aws-session-token|M|AWS_SESSION_TOKEN=SYNTHETICSESSIONTOKEN0123456789
aws-session-token|M|X-Amz-Security-Token: SYNTHETICSECURITYTOKEN0123456789
aws-session-token|M|"SecurityToken": "SYNTHETICSECURITYTOKENABCDEFGHIJ"
aws-session-token|M|SECURITY_TOKEN=SYNTHETICSECURITYTOKENQRSTUVWXYZ
aws-session-token|M|session.token := SYNTHETICSESSIONTOKEN0123456789
aws-session-token|M|Session Token = abcdefghijklmnop
aws-session-token|M|aws_session_token = 'SYNTHETICSESSIONTOKEN+/==ABCDEF'
aws-session-token|M|?X-Amz-Security-Token=awssecuritytokenheaderform
aws-session-token|X|Session Token: EXAMPLE
aws-session-token|X|session_token = <token>
aws-session-token|X|security_token: …
aws-session-token|X|aws_session_token
aws-session-token|X|the session token expires hourly
aws-session-token|X|SessionToken=short
aws-session-token|X|session_token = abcdefghijklmno
account-id-context|M|account_id = "123456789012"
account-id-context|M|accountId = 123456789012
account-id-context|M|"Account": "123456789012"
account-id-context|M|AWS_ACCOUNT_ID=999999999999
account-id-context|M|account.id: 000000000000
account-id-context|M|account := 111122223333
account-id-context|X|account_id = 12345
account-id-context|X|account_id: <account-id>
account-id-context|X|account_id: …
account-id-context|X|aws account 123456789012 is used for tests
account-id-context|X|account_owner = 123456789012
account-id-context|X|arn = "arn:aws:iam::123456789012:role/example"
account-id-context|X|account = 1234
aws-sso-profile|M|export AWS_PROFILE=production
aws-sso-profile|M|aws_profile = "corp-admin-prod"
aws-sso-profile|M|"AwsProfile": "PowerUserAccess-123456789012"
aws-sso-profile|M|$env:AWS_PROFILE = 'corp_admin_prod'
aws-sso-profile|M|AWS PROFILE = CorpAdmin-Prod2
aws-sso-profile|M|awsProfile=dev_profile
aws-sso-profile|M|aws.profile := 9prod.name-x
aws-sso-profile|M|aws profile : mxprod7
aws-sso-profile|X|AWS_PROFILE=default
aws-sso-profile|X|aws_profile: "example"
aws-sso-profile|X|export AWS_PROFILE=<profile>
aws-sso-profile|X|aws_profile = "default."
aws-sso-profile|X|aws_profile = "default,"
aws-sso-profile|X|AWS_PROFILE=examples
aws-sso-profile|M|AWS_PROFILE=dev
aws-sso-profile|M|AWS_PROFILE=abc
aws-sso-profile|M|AWS_PROFILE=x
aws-sso-profile|X|AWS_PROFILE=
aws-sso-profile|X|the AWS profile is selected externally after SSO login.
aws-sso-profile|X|profile = "some-profile"
machine-serial-number|M|Machine Serial Number: C02ZQ0ABC123
machine-serial-number|M|Machine Serial Number: ABC12345
machine-serial-number|M|Machine Serial Number: ABCDEFG1
machine-serial-number|M|serial_number = "ABC1234Z"
machine-serial-number|M|serial_number = "ABC-12345"
machine-serial-number|M|serial_number := CND1234567
machine-serial-number|M|"SerialNumber": "1A2B3C4D5E"
machine-serial-number|M|SERIAL-NUMBER: pf-2x9k1q
machine-serial-number|M|serial:CND1234567
machine-serial-number|M|machine-serial = abc-123456
machine-serial-number|M|device.serial.number = 9mtxaaaaaa
machine-serial-number|X|serial number: see the underside of the device
machine-serial-number|X|Serial Number: unknown
machine-serial-number|X|Machine Serial Number: ABCDEFGH
machine-serial-number|X|serial_number = each.value.serial
machine-serial-number|X|"serial": 123456789
machine-serial-number|X|serial = 1234567
machine-serial-number|X|serial number: <serial>
machine-serial-number|X|serial number: …
machine-serial-number|X|serial = ABC1234
machine-serial-number|X|serial_number
account-id-context|X|account_id = 12345678901
personal-name|M|Personal Name: Alice Smith
personal-name|M|full_name = "Jean-Pierre Blanc"
personal-name|M|"full_name": "Mary Jane Watson"
personal-name|M|REAL-NAME:=O'Brien Casey
personal-name|M|personalName: Alice Smith
personal-name|M|full name = Jean Pierre Dupont
personal-name|X|Personal Name: the name of the person
personal-name|X|personal_name = <your name>
personal-name|X|name = "Alice Smith"
personal-name|X|full_name: Smith
personal-name|X|full name: Jan Li
personal-name|X|Full Name: Not Applicable
personal-name|X|full_name = "first last"
personal-name|X|personal_name: …
personal-name|X|real_name = var.instance_name
personal-name|X|fullname = each.person.name
windows-username-labeled|M|Windows username: alice.smith
windows-username-labeled|M|Windows user: bob
windows-username-labeled|M|Windows account: bob
windows-username-labeled|M|LocalAccount = alice
windows-username-labeled|M|sAMAccountName: alice.smith
windows-username-labeled|M|logon name: alice
windows-username-labeled|M|username = "svc-win-ci"
windows-username-labeled|M|"UserName": "LocalAdmin1"
windows-username-labeled|M|win_username := alice.smith
windows-username-labeled|M|USER-NAME: svc-win-ci
windows-username-labeled|X|Windows username: the local account
windows-username-labeled|X|username: your
windows-username-labeled|X|username: this
windows-username-labeled|X|username: none
windows-username-labeled|X|username: unknown
windows-username-labeled|X|username: example
windows-username-labeled|X|username = <username>
windows-username-labeled|M|username: bob
windows-username-labeled|M|username: abc
windows-username-labeled|M|username: q
windows-username-labeled|X|username: …
windows-username-labeled|X|User Name: name
windows-username-labeled|X|username
windows-username-labeled|X|user: bob
windows-username-labeled|X|account: bob
windows-username-labeled|X|login name: alice
windows-username-labeled|X|computer account: PC1
hostname-labeled|M|Windows hostname: ALICE-PC
hostname-labeled|M|hostname = "build-runner-01"
hostname-labeled|M|Computer Name: DESKTOP-PC1
hostname-labeled|M|"hostname": "ci-host.example.internal"
hostname-labeled|M|host_name := ALICE-PC
hostname-labeled|M|HOSTNAME=build-runner-01
hostname-labeled|M|Machine Name: ALICE-PC
hostname-labeled|X|hostname: localhost
hostname-labeled|X|hostname: hostname
hostname-labeled|X|hostname: computer
hostname-labeled|X|hostname: name
hostname-labeled|X|computer name: your
hostname-labeled|X|hostname = "example.com"
hostname-labeled|X|hostname = <hostname>
hostname-labeled|M|hostname: PC1
hostname-labeled|M|hostname: abc
hostname-labeled|M|hostname: v
hostname-labeled|X|hostname: …
hostname-labeled|X|hostname
EOF
    {
        printf 'aws-secret-access-key|M|aws_secret_access_key\t=\tEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE\n'
        printf 'aws-activation-code|M|activation_code\t=\tSYNTHETICACTIVATIONCODE01234567\n'
        printf 'aws-session-token|M|aws_session_token\t=\tSYNTHETICSESSIONTOKEN0123456789\n'
        printf 'account-id-context|M|account_id\t=\t123456789012\n'
        printf 'aws-sso-profile|M|aws_profile\t=\tmxprod7\n'
        printf 'machine-serial-number|M|serial_number\t=\tABC12345\n'
        printf 'personal-name|M|personal_name\t=\tAlice Smith\n'
        printf 'windows-username-labeled|M|username\t=\talice.smith\n'
        printf 'hostname-labeled|M|hostname\t=\tbuild-runner-01\n'
    } >>"$ST_WORK/vt-table"
    # Serial interleaving closure, by generation: real serials interleave
    # letters and digits arbitrarily, and a hand-picked value list can
    # silently share one interleaving shape — exactly how `ABCDEFG1` and
    # `ABC1234Z` stayed unfound through three review rounds of positional
    # grammar patches. For every length 8..12: exactly one digit at each
    # position, exactly one letter at each position, a 2-digit block at
    # each position, a 2-letter block at each position (190 must-fire
    # tokens), plus the pure-digit and pure-letter tokens of every length
    # (10 silent tokens: the letter-and-digit property's negative side).
    # The other label detectors' value grammars are FLAT character
    # classes with no positional structure — {35,45} secret keys, {8,}
    # activation codes, {16,} session tokens, the exact 12-digit account
    # run — so hand-picked values crossing each floor suffice there; the
    # account detector additionally gained the 11-digit boundary line
    # above (one short of the run).
    _sv_count=0
    for _sv_len in 8 9 10 11 12; do
        _sv_pos=1
        while [ "$_sv_pos" -le "$_sv_len" ]; do
            st_serial_table_line "$_sv_len" "$_sv_pos" 1 yes M
            st_serial_table_line "$_sv_len" "$_sv_pos" 1 no M
            _sv_pos=$((_sv_pos + 1))
        done
        _sv_pos=1
        while [ "$_sv_pos" -lt "$_sv_len" ]; do
            st_serial_table_line "$_sv_len" "$_sv_pos" 2 yes M
            st_serial_table_line "$_sv_len" "$_sv_pos" 2 no M
            _sv_pos=$((_sv_pos + 1))
        done
        st_serial_table_line "$_sv_len" 1 "$_sv_len" yes X
        st_serial_table_line "$_sv_len" 1 "$_sv_len" no X
    done
    # Length sweep (review round 29, the minimum-length-floor class): the
    # value LENGTH dimension generated, not sampled. The floorless
    # identifier classes (aws-sso-profile, windows-username-labeled,
    # hostname-labeled — floors removed down to the grammatical minimum of
    # one character) sweep 1..12 must-fire; the fixed-floor classes sweep
    # their grammar's boundary (below the floor must stay silent, at and
    # above must fire, including the substring over-run just past the
    # ceiling where one exists); machine-serial-number additionally sweeps
    # pure-digit and pure-letter tokens at, above the floor (the
    # property gate's silent side); personal-name sweeps its two-run shape
    # (run lengths 1..6 squared — must fire exactly when each run is
    # 3-plus and the total is 8-plus). Values follow the SYNTHETIC-KEY
    # CONVENTION: sequential pools, sliced by growing prefixes.
    st_sweep_row() {
        printf '%s|%s|%s "%s"\n' "$1" "$2" "$3" "$4" >>"$ST_WORK/vt-table"
    }
    # st_sweep_grow DET FLAG SPELL POOL FROM TO FLOOR — grow a prefix of
    # POOL one character per length; emit a row per length FROM..TO. The
    # row is X when FLAG is X (detector-side suppression: the serial
    # property gate) or when the length is below FLOOR (FLOOR 0 = no
    # floor); M otherwise.
    st_sweep_grow() {
        _sg_det=$1 _sg_flag_mode=$2 _sg_spell=$3 _sg_pool=$4
        _sg_from=$5 _sg_to=$6 _sg_floor=$7
        _sg_val=
        _sg_i=1
        _sg_full=$_sg_pool
        while [ "$_sg_i" -lt "$_sg_from" ]; do
            _sg_val=${_sg_val}${_sg_pool%"${_sg_pool#?}"}
            _sg_pool=${_sg_pool#?}
            [ -n "$_sg_pool" ] || _sg_pool=$_sg_full
            _sg_i=$((_sg_i + 1))
        done
        while [ "$_sg_i" -le "$_sg_to" ]; do
            _sg_val=${_sg_val}${_sg_pool%"${_sg_pool#?}"}
            _sg_pool=${_sg_pool#?}
            [ -n "$_sg_pool" ] || _sg_pool=$_sg_full
            if [ "$_sg_flag_mode" = X ] ||
                { [ "$_sg_floor" -gt 0 ] && [ "$_sg_i" -lt "$_sg_floor" ]; }; then
                st_sweep_row "$_sg_det" X "$_sg_spell" "$_sg_val"
            else
                st_sweep_row "$_sg_det" M "$_sg_spell" "$_sg_val"
            fi
            _sg_i=$((_sg_i + 1))
        done
    }
    st_sweep_grow aws-sso-profile M 'aws_profile =' abcdefghijkl 1 12 0
    st_sweep_grow windows-username-labeled M 'username =' abcdefghijkl 1 12 0
    st_sweep_grow hostname-labeled M 'hostname =' abcdefghijkl 1 12 0
    st_sweep_grow aws-secret-access-key M 'secret_access_key =' \
        EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE 33 46 35
    st_sweep_grow aws-session-token M 'session_token =' \
        SYNTHETICSESSIONTOKEN0123456789 14 17 16
    st_sweep_grow aws-activation-code M 'activation_code =' \
        SYNTHETICACTIVATIONCODE0123456789 6 9 8
    st_sweep_grow account-id-context M 'account_id =' 1234567890123456 10 13 12
    st_sweep_grow machine-serial-number M 'serial_number =' abc123abc123 6 10 8
    # Pure-digit / pure-letter serial tokens at and above the 8-plus
    # floor: the ERE matches but the serial-property gate must skip them
    # (no digit, or no letter) — the sweep's silent side for the property.
    st_sweep_grow machine-serial-number X 'serial_number =' 1234567890123 8 10 0
    st_sweep_grow machine-serial-number X 'serial_number =' abcdefghijkl 8 10 0
    # personal-name two-run shape: run lengths 1..6 squared, runs grown
    # character by character (the outer run carries across its inner loop).
    _sw_p1=ABCDEF
    _sw_r1=
    _sw_l1=1
    while [ "$_sw_l1" -le 6 ]; do
        _sw_r1=${_sw_r1}${_sw_p1%"${_sw_p1#?}"}
        _sw_p1=${_sw_p1#?}
        _sw_p2=GHIJKL
        _sw_r2=
        _sw_l2=1
        while [ "$_sw_l2" -le 6 ]; do
            _sw_r2=${_sw_r2}${_sw_p2%"${_sw_p2#?}"}
            _sw_p2=${_sw_p2#?}
            if [ "$_sw_l1" -ge 3 ] && [ "$_sw_l2" -ge 3 ] &&
                [ "$((_sw_l1 + _sw_l2))" -ge 8 ]; then
                st_sweep_row personal-name M 'Personal Name:' \
                    "${_sw_r1} ${_sw_r2}"
            else
                st_sweep_row personal-name X 'Personal Name:' \
                    "${_sw_r1} ${_sw_r2}"
            fi
            _sw_l2=$((_sw_l2 + 1))
        done
        _sw_l1=$((_sw_l1 + 1))
    done
    printf '%s\n' "$LABEL_DETECTORS" | sed 's/:.*//' >"$ST_WORK/vt-dets"
    while IFS= read -r _vt_det; do
        [ -n "$_vt_det" ] || continue
        grep "^${_vt_det}|M|" "$ST_WORK/vt-table" | cut -d'|' -f3- \
            >"$ST_WORK/vt-must"
        grep "^${_vt_det}|X|" "$ST_WORK/vt-table" | cut -d'|' -f3- \
            >"$ST_WORK/vt-silent"
        if [ ! -s "$ST_WORK/vt-must" ] || [ ! -s "$ST_WORK/vt-silent" ]; then
            printf 'selftest: FAIL  value table for %s needs both directions\n' \
                "$_vt_det"
            _vt_status=1
            continue
        fi
        st_check "values $_vt_det" "$_vt_det" \
            "$ST_WORK/vt-must" "$ST_WORK/vt-silent" || _vt_status=1
    done <"$ST_WORK/vt-dets"
    return "$_vt_status"
}

# SPEC §27 coverage map. The bullets are parsed out of SPEC.md at
# selftest runtime (st_spec27_map below); this table, kept next to the
# parser, maps every bullet to the detector classes and runtime checks
# that cover it. Mapping choices, including the indirect ones:
#   * "Activation ID" → uuid-literal: the activation ID handed to the
#     SSM register-on-premises-api is a UUID (the uuid fixture documents
#     this); the separately-bulleted managed-instance identifier is the
#     mi-... node ID under its own bullet.
#   * "AWS session tokens" → aws-session-token AND aws-session-key-id:
#     an ASIA... temporary key ID is the key-ID half of the same session
#     credential set the token belongs to.
#   * "SSO profile names" → aws-sso-profile (committed label spellings)
#     and aws-profile-name (the runtime $AWS_PROFILE literal scan).
#   * "hostname" → hostname (the runtime literal check, full and short
#     form, case-insensitive, describing the machine running the audit)
#     AND hostname-labeled (the direct label detector: a labeled hostname
#     in committed content — `Windows hostname: ALICE-PC` — is a finding
#     even when the audit runs on a Unix CI runner that can never see the
#     machine's own hostname; review thread 3888208297).
#   * "Windows username" → username (the runtime whoami literal; on
#     Windows whoami returns the account name), user-home-path
#     (C:\Users\<name> is the committed form of the same identity) and
#     windows-username-labeled (the direct label detector for
#     `Windows username: alice.smith`-style committed content; review
#     thread 3888208297).
#   * "personal name" → personal-name (label detector over the
#     identifying name-field family: personal/full/real name, value
#     anchored on a two-run name shape — see the PERSONAL_NAME notes) and
#     display-name (the runtime GECOS/full-name literal, discovered via
#     id -F / getent and scanned like whoami/hostname). Direct coverage;
#     the email-address and user-home-path classes stay on their own
#     bullets.
#   * "generated real S3 bucket name" → state-bucket-name: the runtime
#     literal taken from terraform/bootstrap/terraform.tfvars.
#   * "Terraform state" → terraform-state-tracked: the DIRECT path-level
#     check, in both passes — any tracked *.tfstate / *.tfstate.* path in
#     the worktree, and any commit whose changed-path list (git show
#     --name-only with the standard exclusions, fail-closed) touches one,
#     so state committed then deleted still fires. account-id-arn and
#     uuid-literal ride along as the content-level backstop: a state
#     file's JSON carries ARNs, account IDs and UUIDs, which catches
#     content even under renamed paths.
#   * "user-specific absolute paths" → user-home-path.
# RUNTIME_CHECK_IDS are the checks default_audit performs outside the
# detector tables (terraform-state-tracked is path-level in both passes;
# display-name is the runtime GECOS literal — both runtime-value checks
# are machine-dependent and therefore documented as untestable by the
# selftest, in the same note pattern as whoami/hostname).
SPEC27_MAP='Activation Code|aws-activation-code
Activation ID|uuid-literal
AWS access-key IDs|aws-access-key-id
AWS secret keys|aws-secret-access-key
AWS session tokens|aws-session-token aws-session-key-id
SSO profile names|aws-sso-profile aws-profile-name
SSO URLs|sso-start-url
AWS account ID|account-id-context account-id-arn
managed-node ID|managed-node-id
hostname|hostname hostname-labeled
Windows username|username user-home-path windows-username-labeled
personal name|personal-name display-name
email address|email-address
machine serial numbers|machine-serial-number
generated real S3 bucket name|state-bucket-name
Terraform state|terraform-state-tracked account-id-arn uuid-literal
user-specific absolute paths|user-home-path'
RUNTIME_CHECK_IDS='hostname username state-bucket-name aws-profile-name terraform-state-tracked display-name'

st_spec27_map() {
    _s27_status=0
    _s27_spec="$ROOT/SPEC.md"
    if [ ! -f "$_s27_spec" ]; then
        printf 'selftest: FAIL  SPEC.md not found for §27 coverage map: %s\n' \
            "$_s27_spec"
        return 1
    fi
    # Extract §27's bullet list: from the section heading to the next
    # heading; strip the bullet marker and one trailing period. A SPEC
    # renumbering or rewrite fails here, on purpose: the map must be
    # revisited when §27 changes.
    awk '
        /^# 27\. Repository audit/ {f=1; next}
        f && /^# / {exit}
        f && /^\* / {s=$0; sub(/^\* /, "", s); sub(/\.$/, "", s); print s}
    ' "$_s27_spec" >"$ST_WORK/s27-bullets"
    if [ ! -s "$ST_WORK/s27-bullets" ]; then
        printf 'selftest: FAIL  no §27 bullet list found in SPEC.md (section renamed or restructured? the coverage map must be revisited)\n'
        return 1
    fi
    printf '%s\n' "$SPEC27_MAP" >"$ST_WORK/s27-map"
    _s27_dets=$(printf '%s\n%s\n' "$LABEL_DETECTORS" "$SHAPE_DETECTORS" |
        sed 's/:.*//')
    # tr: an assignment keeps embedded newlines (no field splitting in
    # assignments), and the membership tests below match on single
    # spaces.
    _s27_valid=" $(printf '%s\n%s\n' "$_s27_dets" "$RUNTIME_CHECK_IDS" |
        tr '\n' ' ')"
    _s27_used=" $(awk -F'|' '{print $2}' "$ST_WORK/s27-map" | tr '\n' ' ')"
    # Direction 1: every §27 bullet maps to at least one existing class.
    while IFS= read -r _s27_bullet; do
        [ -n "$_s27_bullet" ] || continue
        _s27_ids=$(awk -F'|' -v b="$_s27_bullet" '$1 == b {print $2}' \
            "$ST_WORK/s27-map")
        if [ -z "$_s27_ids" ]; then
            printf 'selftest: FAIL  §27 bullet has no coverage mapping: "%s"\n' \
                "$_s27_bullet"
            _s27_status=1
            continue
        fi
        for _s27_id in $_s27_ids; do
            case "$_s27_valid" in
            *" $_s27_id "*) ;;
            *)
                printf 'selftest: FAIL  §27 mapping for "%s" names unknown class "%s"\n' \
                    "$_s27_bullet" "$_s27_id"
                _s27_status=1
                ;;
            esac
        done
    done <"$ST_WORK/s27-bullets"
    # Direction 2: every detector class and runtime check is some
    # bullet's coverage — a detector without a §27 anchor is drift too.
    for _s27_id in $_s27_dets $RUNTIME_CHECK_IDS; do
        case "$_s27_used" in
        *" $_s27_id "*) ;;
        *)
            printf 'selftest: FAIL  class "%s" maps to no §27 bullet\n' "$_s27_id"
            _s27_status=1
            ;;
        esac
    done
    if [ "$_s27_status" -eq 0 ]; then
        printf 'selftest: PASS  %-44s %s bullets mapped to %s class ids\n' \
            'SPEC §27 coverage map' \
            "$(grep -c . "$ST_WORK/s27-bullets")" \
            "$(printf '%s\n' "$SPEC27_MAP" | wc -l | tr -d ' ')"
    fi
    return "$_s27_status"
}

# st_hook_smoke — the --scan-file CLI hook (see header) exists so test
# harnesses drive the real engine; exercise the CLI path once so it
# cannot rot: a finding line for a synthetic AKIA, exit 0 always, and a
# missing file yields no findings, still exit 0.
st_hook_smoke() {
    if [ ! -x "$ROOT/scripts/audit.sh" ]; then
        printf 'selftest: FAIL  %s is not executable (the --scan-file hook must be runnable)\n' \
            'scripts/audit.sh'
        return 1
    fi
    printf 'variable = "AKIAQRSTUVWXYZHIJKLMNOP"\nplain line\n' \
        >"$ST_WORK/hook.txt"
    "$ROOT/scripts/audit.sh" --scan-file hook-smoke "$ST_WORK/hook.txt" \
        >"$ST_WORK/hook.out" 2>/dev/null
    _hk_rc=$?
    _hk_want='FINDING hook-smoke:1: aws-access-key-id'
    _hk_got=$(grep -c . "$ST_WORK/hook.out")
    if [ "$_hk_rc" -ne 0 ] || [ "$_hk_got" -ne 1 ] ||
        [ "$(sed -n 1p "$ST_WORK/hook.out")" != "$_hk_want" ]; then
        printf 'selftest: FAIL  --scan-file hook: rc=%s output=%s lines (want rc=0 and exactly %s)\n' \
            "$_hk_rc" "$_hk_got" "$_hk_want"
        sed 's/^/         /' "$ST_WORK/hook.out" | head -n 3
        return 1
    fi
    "$ROOT/scripts/audit.sh" --scan-file hook-smoke "$ST_WORK/no-such-file" \
        >"$ST_WORK/hook2.out" 2>/dev/null
    _hk_rc=$?
    if [ "$_hk_rc" -ne 0 ] || [ -s "$ST_WORK/hook2.out" ]; then
        printf 'selftest: FAIL  --scan-file hook on missing file: rc=%s (want 0) and output must be empty\n' \
            "$_hk_rc"
        return 1
    fi
    printf 'selftest: PASS  %-44s findings printed, exit 0 always\n' \
        '--scan-file hook'
    return 0
}

# st_tfstate_checks — end-to-end scratch-repo test of BOTH Terraform-state
# path checks (review threads 3887975424 and 3888113063): a scratch git
# repository is built with (a) a MINIMAL state file still TRACKED — its
# content trips no content detector, so only the path-level check can
# catch it — and (b) an old.tfstate committed and then DELETED, so only
# the history changed-path check can catch it. The full default audit is
# run in the scratch repo; both findings must appear and the audit must
# exit 1. This drives default_audit itself, not scan_file: the path-level
# check lives in the audit's enumeration loops (the tracked-file loop and
# scan_history), which is exactly why a content-only reproduction through
# scan_file shows nothing. The scratch repo is cleaned without rm -rf
# (files first, then directories deepest-first).
st_tfstate_checks() {
    if ! command -v git >/dev/null 2>&1; then
        printf 'selftest: FAIL  git unavailable: cannot build the tfstate scratch repo\n'
        return 1
    fi
    _ts_dir=$(mktemp -d "${TMPDIR:-/tmp}/audit-selftest-tfstate.XXXXXXXX") || {
        printf 'selftest: FAIL  cannot create tfstate scratch directory\n'
        return 1
    }
    mkdir -p "$_ts_dir/scripts" || {
        printf 'selftest: FAIL  cannot populate tfstate scratch directory\n'
        find "$_ts_dir" -type f -exec rm -f {} + 2>/dev/null
        rmdir "$_ts_dir" 2>/dev/null
        return 1
    }
    cp -- "$ROOT/scripts/audit.sh" "$_ts_dir/scripts/audit.sh" || {
        printf 'selftest: FAIL  cannot copy audit.sh into the scratch repo\n'
        find "$_ts_dir" -type f -exec rm -f {} + 2>/dev/null
        rmdir "$_ts_dir" 2>/dev/null
        return 1
    }
    # A commit identity is required; scope it to these invocations only.
    _ts_git() {
        git -C "$_ts_dir" -c user.email=selftest@invalid \
            -c user.name='Self Test' "$@"
    }
    _ts_git init -q >/dev/null 2>&1 || {
        printf 'selftest: FAIL  git init failed in the scratch repo\n'
        find "$_ts_dir" -type f -exec rm -f {} + 2>/dev/null
        rmdir "$_ts_dir" 2>/dev/null
        return 1
    }
    printf 'note\n' >"$_ts_dir/note.txt"
    printf '{"version":4,"serial":1,"outputs":{},"resources":[]}\n' \
        >"$_ts_dir/old.tfstate"
    printf '{"version":4,"serial":1,"outputs":{},"resources":[]}\n' \
        >"$_ts_dir/minimal.tfstate"
    _ts_git add -A note.txt scripts >/dev/null 2>&1
    _ts_git add -f old.tfstate minimal.tfstate >/dev/null 2>&1
    _ts_git commit -qm 'add minimal state' >/dev/null 2>&1
    _ts_git rm -q old.tfstate >/dev/null 2>&1
    _ts_git commit -qm 'remove old state' >/dev/null 2>&1
    bash "$_ts_dir/scripts/audit.sh" >"$_ts_dir/audit.out" 2>&1
    _ts_rc=$?
    _ts_ok=yes
    [ "$_ts_rc" -eq 1 ] || _ts_ok=no
    grep -q 'FINDING minimal.tfstate: terraform-state-tracked' \
        "$_ts_dir/audit.out" || _ts_ok=no
    grep -q 'old.tfstate: terraform-state-tracked' \
        "$_ts_dir/audit.out" || _ts_ok=no
    if [ "$_ts_ok" != yes ]; then
        printf 'selftest: FAIL  tfstate path checks: rc=%s (want 1); tracked-path and history-path findings both expected\n' \
            "$_ts_rc"
        sed 's/^/         /' "$_ts_dir/audit.out" | head -n 5
        find "$_ts_dir" -type f -exec rm -f {} + 2>/dev/null
        find "$_ts_dir" -depth -type d -exec rmdir {} + 2>/dev/null
        return 1
    fi
    printf 'selftest: PASS  %-44s tracked + history minimal-state paths\n' \
        'terraform-state-tracked'
    find "$_ts_dir" -type f -exec rm -f {} + 2>/dev/null
    find "$_ts_dir" -depth -type d -exec rmdir {} + 2>/dev/null
    return 0
}

# st_message_file — exercise the --message-file pre-commit gate, in the
# same style as st_hook_smoke: a synthetic tripping message must produce
# named findings and exit 1 — including a line that carries the
# suppression marker, because UNCOMMITTED text cannot be annotated — and
# a clean message must produce none and exit 0. The clean sample includes
# the allowlisted commit-trailer address on purpose: the allowlist must
# apply in message mode too, or every real trailer would trip the email
# detector.
st_message_file() {
    if [ ! -x "$ROOT/scripts/audit.sh" ]; then
        printf 'selftest: FAIL  %s is not executable (the --message-file gate must be runnable)\n' \
            'scripts/audit.sh'
        return 1
    fi
    cat >"$ST_WORK/msg-bad.txt" <<'EOF'
fix: example change quoting the values it describes

AWS_PROFILE=production
secret_access_key = EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE # audit-allow:synthetic
variable = "AKIAQRSTUVWXYZHIJKLMNOP"
EOF
    "$ROOT/scripts/audit.sh" --message-file "$ST_WORK/msg-bad.txt" \
        >"$ST_WORK/msg-bad.out" 2>/dev/null
    _mf_rc=$?
    _mf_ok=yes
    [ "$_mf_rc" -eq 1 ] || _mf_ok=no
    for _mf_cls in aws-sso-profile aws-secret-access-key aws-access-key-id; do
        grep -q ": ${_mf_cls}\$" "$ST_WORK/msg-bad.out" || _mf_ok=no
    done
    if [ "$_mf_ok" != yes ]; then
        printf 'selftest: FAIL  --message-file gate: rc=%s (want 1) with named findings for the profile, secret-key and key-ID classes\n' \
            "$_mf_rc"
        sed 's/^/         /' "$ST_WORK/msg-bad.out" | head -n 4
        return 1
    fi
    cat >"$ST_WORK/msg-good.txt" <<'EOF'
fix: rotate the enrollment documentation

Explains the activation flow without quoting any credential material.
The noreply@anthropic.com trailer footer is allowlisted.

Co-Authored-By: Claude Code <noreply@anthropic.com>
EOF
    "$ROOT/scripts/audit.sh" --message-file "$ST_WORK/msg-good.txt" \
        >"$ST_WORK/msg-good.out" 2>/dev/null
    _mf_rc=$?
    if [ "$_mf_rc" -ne 0 ] || grep -q '^FINDING' "$ST_WORK/msg-good.out"; then
        printf 'selftest: FAIL  --message-file gate on clean message: rc=%s (want 0) and no FINDING records\n' \
            "$_mf_rc"
        sed 's/^/         /' "$ST_WORK/msg-good.out" | head -n 4
        return 1
    fi
    printf 'selftest: PASS  %-44s tripping message fails, clean passes\n' \
        '--message-file gate'
    return 0
}

# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

usage() {
    printf 'usage: scripts/%s [--selftest] [--scan-file NAME PATH] [--message-file FILE]\n' \
        "$SCRIPT_NAME" >&2
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
    _profile=${AWS_PROFILE-}
    # Display name (SPEC §27 "personal name", runtime carrier): the
    # GECOS/full-name field of this account, discovered portably — macOS
    # `id -F` first, Linux `getent passwd` field 5 (first comma segment;
    # GECOS carries office/phone after it) when that yields nothing. Like
    # the username, the discovered value is a REAL identifying value that
    # must never be committed, so its literal is scanned through files and
    # history (case-insensitively, like the hostname — a lowercased leak is
    # still a leak) and the finding class display-name is never
    # suppressible (NEVER_SUPPRESSED). Guards, in the whoami/hostname
    # discipline: empty and failed discoveries are silent skips (the
    # platform exposes no name), and a value that is not NAME-SHAPED (not
    # two-plus word runs totalling 8-plus — e.g. a bare username echoed
    # back) is skipped with a note, because the personal-name LABEL
    # detector's own value anchor uses exactly that shape and a non-shaped
    # display value carries no name to leak. Like whoami/hostname, this is
    # a runtime value the selftest cannot pin — it differs per machine.
    _display=$(id -F 2>/dev/null) || _display=
    if [ -z "$_display" ] && command -v getent >/dev/null 2>&1; then
        _display=$(getent passwd "$(id -un 2>/dev/null)" 2>/dev/null |
            cut -d: -f5 | cut -d, -f1) || _display=
    fi
    if [ -n "$_display" ]; then
        if ! printf '%s' "$_display" | grep -qE -- "$PERSONAL_NAME_VALUE"; then
            printf 'audit: note: skipping display-name check: value is not name-shaped (two-plus word runs, 8-plus chars)\n'
            _display=
        fi
    fi

    case "$GENERIC_USERS" in
    *" $_user "*)
        printf 'audit: note: skipping username check for generic CI/user name "%s"\n' "$_user"
        _user=
        ;;
    esac
    # Hostname: also checked case-insensitively; very short values are noise.
    [ ${#_host} -ge 4 ] 2>/dev/null || _host=
    [ ${#_host_short} -ge 4 ] 2>/dev/null || _host_short=
    # AWS_PROFILE: the SSO profile this machine selects. Guarded like the
    # username: the literal scan substring-matches, so a value that is
    # exactly one of GENERIC_PROFILES (`default`, `test` — words naming the
    # slot, not a profile, and appearing in this repository's own prose) is
    # skipped, while every other 2-plus name is scanned, letter-only or not
    # — the same rule and set the aws-sso-profile label detector's
    # generic-value gate applies.
    if [ -n "$_profile" ]; then
        _profile_lc=$(printf '%s' "$_profile" | tr '[:upper:]' '[:lower:]')
        case "$GENERIC_PROFILES" in
        *" $_profile_lc "*)
            printf 'audit: note: skipping AWS_PROFILE check for generic profile name "%s"\n' "$_profile"
            _profile=
            ;;
        esac
        # Minimum length for the RUNTIME scan is 2, not the label
        # detector's 1: this is a fixed-substring scan over every file and
        # every patch, and a 1-character needle matches essentially every
        # line — that is not over-detection, it is breakage. A 1-character
        # profile in COMMITTED content is still caught by the aws-sso-profile
        # label detector, whose value floor is the grammatical minimum.
        [ ${#_profile} -ge 2 ] 2>/dev/null || _profile=
    fi

    # 1. Tracked files. The list is captured BEFORE the loop and its failure
    # is fatal, in the same style as `git rev-list` inside scan_history:
    # piping a failing `git ls-files` straight into the loop would leave it
    # iterating over ZERO files while default_audit still reported "tracked
    # files and full history scanned" — a false clean over an unreadable
    # index or a failing git.
    _files=$(mktemp "${TMPDIR:-/tmp}/audit-tracked.XXXXXXXX") || {
        rm -f "$_results"
        printf '%s: error: cannot create tracked-file list temp file (TMPDIR writable? disk full?) - failing closed\n' \
            "$SCRIPT_NAME" >&2
        exit 2
    }
    if ! tracked_files "$_files"; then
        rm -f "$_files" "$_results"
        printf '%s: error: git ls-files failed (unreadable index or failing git?) - failing closed, no clean result\n' \
            "$SCRIPT_NAME" >&2
        exit 1
    fi
    # Each file is opened via $ROOT/<path> so the audit works from any
    # cwd; findings keep the repo-relative name as their label. The literal
    # scans run over the SAME content the detectors scan: effective_scan_path
    # decides once per file — plain text scans as itself, a UTF-16 file as
    # its decoded form — so a decoded file is not a blind spot for the
    # runtime values either; an undecodable file has already failed closed.
    # _scan snapshots that one decision (scan_file re-runs it as a no-op on
    # the already-effective path) and the decoded temp is dropped after the
    # file's scans, never leaking across iterations.
    while IFS= read -r _f; do
        [ -n "$_f" ] || continue
        [ -f "$ROOT/$_f" ] || continue
        # Path-level Terraform-state prohibition (SPEC §27 "Terraform
        # state"; see header): state must never be tracked at all, so the
        # path itself is the finding — .gitignore already excludes these,
        # and this fails closed if one is ever added anyway. The marker
        # cannot suppress it: a state file is never synthetic, and the
        # finding names a path, not a line.
        case "$_f" in
        *.tfstate | *.tfstate.*)
            printf 'FINDING %s: terraform-state-tracked (Terraform state is committed - SPEC §27; remove it from the index and purge history)\n' \
                "$_f"
            ;;
        esac
        effective_scan_path "$ROOT/$_f" "$_f"
        _scan=$EFFECTIVE_PATH
        [ -n "$_scan" ] || continue
        scan_file "$_scan" "$_f"
        scan_literal state-bucket-name "$_f" "$_scan" "$_bucket"
        scan_literal username "$_f" "$_scan" "$_user"
        scan_literal hostname "$_f" "$_scan" "$_host" ic
        scan_literal hostname "$_f" "$_scan" "$_host_short" ic
        scan_literal aws-profile-name "$_f" "$_scan" "$_profile"
        scan_literal display-name "$_f" "$_scan" "$_display" ic
        drop_scan_temp "$_scan" "$ROOT/$_f"
    done <"$_files" >"$_results"
    rm -f "$_files"

    # 2. Full history (message bodies and patches). The guarded runtime
    # values pass through so history gets the same literal scans the
    # tracked-file loop above applies.
    scan_history "$_bucket" "$_user" "$_host" "$_host_short" "$_profile" \
        "$_display" >>"$_results"

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

# message_file_audit FILE — run the full detection engine (every label and
# shape detector) over a PROPOSED commit-message file, report findings,
# exit 1 on any. This is the pre-commit gate for message text: the default
# audit scans commit message bodies too, but only AFTER the commit exists,
# when fixing means history surgery — twice already a commit quoted a
# detector-tripping value in its body (synthetic or not) and the audit went
# red only afterwards, leaving marker-annotated equivalence lines as the
# cleanup. Checking the message BEFORE committing makes that class of
# self-inflicted finding impossible to create. Two deliberate differences
# from the default audit:
#   * the marker and history-equivalence suppressions are OFF
#     (MARKER_GATE_OFF in emit_hits): uncommitted text has no standing
#     annotations, so a tripping line must be REWORDED, not annotated —
#     including hard-rule classes and suppressible ones alike;
#   * the runtime per-machine value checks are skipped: whoami/hostname/
#     bucket/profile literals describe THIS machine, not text on its way
#     into history, and the audit proper re-checks the committed message
#     against them anyway.
message_file_audit() {
    _mf_file=$1
    if [ ! -f "$_mf_file" ]; then
        printf '%s: error: --message-file: no such file: %s\n' \
            "$SCRIPT_NAME" "$_mf_file" >&2
        exit 2
    fi
    _mf_out=$(mktemp "${TMPDIR:-/tmp}/audit-message.XXXXXXXX") || {
        printf '%s: error: cannot create message temp file (TMPDIR writable? disk full?) - failing closed\n' \
            "$SCRIPT_NAME" >&2
        exit 2
    }
    MARKER_GATE_OFF=yes
    scan_stream 'commit-message' "$_mf_file" >"$_mf_out"
    MARKER_GATE_OFF=
    if [ -s "$_mf_out" ]; then
        printf 'message: FAIL - %s finding(s) in %s (reword the message; uncommitted text cannot be annotated)\n' \
            "$(grep -c . "$_mf_out")" "$_mf_file"
        cat "$_mf_out"
        rm -f "$_mf_out"
        exit 1
    fi
    printf 'message: clean (no detector findings in %s)\n' "$_mf_file"
    rm -f "$_mf_out"
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
        sed 's/:.*//'); do
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
    # finding (a), and a real AWS key-ID shape (b) or a session-token
    # assignment clearing its 16-plus value anchor (c) carrying the marker
    # must STILL be detected — the hard rule in the header.
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

    _rel="$FIXTURE_DIR/marker-ignored-session-token.txt"
    if [ ! -f "$ROOT/$_rel" ]; then
        printf 'selftest: FAIL  %-44s fixture missing\n' "$_rel"
        _status=1
    elif printf '%s\n' "$_found" |
        grep -q "^FINDING $_rel:[0-9]*: aws-session-token\$"; then
        printf 'selftest: PASS  %-44s session token still detected with marker\n' "$_rel"
    else
        printf 'selftest: FAIL  %-44s session token not detected with marker\n' "$_rel"
        _status=1
    fi

    # Generative spelling matrix, per-detector value must/must-not
    # tables, and the SPEC §27 coverage map (see the harness section
    # above). Scratch space first; allocation failure fails closed.
    ST_WORK=$(mktemp -d "${TMPDIR:-/tmp}/audit-selftest.XXXXXXXX") || {
        printf '%s: error: cannot create selftest scratch directory (TMPDIR writable? disk full?)\n' \
            "$SCRIPT_NAME" >&2
        exit 2
    }
    st_label_matrix || _status=1
    st_shape_matrix || _status=1
    st_value_tables || _status=1
    st_spec27_map || _status=1
    st_tfstate_checks || _status=1
    st_hook_smoke || _status=1
    st_message_file || _status=1
    rm -f "$ST_WORK"/* 2>/dev/null
    rmdir "$ST_WORK" 2>/dev/null
    ST_WORK=

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
--scan-file)
    # Internal test hook (see header): full engine over one file, standard
    # exclusions, FINDING lines on stdout, exit 0 regardless of findings.
    [ "$#" -eq 3 ] || usage
    if [ ! -f "$3" ]; then
        printf '%s: error: --scan-file: no such file: %s\n' \
            "$SCRIPT_NAME" "$3" >&2
        exit 0
    fi
    scan_file "$3" "$2"
    exit 0
    ;;
--message-file)
    # Pre-commit gate for commit-message text (see header): full engine,
    # no marker suppression, exit 1 on any finding.
    [ "$#" -eq 2 ] || usage
    message_file_audit "$2"
    ;;
-h | --help)
    printf 'usage: scripts/%s [--selftest] [--scan-file NAME PATH] [--message-file FILE]\n' \
        "$SCRIPT_NAME"
    exit 0
    ;;
*)
    printf '%s: error: unknown argument: %s\n' "$SCRIPT_NAME" "$1" >&2
    usage
    ;;
esac
