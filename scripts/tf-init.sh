#!/bin/sh
# tf-init.sh — build (and with -n, print) the `terraform init` command that
# points a stack at the shared S3 backend (SPEC §13, Plan T6).
#
# Usage:
#   scripts/tf-init.sh <bootstrap|infrastructure> [-n]
#
#     stack   bootstrap | infrastructure
#     -n      print the exact command line (single line, space-separated
#             arguments) without running it; without -n the command is exec'd
#
# Inputs (environment):
#   AWS_REGION         AWS region (preferred)
#   AWS_DEFAULT_REGION used when AWS_REGION is unset
#                      A region is required: it goes into the backend config
#                      and is what makes the state bucket addressable.
#   TFVARS_FILE        tfvars file to read bucket_name from
#                      (default: terraform/bootstrap/terraform.tfvars,
#                      which is the user's untracked real file)
#
# Behaviour:
#   state key      <stack>/terraform.tfstate
#   -migrate-state appended only when terraform/<stack>/terraform.tfstate
#                  exists locally (the bootstrap local-state migration case)
#   use_lockfile   native S3 state locking is always requested

set -u

SCRIPT_NAME=tf-init.sh

usage() {
    printf 'usage: scripts/%s <bootstrap|infrastructure> [-n]\n' "$SCRIPT_NAME" >&2
    exit 2
}

die() {
    printf '%s: error: %s\n' "$SCRIPT_NAME" "$1" >&2
    exit "${2:-1}"
}

# --- arguments ---------------------------------------------------------------

STACK=
DRY_RUN=0

while [ $# -gt 0 ]; do
    case "$1" in
    -n | --dry-run)
        DRY_RUN=1
        ;;
    -h | --help)
        printf 'usage: scripts/%s <bootstrap|infrastructure> [-n]\n' "$SCRIPT_NAME"
        exit 0
        ;;
    -*)
        printf '%s: error: unknown option: %s\n' "$SCRIPT_NAME" "$1" >&2
        usage
        ;;
    *)
        if [ -n "$STACK" ]; then
            printf '%s: error: unexpected extra argument: %s\n' "$SCRIPT_NAME" "$1" >&2
            usage
        fi
        STACK=$1
        ;;
    esac
    shift
done

if [ -z "$STACK" ]; then
    printf '%s: error: missing stack argument\n' "$SCRIPT_NAME" >&2
    usage
fi

case "$STACK" in
bootstrap | infrastructure) ;;
*)
    printf '%s: error: unknown stack: %s (expected bootstrap or infrastructure)\n' \
        "$SCRIPT_NAME" "$STACK" >&2
    usage
    ;;
esac

# --- repository root (script lives in <root>/scripts) ------------------------

SELF_DIR=$(dirname -- "$0") || die 'cannot locate repository root'
ROOT=$(CDPATH=; cd -- "$SELF_DIR/.." && pwd) || die 'cannot locate repository root'

# --- region ------------------------------------------------------------------

REGION=${AWS_REGION-}
if [ -z "$REGION" ]; then
    REGION=${AWS_DEFAULT_REGION-}
fi
if [ -z "$REGION" ]; then
    die 'AWS_REGION (or AWS_DEFAULT_REGION) is not set; a region is required for the S3 backend config'
fi

# --- bucket from tfvars ------------------------------------------------------

if [ -n "${TFVARS_FILE-}" ]; then
    TFVARS=$TFVARS_FILE
else
    TFVARS=$ROOT/terraform/bootstrap/terraform.tfvars
fi

if [ ! -f "$TFVARS" ]; then
    die "tfvars file not found: $TFVARS (set TFVARS_FILE or create it)"
fi

# First bucket_name assignment, with surrounding quotes stripped.
BUCKET=$(sed -n 's/^[[:space:]]*bucket_name[[:space:]]*=[[:space:]]*"\([^"]*\)".*$/\1/p' "$TFVARS" | head -n 1)
if [ -z "$BUCKET" ]; then
    BUCKET=$(sed -n "s/^[[:space:]]*bucket_name[[:space:]]*=[[:space:]]*'\([^']*\)'.*$/\1/p" "$TFVARS" | head -n 1)
fi
if [ -z "$BUCKET" ]; then
    BUCKET=$(sed -n 's/^[[:space:]]*bucket_name[[:space:]]*=[[:space:]]*\([A-Za-z0-9._-][A-Za-z0-9._-]*\).*$/\1/p' "$TFVARS" | head -n 1)
fi
if [ -z "$BUCKET" ]; then
    die "no bucket_name assignment found in $TFVARS"
fi

# --- command -----------------------------------------------------------------

set -- terraform -chdir="terraform/$STACK" init \
    -backend-config="bucket=$BUCKET" \
    -backend-config="key=$STACK/terraform.tfstate" \
    -backend-config="region=$REGION" \
    -backend-config="use_lockfile=true"

# Only offer migration when there is local state to migrate.
if [ -f "$ROOT/terraform/$STACK/terraform.tfstate" ]; then
    set -- "$@" -migrate-state
fi

if [ "$DRY_RUN" -eq 1 ]; then
    printf '%s\n' "$*"
    exit 0
fi

exec "$@"
