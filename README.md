# aws-pc-mgr

Reproducibly configure a personal Windows 11 machine as an AWS Systems Manager
(SSM) **hybrid managed node**, using outbound connections only.

The repository contains: Terraform for all AWS-side infrastructure (including
the S3 backend that holds Terraform state), a PowerShell setup script for the
Windows machine, a read-only diagnostic script, and the tests and audit tooling
that keep the repository free of secrets and identifying information.

The managed machine is outside AWS. Nothing here requires inbound firewall
rules, router port forwarding, a VPN, a public IP address, or exposing RDP,
SSH, PowerShell Remoting, or any other management port to the Internet.

## Contents

1. [Overview and architecture](#overview-and-architecture)
2. [Windows 11 is not AWS-supported](#windows-11-is-not-aws-supported)
3. [Prerequisites](#prerequisites)
4. [State bucket tfvars setup](#state-bucket-tfvars-setup)
5. [Bootstrap workflow](#bootstrap-workflow)
6. [Windows enrollment: setup.ps1](#windows-enrollment-setupps1)
7. [Diagnostics: check.ps1](#diagnostics-checkps1)
8. [Activation lifecycle](#activation-lifecycle)
9. [Destruction and deregistration](#destruction-and-deregistration)
10. [Pricing note: Session Manager and Run Command](#pricing-note-session-manager-and-run-command)
11. [Windows 11 compatibility record](#windows-11-compatibility-record)
12. [Repository hygiene: audit, tf-init, tests, CI](#repository-hygiene-audit-tf-init-tests-ci)
13. [Security properties](#security-properties)

---

## Overview and architecture

Three components are involved:

```text
        Terraform runner
        ================
        Arbitrary OS

        Terraform
        AWS credentials from normal
        AWS credential discovery
               |
               v
        +-------------+
        |     AWS     |
        |             |
        | S3 backend  |
        | IAM role    |
        | SSM         |
        | activation  |
        +------+------+
               |
               | SSM hybrid registration
               |
               v
        Windows 11 machine
        ==================
            SSM Agent
               |
        managed-node IAM role
               |
        AWS-issued temporary
           credentials
```

**Terraform runner** — any machine or OS that can run Terraform. Its only
responsibilities are: obtain the repository, have AWS authentication available
(the normal AWS SDK credential resolution chain, typically an externally
selected `AWS_PROFILE` after an SSO login), run Terraform, and retrieve the
temporary SSM activation values needed for the one-time Windows enrollment.
**The Terraform runner has no ongoing role** once Terraform has applied: it is
not a management workstation, it performs no ongoing administration of the
Windows machine, and its SSO session expiring changes nothing about how the
Windows machine is managed. The Terraform runner and the Windows machine never
share credentials.

**AWS** — the S3 bucket that persists Terraform state (encrypted, versioned,
public-access-blocked, natively locked), the IAM role the managed node assumes,
the single-registration SSM hybrid activation used to enroll the machine, and
Systems Manager itself (Run Command, Session Manager).

**Windows 11 machine** — the managed machine. It runs SSM Agent, holds no AWS
SSO configuration and no static AWS credentials of any kind, and reaches AWS
through outbound HTTPS only. Initial registration needs only an AWS region, an
SSM Activation ID, and an SSM Activation Code; afterwards SSM Agent maintains
the hybrid managed-node identity and rotates the AWS-issued temporary
credentials for the attached role itself. The machine stays manageable with no
AWS user logged in.

Repository layout:

```text
terraform/bootstrap/        S3 state bucket (+ its own tests, tfvars example)
terraform/infrastructure/   managed-node IAM role + SSM activation (+ tests)
scripts/tf-init.sh          builds the `terraform init` command for either stack
scripts/audit.sh            secret/identifier audit of files and full history
scripts/windows/SSMHybrid.psm1  shared decision logic (unit-tested)
scripts/windows/setup.ps1   enrollment entry script (Windows, elevated)
scripts/windows/check.ps1   read-only diagnostics (Windows)
tests/unit/                 Pester unit tests for SSMHybrid.psm1
tests/windows/              on-machine Pester tests for the entry scripts
tests/tf-init.test.sh       contract test for tf-init.sh
tests/fixtures/             synthetic audit fixtures + tfvars fixture
.github/workflows/ci.yml    CI (three jobs; see below)
```

## Windows 11 is not AWS-supported

AWS does not officially list Windows 11 as a supported operating system for
SSM hybrid managed nodes; its supported Windows platforms are Windows Server
editions. Real-world reports indicate SSM Agent installs, registers, and
provides core SSM functionality on Windows 11 anyway. Therefore:

> **Windows 11 is an intentionally tested but AWS-unsupported configuration.**

In practice that means:

* Windows 11 is never disguised as Windows Server, and nothing works around OS
  detection; the normal AWS hybrid-node registration mechanism is used as-is.
* Every piece of required functionality is tested on the actual Windows 11
  machine rather than assumed from Windows Server documentation. See the
  [compatibility record](#windows-11-compatibility-record); until the
  on-machine validation battery has run, Windows-side behavior is **pending
  validation**.
* Nothing depends on SSM functionality known to require Windows Server-specific
  components, and no Windows Server role/feature management or
  Server-specific SSM documents are used.

## Prerequisites

* **Terraform >= 1.11** on the Terraform runner (native S3 state locking via
  `use_lockfile`). The AWS provider constraint is `~> 6.62`;
  `.terraform.lock.hcl` is committed for both stacks, `.terraform/` is not.
* **AWS credentials via the normal SDK chain** on the Terraform runner. The
  expected normal case is an AWS IAM Identity Center / SSO profile selected
  externally after login, e.g. `AWS_PROFILE=<profile>`. No profile name, start
  URL, or key material is committed anywhere, and Terraform is never given a
  `profile` in provider or backend configuration — any standard credential
  provider works.
* **An AWS region** for the work, exported as `AWS_REGION` (or
  `AWS_DEFAULT_REGION`); `scripts/tf-init.sh` requires it and the provider
  picks it up from the environment too. `ap-southeast-2` is used below as a
  generic example region — substitute your own.
* **A Windows 11 machine** with outbound HTTPS access to AWS.
* **PowerShell 5.1 or later**, elevated ("Run as administrator"), for the
  Windows setup. No AWS CLI, AWS SSO, `AWS_PROFILE`, or Terraform is needed on
  the Windows machine.
* **git** (or another way to get this repository onto both machines).

## State bucket tfvars setup

Terraform cannot use an S3 backend before the bucket exists, so the bootstrap
stack (temporary local state) creates it. The bucket name is a variable you
supply through an **untracked** tfvars file:

```sh
cd terraform/bootstrap
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` and replace `replaceme` with a **globally unique,
generic** suffix:

```hcl
bucket_name = "win11-ssm-tfstate-<generated-suffix>"
```

Naming rules (enforced by a variable validation):

* 3–63 characters: lowercase letters, digits, hyphens;
* must start and end with a letter or digit; no leading/trailing/double hyphen;
* no S3-reserved forms: `sthree-` or `amzn-s3-demo-` prefixes, `-s3alias`
  suffix (CreateBucket rejects these — validation catches them up front);
* globally unique across all of AWS S3.

The name **must not contain identifying information**: no person's name,
username, hostname, email, or AWS account ID. S3 bucket names are world-visible
in DNS records; pick a random generic suffix. `terraform.tfvars` is git-ignored
(`*.tfvars`) — the real bucket name exists in AWS and in Terraform state, never
in committed source. The `scripts/audit.sh` scanner treats the bucket name in
your local untracked tfvars as a runtime value: if it ever appears in a tracked
file or in history, the audit fails.

## Bootstrap workflow

Run from the repository root on the Terraform runner unless a step `cd`s
elsewhere. `scripts/tf-init.sh` must be invoked from the repository root.

### 1. Clone the repository

```sh
git clone <repo-url> && cd aws-pc-mgr
```

Any machine capable of running Terraform will do; nothing assumes its OS.

### 2. Make AWS credentials available to Terraform

```sh
# after the SSO login procedure appropriate to your environment:
export AWS_PROFILE=<profile>
export AWS_REGION=ap-southeast-2   # example; also satisfies tf-init.sh
```

The profile is selected externally and its name never enters the repository.
Terraform uses the normal AWS SDK credential resolution chain.

### 3. Configure the tfvars file

As described [above](#state-bucket-tfvars-setup):
`cd terraform/bootstrap && cp terraform.tfvars.example terraform.tfvars`, then
choose the bucket name.

### 4. Create the state bucket (temporary local state)

The S3 backend cannot hold this stack's state before the bucket exists, so the
backend block is set aside while the bucket is created:

```sh
cd terraform/bootstrap
mv backend.tf backend.tf.off   # temporarily remove the backend block
terraform init                 # provider download only; local state
terraform plan
terraform apply                # creates the bucket; writes local terraform.tfstate
terraform output -raw state_bucket_name
mv backend.tf.off backend.tf   # restore the backend block
```

Why the `mv` step exists: `terraform init -backend=false` disables backend
initialization but does not select a local backend — `terraform plan` and
`terraform apply` then refuse with `Error: Backend initialization required`
until the backend block is initialized, so the block must be absent while the
bucket is created. (`init -backend=false` remains the correct invocation for
`terraform validate` and `terraform test`, whose mocked providers and
in-memory state never touch a backend — that is exactly how CI uses it.)

### 5. Migrate the bootstrap state into S3

From the repository root:

```sh
scripts/tf-init.sh bootstrap
```

This runs, in `terraform/bootstrap`:

```text
terraform -chdir=terraform/bootstrap init \
  -backend-config=bucket=<bucket> \
  -backend-config=key=bootstrap/terraform.tfstate \
  -backend-config=region=<region> \
  -backend-config=use_lockfile=true \
  -migrate-state
```

`-migrate-state` is appended automatically because
`terraform/bootstrap/terraform.tfstate` exists locally (the script omits it
when there is no local state to migrate).

### 6. Verify the migration, THEN delete the local state files

Order matters — verify first, delete second:

```sh
cd terraform/bootstrap
terraform plan          # must report no changes (state readable from S3)
terraform state list    # must list the bucket resources
cd ../..
rm -f terraform/bootstrap/terraform.tfstate terraform/bootstrap/terraform.tfstate.backup
```

Only after a clean plan and a correct state listing are the local state files
removed. They are git-ignored anyway (`*.tfstate`, `*.tfstate.*`), so they can
never be committed, but leaving them around invites confusion about which state
is authoritative. From here on, S3 is authoritative for the bootstrap stack.
(You can additionally confirm bucket versioning created a recoverable first
version of the state object in the S3 console.)

### 7. Initialize the infrastructure stack

From the repository root:

```sh
scripts/tf-init.sh infrastructure
```

Same shape, key `infrastructure/terraform.tfstate`, no `-migrate-state` (there
is no local state for this stack — it uses S3 from its first apply).

### 8. Apply the infrastructure

```sh
cd terraform/infrastructure
terraform plan
terraform apply
```

This creates the `win11-ssm-hybrid-node` IAM role (trust: the
`ssm.amazonaws.com` service principal; permissions: exactly the
`AmazonSSMManagedInstanceCore` AWS-managed policy) and a single-registration
SSM hybrid activation (`registration_limit = 1`, generic description, no
identifying tags).

### 9. Retrieve the activation values

```sh
terraform output -raw activation_id
terraform output -raw activation_code
```

Both outputs are marked `sensitive = true` (a plain `terraform output` masks
them). **Treat both as temporary secrets**: read them on screen when enrolling,
never save them into files, notes, logs, chats, or command history.

### 10. Get the repository onto the Windows machine — without credentials

Clone the repository fresh on the Windows 11 machine. Do **not** copy any AWS
profile, `~/.aws` contents, environment credentials, or SSO configuration with
it. The repository itself contains none (the real tfvars is untracked and state
lives in S3), which is exactly why a plain clone is safe to transfer.

### 11. Enroll the Windows machine

From an elevated PowerShell in the repository root on the Windows machine:

```powershell
.\scripts\windows\setup.ps1
```

Interactive prompts ask for the AWS region, the Activation ID, and the
Activation Code (**masked**) — but only when the machine turns out to actually
need enrolling; a re-run on an already-registered machine asks for nothing.
Prefer the parameterless run: a value typed at a prompt is not recorded in
PSReadLine history, whereas anything typed on the command line — including an
inline `-ActivationId` value — is. `-Region` / `-ActivationId` still exist for
scripted use. No AWS SSO login and
no AWS CLI involvement happens on Windows. See
[Windows enrollment: setup.ps1](#windows-enrollment-setupps1) for exactly what
the script prints and does.

### 12. Validate

Confirm the node reports `Online`, then run the validation battery: Run Command
(`AWS-RunPowerShellScript`), an interactive Session Manager session, SSM Agent
restart, reboot recovery, and setup idempotence. Fill the
[compatibility record](#windows-11-compatibility-record) from the results.

Backend recoverability check (worth doing once): a **fresh clone** on any
machine with its own AWS credentials can run `scripts/tf-init.sh
infrastructure` and `terraform plan` against the existing S3 state with no
files from the original Terraform runner — proving the state in S3 is
authoritative.

## Windows enrollment: setup.ps1

`scripts/windows/setup.ps1` (elevated; decision logic lives in the unit-tested
`SSMHybrid.psm1` module next to it).

```text
.\scripts\windows\setup.ps1                                   # fully interactive (preferred)
.\scripts\windows\setup.ps1 -Region ap-southeast-2            # scripted use; see Parameters
.\scripts\windows\setup.ps1 -ForceReregister                  # destructive; see below
```

**Parameters.** `-Region` and `-ActivationId` are optional, and exist for
scripted use. When supplied they are validated immediately (an invalid supplied
value fails fast with exit 2 after up to three prompt attempts). When omitted
they are prompted for (up to three attempts) **only on the `Register` path** —
every other action completes without them, so a parameterless re-run on an
already-enrolled machine asks for nothing at all. **Prefer the prompts**:
anything typed on a command line is recorded in PSReadLine history — and its
on-disk history file — in plain text, so an inline `-ActivationId` value
outlives the session, while the same value typed at a prompt does not. The
**Activation Code is never a parameter and never appears on a command line**:
it is read through a masked `Read-Host -AsSecureString` prompt
(`Read-SsmSecret`), and only when a registration is actually about to run — an
idempotent re-run never asks for it.

**Flow.** The script first refuses to run unless elevated (exit 1, nothing
changed), then validates any supplied `-Region` / `-ActivationId`, then
inspects the local `AmazonSSMAgent` service and the local
registration file (`$env:ProgramData\Amazon\SSM\InstanceData\registration`),
classifies the machine into one of six states, prints
`State: <state>. Planned action: <action>.`, and executes the mapped action:

| Local state | Action | What it does | Exit |
|---|---|---|---|
| `Absent` / `InstalledUnregistered` | `Register` | download, verify, run `ssm-setup-cli` | 0 |
| `RegisteredHealthy` | `NoOperation` | report ID, verify service | 0 |
| `RegisteredStopped` | `StartService` | start existing service (no re-register) | 0 |
| `RegisteredUnhealthy` / `Ambiguous` | `ManualIntervention` | explain, change nothing | 3 |
| any registered state + `-ForceReregister` | `Reregister` | confirm, stop agent, clear local registration, leave agent stopped | 3 |

What each path prints and does:

* **NoOperation** — re-verifies the service (starting it if it stopped since
  the first check), then prints the managed node ID (`mi-...`), the region from
  the local registration record (the line is omitted when the record carries
  none), and service status, and states that no changes were made and **no
  activation was consumed**. This is what a healthy re-run looks like: the bare
  command, no prompts, no inputs required.
* **StartService** — non-destructive repair: starts the existing
  `AmazonSSMAgent` service and reports the same summary, preserving the
  existing registration. Like `NoOperation`, it never prompts for activation
  values.
* **Register** — announces that the AWS setup CLI will be downloaded over HTTPS
  and its signature verified, prompts for any missing region / Activation ID
  and then the (masked) activation code, then:
  forces TLS 1.2 where needed, downloads `ssm-setup-cli.exe` from
  `https://amazon-ssm-<region>.s3.<region>.amazonaws.com/latest/windows_amd64/ssm-setup-cli.exe`
  into a temp directory, **refuses to execute** unless its Authenticode
  signature is `Valid` and signed by `Amazon.com Services LLC`, runs the
  registration (`-register -region ... -activation-id ... -activation-code ...`,
  a command line that is never echoed or logged), and deletes the temp
  executable. It then verifies the registration file parses, that the service
  exists / is Running / is Automatic (fixing startup type or starting it if
  needed), prints `Registration complete.` with the managed node ID, region,
  and service status plus a note that it can take a few minutes to report
  `Online` in AWS, and clears the bootstrap secrets from memory. On failure it
  explains that registration may have partially completed, names what to
  inspect, deletes nothing, and exits 1.
* **ManualIntervention** (`RegisteredUnhealthy` or `Ambiguous`) — changes
  nothing automatically: explains that a registration record exists but the
  service is missing/not Running/not Automatic, or that the record cannot be
  parsed and cannot be trusted for an automatic decision; lists what to inspect
  (`Get-Service AmazonSSMAgent`, `Get-CimInstance Win32_Service`, the
  registration file, the agent log under `$env:ProgramData\Amazon\SSM\Logs`);
  notes registration may be partially complete and nothing was deleted or
  deregistered; exits 3.
* **Reregister** (`-ForceReregister`) — prints an explicit DESTRUCTIVE warning:
  AmazonSSMAgent will be stopped first and left STOPPED; the local SSM
  registration will be cleared (`amazon-ssm-agent -register -clear`);
  **the current managed-node ID stops being used by this machine
  (the existing registration identity is destroyed)**; the node remains
  registered in AWS until separately deregistered there; and re-enrollment
  consumes a **new** activation (the previous one is consumed — the limit is 1)
  and yields a **new** managed-node ID. You must type `yes` to proceed; the
  script then stops AmazonSSMAgent (already-stopped and service-missing are
  both tolerated; the clear only runs once the service is verified stopped —
  the same stop-first sequence as the manual reset below), clears the local
  registration, leaves the service stopped — without a registration it has
  nothing to run with — and exits 3. Re-enroll by running the script again
  **without** `-ForceReregister`, providing fresh activation values; that
  Register run starts AmazonSSMAgent again with the new identity.

**Exit codes.** `0` success; `1` refusal or failure (not elevated, service
query failure, registration failure, unexpected state — nothing deleted);
`2` invalid inputs (bad region/activation ID, empty activation code); `3`
manual-intervention and reregister paths.

The script never runs `aws configure`, never performs an SSO login, never
writes under your `.aws` directory, and never deregisters, deletes
registration data, or consumes an activation on its own.

## Diagnostics: check.ps1

```powershell
.\scripts\windows\check.ps1
```

Strictly **read-only**: starts nothing, changes nothing, deletes nothing. It
prints labeled sections:

* Windows edition/version and build (`Win32_OperatingSystem`);
* SSM Agent installation status and version (from `amazon-ssm-agent --version`,
  falling back to the file's version resource);
* `AmazonSSMAgent` service existence, running state, and startup configuration;
* whether a local SSM registration exists, and the managed node ID and region
  where discoverable (the raw registration file is never dumped — it may
  contain key material);
* recent warning/error lines from the SSM Agent log (last 500 lines scanned,
  last 50 shown).

A registration file that **exists but cannot be read** — for example from an
unelevated session hitting its ACL, since this script is documented as usable
without elevation — is reported as a read failure (its path plus a coarse
failure category, `access denied` vs `read error`), never as "no registration
file": misreporting an enrolled machine as unenrolled would be a false
diagnosis. The same applies to a file that exists but does not parse as
registration data. Both states count as problems (**exit 1**), because the
diagnostic could not verify health, and in neither is anything from inside
the file — nor error text quoting it — ever printed.

It never prints the Activation Code or any credential material. **Exit codes:**
`0` healthy, `1` problems found (each problem is listed). Recent log warnings
are reported for context but do not by themselves count as problems, since a
healthy agent can log transient warnings.

## Activation lifecycle

An SSM activation is the **registration mechanism**, not the managed node
itself. An activation can expire unused, become unusable once its registration
limit is consumed, or be deleted — none of which deregisters or affects an
already-registered node. Once the Windows machine is registered, the activation
is irrelevant.

The Terraform configuration is built so a consumed or expired activation causes
**no drift and no churn**: every argument of `aws_ssm_activation` forces
replacement when changed, and nothing in this configuration changes after
apply (fixed generic name and description, `registration_limit = 1`, role
name). `expiration_date` is **deliberately unset** — AWS defaults it to 24
hours, and pinning a timestamp would make every later apply plan a replacement.
So `terraform plan` stays clean even after the activation has expired or been
consumed. No tags are set, because they would propagate to the managed node.

**Re-registration runbook** (only needed when you deliberately want a fresh
identity, e.g. after clearing a broken local registration):

```sh
cd terraform/infrastructure
terraform apply -replace='aws_ssm_activation.node'   # new activation
terraform output -raw activation_id
terraform output -raw activation_code
```

Then, within the activation's lifetime (24 hours by default), on Windows:

```powershell
.\scripts\windows\setup.ps1 -ForceReregister   # type yes; stops agent, clears local registration, leaves agent stopped; exits 3
.\scripts\windows\setup.ps1                    # now unregistered -> Register path prompts for the NEW activation values (starts the agent again)
```

## Destruction and deregistration

**`terraform destroy` is not sufficient** to remove the Windows machine from
SSM. Deregistering a managed node is a separate operation from deleting its
activation or IAM infrastructure, and these steps are deliberately manual —
run them yourself, nothing here automates cleanup:

1. **Deregister the node on the AWS side** (from the Terraform runner or
   anywhere with authorized AWS credentials — not the Windows machine, which
   by design has none):

   ```sh
   aws ssm deregister-managed-instance --instance-id <managed-node-id> --region <region>
   ```

   Discover the ID with `.\scripts\windows\check.ps1` on the machine, or
   `aws ssm describe-instance-information` / Fleet Manager in the console.

2. **Reset the local registration** on the Windows machine, elevated:

   ```powershell
   Stop-Service AmazonSSMAgent
   # Remove the IdentityConsumptionOrder key from the agent configuration, if present:
   notepad "$env:ProgramFiles\Amazon\SSM\amazon-ssm-agent.json"
   & "$env:ProgramFiles\Amazon\SSM\amazon-ssm-agent.exe" -register -clear
   ```

   `-register -clear` removes the agent's local registration data under
   `$env:ProgramData\Amazon\SSM\InstanceData`. This is the same stop-then-clear
   sequence `-ForceReregister` performs (that path stops the service before the
   clear and leaves it stopped); doing it here just leaves the machine
   unregistered.

3. **Optionally uninstall SSM Agent** (Windows *Apps & features* / installed
   programs) if you no longer want it on the machine.

4. **Destroy the AWS infrastructure**, if that is what you want:

   ```sh
   cd terraform/infrastructure
   terraform destroy     # activation + IAM role; does NOT deregister anything
   ```

   Note the bootstrap stack's S3 bucket carries `lifecycle { prevent_destroy
   = true }`: `terraform destroy` in `terraform/bootstrap` will **refuse** to
   delete the state bucket. That is deliberate — state history is the thing
   you least want to lose to a routine destroy. Deleting the bucket is a
   manual, explicit decision (remove the guard or delete the bucket
   out-of-band).

## Pricing note: Session Manager and Run Command

From **2026-09-30**, AWS charges pay-as-you-go fees for Session Manager
sessions and Run Command invocations on hybrid managed nodes. This system uses
exactly those two capabilities, so expect a small recurring cost while the
machine is enrolled. Budget accordingly; AWS's Systems Manager pricing pages
have the current rates.

## Windows 11 compatibility record

Filled in from the on-machine validation battery results; until then the cells
are placeholders and Windows-side behavior is pending validation (see
[Windows 11 is not AWS-supported](#windows-11-is-not-aws-supported)). Only
non-identifying information is recorded here — no hostname, username,
managed-node ID, or account ID.

```text
Windows edition/version: <e.g. Windows 11 Pro>
Windows build:           <e.g. 22631>
SSM Agent version:       <e.g. 3.x.xxxx.x>
Test date:               <yyyy-mm-dd>
```

| Test | Result |
|---|---|
| Registration | PASS / FAIL |
| Run Command | PASS / FAIL |
| Session Manager | PASS / FAIL |
| Agent restart | PASS / FAIL |
| Reboot recovery | PASS / FAIL |
| Sleep/wake recovery | N/A — this machine does not use sleep |
| Agent upgrade | PASS / FAIL / NOT TESTED |

## Repository hygiene: audit, tf-init, tests, CI

### audit.sh

```sh
scripts/audit.sh                          # audit the repository; exit 1 on any finding
scripts/audit.sh --selftest               # prove every detector still fires on synthetic fixtures,
                                          #   a generated spelling matrix, value must/must-not
                                          #   tables, and the SPEC §27 coverage map
scripts/audit.sh --message-file FILE      # pre-commit gate: the same detectors over PROPOSED
                                          #   commit-message text; exit 1 on any finding
```

`--message-file` is the gate for **commit message text**: the default audit
scans message bodies as content, but only after the commit exists, when the
fix is history surgery. Twice a commit has quoted a detector-tripping value
in its body and the audit went red only afterwards; checking the message
before committing makes that class impossible to create. Suppression is
deliberately unavailable in this mode — uncommitted text has no standing
annotations, so reword the message. The runtime per-machine value checks are
skipped (they describe this machine, not proposed content).

**pre-push hook.** `scripts/hooks/pre-push` runs the full audit as the last
gate before commits leave the machine — the last point at which
`git commit --amend` still fixes a finding for free. Install it once per
clone (git does not track `.git/hooks`):

```sh
git config core.hooksPath scripts/hooks
```

The default audit scans all tracked files — text directly, UTF-16 and
BOM'd UTF-32 files (UTF-16 such as Windows PowerShell `>` redirection
output) decoded to UTF-8 and scanned in decoded form — and the **full
history of every commit** (message
bodies, scanned for every commit independently of the path-filtered patches,
plus the patches) for: AWS access-key IDs (`AKIA...`,
`ASIA...`), secret-key, activation-code, session-token, account-ID,
SSO-profile and machine-serial-number label assignments
— the label
detectors match a **lowercased copy of each line** with
separator-wildcarded label words, so every case variant (lowercase HCL
`aws_secret_access_key`, env `AWS_SECRET_ACCESS_KEY`, camelCase
`SecretAccessKey`, JSON `"SecretAccessKey": "..."`, spaced
`Secret Access Key = ...`, env `AWS_SESSION_TOKEN`, `SessionToken`, and
the security-token spellings of the same credential — signed-request
header `X-Amz-Security-Token`, JSON `SecurityToken`, env
`SECURITY_TOKEN`) and
every separator spelling inside the label
is the same pattern — the account label likewise matches with or without
its `id` suffix in any case (`account_id`, `accountId`, UPPER
`AWS_ACCOUNT_ID`, JSON `"Account": "…"`, the GetCallerIdentity dump
shape) — with the assignment `=` or `:` separated and
value-anchored (by length, or by the 12-digit run for the account label,
so a bare `Account:` label holding an account name or free text never
trips), so short synthetic literals like
`SecretAccessKey=EXAMPLE` or `Session Token: EXAMPLE` in the Windows-tier
tests cannot trip it —
the SSO-profile label is aws-prefixed only (`AWS_PROFILE`, `aws_profile`,
`AwsProfile`, spaced `AWS PROFILE = …`; the bare `profile` key of HCL
documentation is deliberately not matched) and its value anchor is a single
unbroken run of any length — letter-only profile names are real, so no
shape is required — with an explicit generic-value
exclusion (default, example, examples, placeholder, value, name, profile,
none, test: words that name the slot, not a profile anyone selected), so
`AWS_PROFILE=<profile>` placeholders (angle brackets cannot match),
`AWS_PROFILE=default` boilerplate and prose never trip, the labeled
Windows-identifier labels (the `username` core — `Windows username:`,
`win_username`, `UserName`, `user.name` — plus the Windows-qualified nouns
`Windows user:`, `Windows account:`, `LocalAccount`, `SamAccountName`,
`logon name`; the hostname label alternation `hostname` / `computer name` /
`machine name` — every alternative is decided in the LABEL VOCABULARY
TABLE inside scripts/audit.sh, with bare `user`/`account` and `login
name` deliberately excluded) anchored
to a single identifier run of any length with doc-filler sets excluded after the
match (a labeled `root` or `Administrator` is a finding, not filler), so a
labeled identifier on the Windows machine is caught as committed content
even when the audit runs on the Unix CI runner whose runtime checks can
never see it, the personal-name
label family (`personal name`, `full name`, `real name` in any spelling —
never the bare `name` key of ordinary code) anchored to a two-run name
shape (each run 3-plus, totalling 8-plus, with a small form-boilerplate
exclusion set for values like `Not Applicable`), so `Personal Name: Alice
Smith` fires while `Personal Name: the name of the person`, single tokens,
placeholders and very short names stay silent, and the serial label
(`serial number`, `SerialNumber`, `serial_number`, `Machine Serial
Number: …` — a `machine` prefix word needs no handling of its own)
requires one post-label token of 8-plus carrying both a letter and a
digit — a **property**, not a positional pattern, so any interleaving
(`ABC12345`, `ABC-12345`, `ABCDEFG1`, `ABC1234Z`) fires while free text,
a Terraform state file's pure-digit `"serial": 57` counter and
pure-letter words never do —
managed-node IDs (`mi-...`), UUID
literals, SSO start URLs (any scheme/host capitalization), email addresses, 12-digit account IDs in ARNs
of any service (empty-region `arn:aws:iam::…` style or regional
`arn:aws:ssm:us-east-1:…` style, any capitalization of the `arn:aws`
prefix and namespace spans), and user-specific absolute paths
(`C:\Users\<username>\…`, `c:\users\…`, `C:/Users/<username>/…`,
`/Users/<username>/…`, `/home/<username>/…` — the username segment is the
identity; `Users` matches any capitalization because the filesystems
behind it are case-insensitive, `/home` stays lowercase because Linux
filesystems are case-sensitive, and a leading boundary keeps URL paths
such as `https://example.com/home/<page>` from tripping; `<username>`-style
placeholders cannot match because the segment class excludes `<`); these
value-shape detectors match the original
line unchanged, because their grammar is case-bearing. It also treats
runtime values as findings if they
appear in tracked files or in history (commit message bodies and patches
alike): the bucket name from your local untracked
`terraform/bootstrap/terraform.tfvars`, plus your local `whoami` and `hostname`
values, your account's display name (the GECOS/full-name field via
`id -F` on macOS or `getent passwd` on Linux, skipped with a note when the
platform exposes none or the value is not name-shaped), and — when set to
a specific-enough name — your `AWS_PROFILE`
value, the SSO profile this machine selects (generic values such as
`default` are skipped, like generic CI usernames). Tracked and historical
`*.tfstate`/`*.tfstate.*` PATHS are findings too — in the worktree and in
every commit's changed-path list — so even a minimal
`{"version":4,...}` state file, or one committed and later deleted, is
caught independently of its content. `--selftest` runs the same engine over the synthetic fixtures in
`tests/fixtures/audit/` (each constructed to trip a detector) and exits 0 only
if every detector fires — it proves the audit itself still works. The fixture
directory is excluded from the default audit by path (that is its purpose), as
is `scripts/audit.sh` itself, since it necessarily contains the detector
patterns.

**Suppression marker `# audit-allow:synthetic`.** A line carrying this marker
comment — normally trailing on the very line holding the value — is skipped by
every *suppressible* detector, in both file mode and history mode (history
checks the raw patch line). It exists only for **synthetic** test/doc values
(example UUIDs in module help, invented `mi-` literals in unit tests) and
for **label-shape collisions in code**, where the deliberately broad label
detectors match an ordinary assignment whose "value" is code rather than a
credential — setup.ps1 carries
`$activationCode = Read-ActivationCode # audit-allow:synthetic` verbatim
for exactly that reason. Two
hard rules, enforced in code: the marker can **never** silence AWS key
material (`AKIA`/`ASIA` key IDs, secret-key or session-token assignments in
any spelling or case) or the
runtime per-machine value checks (bucket name, username, hostname, AWS
profile name) — those are
real by definition. And history equivalence: a finding in an already-committed
line is also skipped when the byte-identical line exists in the current tree
carrying the marker, so synthetic lines committed before the marker existed
need no history rewrite. Never use the marker to make a runtime-discovered
value committable; that is not what it is for.

**Binary content fails closed.** A tracked file with binary content that is
not decodable UTF-16 or BOM'd UTF-32 (or when `iconv` is unavailable or
lacks the encoding), and any commit whose
patch shows only git's `Binary files ... differ` marker, each produce an
explicit `unscannable-binary-content` finding: the audit never passes
silently over content it could not scan — decode the file, commit text, or
verify that history manually. A successful decode is re-verified too: when
the decoded output still contains NUL bytes (`iconv` can read the wrong
encoding — UTF-32 read as UTF-16 — "successfully" into NUL-interleaved
garbage no detector can match), the file gets the same
`unscannable-binary-content` finding rather than being scanned as text.
The history scan fails closed the same way
when it cannot even enumerate commits: a failing `git rev-list` (corrupt or
unreadable history) exits with an error rather than reporting a clean
zero-commit scan.

### tf-init.sh

```text
scripts/tf-init.sh <bootstrap|infrastructure> [-n]
```

`-n` (or `--dry-run`) prints the exact `terraform init` command without
running it. Region comes from `AWS_REGION` (fallback `AWS_DEFAULT_REGION`;
the script errors if neither is set). The bucket comes from
`TFVARS_FILE` (default: `terraform/bootstrap/terraform.tfvars`, parsed for
`bucket_name`). The state key is always `<stack>/terraform.tfstate`, native S3
locking (`use_lockfile=true`) is always requested, and `-migrate-state` is
appended only when `terraform/<stack>/terraform.tfstate` exists locally. Run
it from the repository root.

### Tests

* **Terraform** — `terraform test` per stack (`cd terraform/<stack> &&
  terraform test`, after `terraform init -backend=false`): `mock_provider`
  runs with in-memory state; no credentials or backend needed. Asserts the
  bucket configuration, the IAM trust policy and policy attachment, the
  activation settings, and the outputs.
* **Module unit tests** — `tests/unit/SSMHybrid.Tests.ps1` (Pester 5) covers
  the eight exported `SSMHybrid.psm1` contract functions; the module also
  exports three Windows-only adapters (`Get-SsmServiceInfo`,
  `Get-SsmRegistrationFileJson`, `Invoke-SsmEnrollment`), which `setup.ps1`
  and `check.ps1` call after `Import-Module` — the adapters are exercised by
  the Windows-tier tests below, not here, and the module is written so it
  imports on any OS. Run in the PowerShell 7 container:

  ```sh
  docker run --rm -v "$PWD:/src" -w /src \
    mcr.microsoft.com/powershell:7.4-ubuntu-22.04 \
    pwsh -c "Install-Module Pester -MinimumVersion 5.5 -Scope CurrentUser -Force; Invoke-Pester /src/tests/unit -Output Detailed"
  ```

* **Windows-tier tests** — `tests/windows/{Setup,Check}.Tests.ps1` (Pester 5)
  exercise `setup.ps1` / `check.ps1` end-to-end on the enrolled machine:
  idempotent second run, signature verification, refusal paths, and that no
  secret material leaks into output. They are two-tiered: the module-import
  and parser syntax checks run anywhere, while the machine-state tests are
  Skip-guarded to Windows (elevated, and enrolled where the assertion needs a
  registration) — they run red-then-green on the real machine during
  validation, never in CI.
* **Shell** — `sh tests/tf-init.test.sh` asserts `tf-init.sh`'s dry-run
  output, region handling, and error behavior against a fixture tfvars file.

### CI

`.github/workflows/ci.yml` — three jobs on every push and pull request, no
secrets and no AWS credentials anywhere:

1. **terraform** — per stack: `fmt -check -recursive`,
   `init -backend=false`, `validate`, `test` (mock providers), plus tflint on
   its bundled ruleset only (no plugins, so it needs no network or
   credentials).
2. **pwsh** — the same PowerShell 7 container as local testing, running the
   `tests/unit` Pester suite and PSScriptAnalyzer over `scripts/windows`
   (5.1/7.0 syntax compatibility, per `.PSScriptAnalyzerSettings.psd1`);
   `tests/windows` is parse-checked only — machine-tier tests never run in
   CI.
3. **shell** — `sh tests/tf-init.test.sh`, `scripts/audit.sh --selftest`, and
   shellcheck, on a full-history checkout (the audit scans history, so a
   shallow clone would truncate it). The default `scripts/audit.sh` mode is
   also meant to gate this job; see `.github/workflows/ci.yml` for its
   current state, and run it locally before pushing regardless.

## Security properties

* **Outbound-only.** The Windows machine initiates all connections; nothing in
  this repository opens an inbound port, forwards a router port, or needs a
  VPN or public IP.
* **No AWS identity on Windows.** No IAM user, no access keys, no static
  credentials, no SSO configuration, no `AWS_PROFILE`; enrollment uses only
  region + Activation ID + Activation Code, and afterwards the agent rotates
  AWS-issued temporary credentials for the managed-node role itself.
* **External Terraform authentication.** Providers and backends carry no
  profile or keys; the profile used to run Terraform is selected externally
  and never committed.
* **Durable, protected state.** S3 backend with server-side encryption
  (AES256), versioning, all four public-access blocks, `BucketOwnerEnforced`
  ownership, native state locking (`use_lockfile`), and `prevent_destroy` on
  the bucket.
* **Single-use activation.** `registration_limit = 1`, default 24 h lifetime,
  `sensitive` outputs, Activation Code never a parameter / never printed /
  never logged / never committed; existing registrations are never silently
  overwritten — the destructive path requires `-ForceReregister` plus an
  interactive confirmation.
* **Verified supply chain.** AWS binaries are downloaded over HTTPS when
  needed (never committed), checked for a valid Authenticode signature from
  `Amazon.com Services LLC` before execution, and `ssm-setup-cli`'s own
  signature validation is left enabled.
* **Least privilege.** The managed-node role carries exactly
  `AmazonSSMManagedInstanceCore` and trusts only the `ssm.amazonaws.com`
  service principal; no application permissions, no account IDs hard-coded.
* **Known accepted trade-off.** During enrollment the activation code is
  briefly visible in the process command line of `ssm-setup-cli` (the tool
  takes it only as an argument); it is never echoed or logged by these
  scripts, and the assumption is a single-user machine.
