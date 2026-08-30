Yes. I conflated “the machine from which Terraform happens to be run” with a management workstation. That is not part of the architecture.

The correct model is:

```text
Terraform runner
  - arbitrary OS
  - runs Terraform
  - already has AWS authentication available
  - normally via an externally selected AWS SSO profile
  - has no ongoing role once Terraform has applied

AWS
  - S3 Terraform backend
  - IAM role
  - SSM hybrid activation
  - Systems Manager

Windows 11 machine
  - the managed machine
  - SSM Agent
  - no SSO configuration
  - no static AWS credentials
  - managed through SSM
```

In particular, there should be **no tests involving expiry of the Terraform runner's SSO session**, no assumption it is Windows, and no suggestion that it performs ongoing administration. Its only relevance is that Terraform has to run somewhere.

Here is the corrected complete spec.

# Windows 11 as an AWS Systems Manager Managed Node

## 1. Goal

Build a Git repository that reproducibly configures a personal Windows 11 machine as an AWS Systems Manager (SSM) hybrid managed node.

The repository must contain:

* Terraform for all required AWS-side infrastructure.
* Terraform for an S3 backend used to persist Terraform state.
* A PowerShell setup script for all required setup on the Windows 11 machine.
* A PowerShell diagnostic/check script for the Windows machine.
* Documentation sufficient to bootstrap the system from a fresh clone.
* Repeatable validation demonstrating that SSM management works correctly.

The managed Windows machine is outside AWS and communicates with AWS using outbound connections only.

The solution must not require:

* inbound firewall rules;
* router port forwarding;
* a VPN;
* a public IP address;
* exposing RDP, SSH, PowerShell Remoting, or another management port to the Internet.

No secrets or user/machine-identifying information may be stored in the Git repository or Git history.

---

# 2. Scope

This project is specifically concerned with establishing AWS Systems Manager management of a Windows 11 machine.

Required functionality:

* Install SSM Agent on Windows 11.
* Register the Windows machine as an SSM hybrid managed node.
* Have the node report `Online` in Systems Manager.
* Execute PowerShell through SSM Run Command.
* Establish interactive Session Manager sessions.
* Automatically reconnect after reboot.
* Automatically reconnect after sleep/wake if the machine uses sleep.
* Operate without AWS SSO configuration or permanent AWS credentials on the Windows machine.

Explicitly outside the initial scope:

* Patch Manager.
* SSM Inventory.
* Fleet Manager Remote Desktop.
* Windows Server role/feature management.
* Windows Server-specific SSM documents.
* application-specific AWS permissions.
* application deployment.
* general-purpose AWS CLI configuration on the Windows machine.

---

# 3. Windows 11 support status

AWS does not officially list Windows 11 as a supported operating system for Systems Manager hybrid managed nodes. Its supported Windows platforms are Windows Server editions.

Real-world reports nevertheless indicate that SSM Agent can install, register, and provide core SSM functionality on Windows 11.

Therefore:

> Windows 11 is an intentionally tested but AWS-unsupported configuration.

Do not attempt to disguise Windows 11 as Windows Server or otherwise work around OS detection.

Use the normal AWS hybrid-node registration mechanism.

Functionality required by this project must be tested on the actual Windows 11 machine rather than assumed to work based on Windows Server documentation.

Do not depend on SSM functionality known to require Windows Server-specific components.

---

# 4. Architecture

There are three relevant components:

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

The Terraform runner has no ongoing role in management of the Windows machine.

It is simply the environment from which Terraform is executed.

The Terraform runner and Windows managed node must not share credentials.

---

# 5. Terraform runner

Terraform may be run from any suitable machine or operating system.

Do not assume that the Terraform runner is Windows.

Do not treat it as a dedicated administrative workstation.

Its responsibilities are only to:

1. obtain the repository;
2. have AWS authentication available;
3. run Terraform;
4. retrieve the temporary SSM activation values required for initial Windows enrollment.

Once the infrastructure has been applied, the Terraform runner is not involved in normal SSM operation.

## AWS authentication for Terraform

The expected normal authentication mechanism where Terraform is run is an AWS IAM Identity Center / AWS SSO profile.

However, the profile name must not be hard-coded anywhere in the repository.

For example, the environment running Terraform may have externally selected:

```text
AWS_PROFILE=<profile>
```

after whatever SSO login procedure is appropriate to that environment.

Terraform must use the normal AWS SDK credential resolution chain.

Do not configure:

```hcl
provider "aws" {
  profile = "some-profile"
}
```

Do not hard-code a profile in S3 backend configuration.

Although AWS SSO is the expected normal authentication source, Terraform must not depend specifically on SSO. Other standard AWS credential providers should continue to work.

The repository must not contain:

* SSO profile names;
* SSO start URLs;
* SSO configuration;
* AWS access keys;
* AWS secret keys;
* AWS session tokens.

---

# 6. Windows managed-node authentication

The Windows 11 machine must not use the Terraform runner's AWS authentication.

The Windows machine must not require or contain:

* AWS IAM Identity Center / SSO configuration;
* an AWS SSO profile;
* `AWS_PROFILE`;
* an IAM user;
* IAM user access keys;
* static AWS credentials;
* credentials copied from the Terraform runner;
* any other long-lived AWS credentials for SSM operation.

Initial registration uses only:

* AWS region;
* SSM Activation ID;
* SSM Activation Code.

After registration, SSM Agent authenticates using the SSM hybrid managed-node identity and the IAM role associated with that identity.

SSM Agent is responsible for obtaining and rotating AWS-issued temporary credentials for that role.

The Windows machine must remain manageable without any AWS user login taking place on it.

---

# 7. Security requirements

The implementation must preserve all of the following:

* No inbound Internet access is introduced.
* The Windows machine has no IAM user.
* The Windows machine has no permanent AWS access key.
* The Windows machine has no dependency on AWS SSO.
* Credentials from the Terraform runner are never copied to Windows.
* Terraform authentication is supplied externally.
* The AWS profile used to run Terraform is not committed.
* Terraform state is stored durably in S3.
* Terraform state is encrypted.
* Terraform state is versioned.
* Terraform state cannot be accessed publicly.
* Terraform state locking is enabled.
* SSM activation credentials are short-lived.
* The SSM activation allows only one registration.
* Activation credentials are never committed.
* Secrets are not written to logs.
* Identifying machine/user information is not committed.
* Existing SSM registrations are never silently overwritten.
* AWS binaries are downloaded when needed rather than committed.
* IAM permissions follow least privilege.

---

# 8. Repository structure

Use approximately:

```text
/
├── README.md
├── .gitignore
│
├── terraform/
│   ├── bootstrap/
│   │   ├── versions.tf
│   │   ├── providers.tf
│   │   ├── backend.tf
│   │   ├── state.tf
│   │   └── outputs.tf
│   │
│   └── infrastructure/
│       ├── versions.tf
│       ├── providers.tf
│       ├── backend.tf
│       ├── data.tf
│       ├── iam.tf
│       ├── ssm.tf
│       └── outputs.tf
│
└── scripts/
    └── windows/
        ├── setup.ps1
        └── check.ps1
```

Files may be consolidated if this improves clarity.

Do not introduce Terraform modules merely for abstraction. Keep the configuration small and directly inspectable.

Commit `.terraform.lock.hcl`.

Do not commit `.terraform/`.

---

# 9. Terraform versions

Pin Terraform to a recent version supporting native S3 backend locking using `use_lockfile`.

Specify an appropriate compatible version constraint for the AWS provider.

Record version requirements in `versions.tf` and commit `.terraform.lock.hcl`.

Do not introduce DynamoDB solely for state locking when native S3 state locking is available.

---

# 10. Terraform S3 backend

Terraform state must be stored in Amazon S3.

Persistent local Terraform state is not acceptable because losing the machine or working directory from which Terraform happened to be run must not lose the authoritative infrastructure state.

## Backend bootstrap

Terraform cannot use an S3 backend before the bucket exists.

Use a small bootstrap Terraform configuration:

```text
terraform/bootstrap
       |
       | temporary local state
       v
creates S3 state bucket
       |
       v
bootstrap state migrated to S3
       |
       v
terraform/infrastructure
uses S3 from first apply
```

Local state is acceptable only to initially create the backend infrastructure.

It must not remain authoritative afterward.

---

# 11. State bucket

The bootstrap Terraform must create a dedicated S3 bucket for Terraform state.

Configure:

* S3 Block Public Access.
* Bucket versioning.
* Server-side encryption.
* No public bucket policy.
* No public ACL.
* Appropriate object ownership settings.
* Support for native Terraform S3 state locking.

Do not create a customer-managed KMS key unless there is a specific requirement for one.

Standard S3 server-side encryption is sufficient.

## Bucket name

Do not commit a real bucket name containing identifying information.

Prefer letting Terraform generate a globally unique name from a generic prefix, for example:

```text
win11-ssm-tfstate-<generated-suffix>
```

The unique suffix must not be derived from:

* person's name;
* username;
* hostname;
* email;
* AWS account ID.

Expose the resulting bucket name as a Terraform output.

It may exist in AWS and Terraform state, but not as identifying source-controlled configuration.

---

# 12. Bootstrap state migration

After creating the S3 bucket:

1. Obtain the generated bucket name from Terraform output.
2. Reinitialize the bootstrap stack against that S3 backend.
3. Migrate its temporary local state into S3.
4. Verify that the migrated state is readable.
5. Verify that S3 versioning has created a recoverable state object.
6. Only then remove obsolete local state files.

Use a state key such as:

```text
bootstrap/terraform.tfstate
```

After this process, subsequent bootstrap Terraform operations must use S3.

---

# 13. Main infrastructure backend

The main infrastructure stack must use S3 from its first apply.

Use a separate key such as:

```text
infrastructure/terraform.tfstate
```

Declare the backend without credentials or user-specific configuration:

```hcl
terraform {
  backend "s3" {}
}
```

Supply backend location information to `terraform init`, for example:

```text
terraform init \
  -backend-config="bucket=<bucket>" \
  -backend-config="key=infrastructure/terraform.tfstate" \
  -backend-config="region=<region>" \
  -backend-config="use_lockfile=true"
```

Do not include:

```text
profile = ...
```

in backend configuration.

Backend authentication must use the same normal AWS credential resolution mechanism as Terraform.

---

# 14. Backend recoverability

Verify that a fresh repository checkout in any suitable Terraform-running environment can:

1. obtain AWS credentials independently;
2. initialize against the existing S3 backend;
3. read the existing Terraform state;
4. run `terraform plan` without depending on files from the original Terraform runner.

This verifies that the S3 state is authoritative.

---

# 15. AWS region

Do not hard-code an environment-specific AWS region unnecessarily.

Allow normal AWS configuration/environment mechanisms to supply it where possible, including:

```text
AWS_REGION
AWS_DEFAULT_REGION
```

If a Terraform variable is required, do not commit a real environment-specific value.

The selected region must also be supplied to the Windows setup because SSM hybrid registration is region-specific.

---

# 16. AWS infrastructure

The main Terraform stack must create all AWS infrastructure required for the Windows managed node.

At minimum:

1. IAM role for the SSM hybrid managed node.
2. IAM trust policy.
3. Required Systems Manager IAM policy attachment.
4. SSM hybrid activation.

Do not require manual AWS Console setup for these resources.

Do not add unrelated application permissions.

---

# 17. Managed-node IAM role

Create an IAM role specifically for the Windows SSM hybrid managed node.

Attach:

```text
arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
```

as the initial permission set.

Use the appropriate Systems Manager trust relationship.

Follow current AWS recommendations for restrictions such as `aws:SourceAccount` and appropriate `aws:SourceArn` conditions where applicable.

Discover AWS values dynamically using Terraform, including as appropriate:

```hcl
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}
```

Do not hard-code the AWS account ID.

Do not create an IAM user.

Do not create access keys.

Do not grant application-specific AWS access in this project.

---

# 18. SSM hybrid activation

Create an SSM hybrid activation associated with the managed-node IAM role.

Set:

```hcl
registration_limit = 1
```

Use a short activation lifetime suitable for bootstrap.

Use only a generic description, for example:

```text
Windows hybrid managed node
```

Do not encode:

* hostname;
* username;
* person's name;
* email;
* serial number;
* machine-specific identifiers;
* manually entered account IDs.

---

# 19. Activation credentials

The activation produces:

* Activation ID.
* Activation Code.

Treat both as temporary bootstrap-sensitive information.

Terraform outputs exposing these values must be marked:

```hcl
sensitive = true
```

They must never be written into:

* tracked `.tfvars`;
* tracked backend configuration;
* `.env`;
* source scripts;
* README real examples;
* logs;
* Git history.

They may be retrieved directly from Terraform when enrolling the Windows machine:

```text
terraform output -raw activation_id
terraform output -raw activation_code
```

---

# 20. Windows setup script

Create:

```text
scripts/windows/setup.ps1
```

This performs all Windows-side setup required to register the machine as an SSM hybrid managed node.

It must run from an elevated PowerShell session on Windows 11.

It must not require:

* AWS CLI;
* AWS SSO;
* `AWS_PROFILE`;
* Terraform;
* access keys.

## Inputs

The script requires:

* AWS region;
* SSM Activation ID;
* SSM Activation Code.

Support interactive entry.

Environment variables or explicit parameters may also be supported where useful, but interactive use must not require the Activation Code to appear in PowerShell command history.

Prefer secure/masked input for the Activation Code where practical.

Never print the Activation Code.

Never write it to a log.

---

# 21. Windows installation process

Use AWS's current hybrid-node Windows installation mechanism, currently based on `ssm-setup-cli`.

Do not commit:

* `ssm-setup-cli.exe`;
* SSM Agent installers;
* other downloaded AWS binaries.

The script should:

1. Confirm that it is running elevated.
2. Validate required inputs.
3. Detect whether SSM Agent is already installed.
4. Detect whether an SSM registration already exists.
5. Refuse to silently overwrite an existing registration.
6. Download the current AWS SSM setup executable from AWS for the selected region.
7. Validate the downloaded executable using Windows Authenticode or the appropriate AWS-recommended verification mechanism.
8. Refuse to execute an invalidly signed binary.
9. Register using the supplied:

   * region;
   * Activation ID;
   * Activation Code.
10. Confirm successful SSM Agent installation.
11. Confirm the `AmazonSSMAgent` service exists.
12. Confirm that it is running.
13. Confirm that it is configured for automatic startup.
14. Determine the resulting `mi-...` managed-node ID from local registration information.
15. Display the managed-node ID.
16. Remove temporary installation files.
17. Clear sensitive bootstrap values from script variables/environment where practical.

Do not create an AWS CLI profile.

Do not perform an SSO login.

---

# 22. Idempotence

Re-running:

```powershell
.\scripts\windows\setup.ps1
```

on an already correctly configured machine must be safe.

If the machine is already registered:

* detect the existing registration;
* display the existing managed-node ID;
* verify the SSM Agent service;
* exit successfully if healthy.

Do not automatically:

* deregister it;
* delete registration information;
* consume another activation;
* create another SSM identity.

If explicit re-registration functionality is implemented, require an option such as:

```powershell
-ForceReregister
```

and make the destructive implications clear.

---

# 23. Partial/broken installation handling

Distinguish at least:

1. SSM Agent absent.
2. SSM Agent installed but apparently unregistered.
3. Registered and healthy.
4. Registered but service stopped.
5. Registration present but apparently unhealthy.
6. Conflicting or ambiguous registration information.

Prefer non-destructive repair.

For example, if the registration exists and the service is merely stopped, start the existing service rather than re-registering.

Do not destroy registration state automatically in ambiguous cases.

Require explicit action for destructive recovery.

---

# 24. Windows diagnostic script

Create:

```text
scripts/windows/check.ps1
```

It must be non-destructive.

Report:

* Windows edition/version.
* Windows build.
* SSM Agent installation status.
* SSM Agent version.
* `AmazonSSMAgent` service existence.
* Service startup configuration.
* Service running state.
* Whether local SSM registration appears to exist.
* Managed-node ID where locally discoverable.
* Relevant recent SSM Agent warnings/errors.

Do not expose:

* Activation Code.
* AWS secret credentials.
* session tokens.
* temporary role credentials.

---

# 25. Windows credential constraints

The SSM setup must not execute:

```text
aws configure
```

It must not require ordinary AWS credentials in:

```text
%USERPROFILE%\.aws\credentials
```

It must not require an SSO profile in:

```text
%USERPROFILE%\.aws\config
```

AWS CLI may or may not exist on the machine; SSM management must not depend on it.

After registration, the machine must be manageable when:

* no AWS user is logged in;
* `AWS_PROFILE` is unset;
* no SSO profile exists;
* no static AWS credentials exist.

---

# 26. `.gitignore`

At minimum:

```text
.terraform/
*.tfstate
*.tfstate.*
*.tfvars
*.tfvars.json
.env
*.log
```

Do not ignore:

```text
.terraform.lock.hcl
```

Ignore any generated local backend configuration or temporary script artifacts that may contain runtime values.

---

# 27. Repository audit

Before completion, inspect the tracked repository and Git history for accidental inclusion of:

* Activation Code.
* Activation ID.
* AWS access-key IDs.
* AWS secret keys.
* AWS session tokens.
* SSO profile names.
* SSO URLs.
* AWS account ID.
* managed-node ID.
* hostname.
* Windows username.
* personal name.
* email address.
* machine serial numbers.
* generated real S3 bucket name.
* Terraform state.
* user-specific absolute paths.

Runtime-discovered values may exist locally or in AWS; they simply must not become committed source material.

---

# 28. Validation: Terraform backend

Verify:

* backend S3 bucket exists;
* public access is blocked;
* encryption is enabled;
* versioning is enabled;
* state locking works;
* bootstrap state is in S3;
* infrastructure state is in S3;
* separate state keys are used.

Then validate from a fresh repository checkout that Terraform can initialize against the existing state and produce a correct plan.

Do not assume anything about the OS of the environment performing this test.

---

# 29. Validation: SSM registration

After running the Windows setup, confirm through Systems Manager that the managed node exists and reports:

```text
PingStatus = Online
```

Discover its `mi-...` identifier dynamically.

Do not commit the identifier.

---

# 30. Validation: Run Command

Use:

```text
AWS-RunPowerShellScript
```

to execute a harmless command such as:

```powershell
Write-Output "ssm-run-command-ok"
```

Verify:

* command accepted;
* command executed;
* command succeeded;
* expected output returned.

---

# 31. Validation: Session Manager

Open an interactive Session Manager session to the Windows machine.

Verify:

* session establishes;
* commands execute;
* output is returned;
* session closes cleanly.

No inbound network configuration should be necessary.

---

# 32. Validation: no Windows AWS user credentials

Confirm that SSM operation does not depend upon:

* an AWS SSO configuration on Windows;
* `AWS_PROFILE`;
* IAM user keys;
* AWS CLI login.

Do not delete unrelated AWS configuration if it happens to exist on the machine.

The purpose is to establish that the SSM setup has no dependency on it.

---

# 33. Validation: SSM Agent restart

Restart the `AmazonSSMAgent` Windows service.

Verify:

* service restarts;
* the same managed-node identity is retained;
* node returns to `Online`;
* Run Command continues to work.

---

# 34. Validation: reboot

Restart Windows.

Where practical, verify reconnection before an interactive user logs in.

Confirm:

* `AmazonSSMAgent` starts automatically;
* node returns to `Online`;
* no AWS login is necessary;
* Run Command works;
* Session Manager works.

This is a key Windows 11 compatibility test.

---

# 35. Validation: sleep/wake

If the machine normally uses sleep:

1. Put the machine to sleep.
2. Confirm it becomes unavailable as expected.
3. Wake it.
4. Confirm SSM Agent reconnects automatically.
5. Confirm the node returns to `Online`.
6. Repeat Run Command.

---

# 36. Validation: repeated setup

Run:

```powershell
.\scripts\windows\setup.ps1
```

again.

Expected:

* existing registration detected;
* same managed-node ID reported;
* service checked;
* no new activation consumed;
* no new identity created.

---

# 37. Optional SSM Agent upgrade test

Because Windows 11 is unsupported, if practical test an SSM Agent update.

Record:

* version before;
* version after;
* whether the service recovered;
* whether the same managed-node identity remained;
* whether Run Command works afterward;
* whether Session Manager works afterward.

Do not make automatic Agent updating part of the initial project unless necessary.

---

# 38. Windows 11 compatibility record

Maintain a small compatibility section in the README.

Record only non-identifying information:

```text
Windows edition/version:
Windows build:
SSM Agent version:
Test date:
```

Record results:

```text
Registration         PASS/FAIL
Run Command          PASS/FAIL
Session Manager      PASS/FAIL
Agent restart        PASS/FAIL
Reboot recovery      PASS/FAIL
Sleep/wake recovery  PASS/FAIL
Agent upgrade        PASS/FAIL/NOT TESTED
```

Do not record:

* hostname;
* username;
* managed-node ID;
* account ID.

---

# 39. README setup workflow

Document the complete bootstrap.

## 1. Clone the repository

```text
git clone ...
cd ...
```

This may be done on any machine capable of running Terraform.

## 2. Make AWS credentials available to Terraform

Terraform uses normal AWS credential discovery.

The expected normal case is that an AWS SSO profile has already been configured in the environment where Terraform runs.

The profile should be selected externally, for example:

```text
AWS_PROFILE=<profile>
```

after the appropriate SSO login.

Do not configure the profile in the repository.

## 3. Bootstrap S3 state

Enter:

```text
terraform/bootstrap
```

Initialize using temporary local state.

Run:

```text
terraform plan
terraform apply
```

This creates the S3 backend bucket.

## 4. Migrate bootstrap state

Retrieve the generated bucket name.

Reinitialize the bootstrap stack against S3 using:

```text
bootstrap/terraform.tfstate
```

Migrate the existing state.

Verify successful migration before removing local state.

## 5. Initialize main infrastructure

Enter:

```text
terraform/infrastructure
```

Initialize against the same S3 bucket using:

```text
infrastructure/terraform.tfstate
```

with native S3 state locking enabled.

## 6. Apply infrastructure

Run:

```text
terraform plan
terraform apply
```

This creates:

* managed-node IAM role;
* SSM policy attachment;
* single-registration SSM hybrid activation.

## 7. Retrieve activation values

Retrieve:

```text
terraform output -raw activation_id
terraform output -raw activation_code
```

Treat these as temporary secrets.

Do not save them in repository files.

## 8. Make the repository scripts available on Windows

Clone or otherwise transfer the repository to the Windows 11 machine.

Do not transfer AWS profiles or credentials with it.

## 9. Run Windows setup

From elevated PowerShell:

```powershell
.\scripts\windows\setup.ps1
```

Provide:

* region;
* Activation ID;
* Activation Code.

No AWS SSO or AWS CLI login should be performed on Windows.

## 10. Validate

Perform the registration, Run Command, Session Manager, restart, reboot, sleep/wake, and idempotence tests.

---

# 40. Terraform activation lifecycle

An SSM activation is the registration mechanism, not the managed node itself.

An activation may:

* expire unused;
* become unusable after its registration limit is consumed;
* be deleted without deregistering an already registered node.

Do not design Terraform so that it continually replaces a consumed activation merely because it can no longer register another machine.

Once the intended Windows machine is registered, the continued usability of that activation is irrelevant.

Avoid perpetual Terraform drift or unnecessary activation replacement.

Document the lifecycle behavior chosen.

---

# 41. Destruction and deregistration

`terraform destroy` must not be described as sufficient to fully remove the Windows machine from SSM.

Deregistering a managed node is a separate operation from deleting its activation or IAM infrastructure.

Document the conceptual cleanup sequence:

1. Deregister the managed node from SSM.
2. Remove/reset its local SSM registration.
3. Optionally uninstall SSM Agent.
4. Destroy AWS infrastructure where appropriate.

Automating cleanup is not required for the initial implementation.

---

# 42. Error handling

PowerShell scripts should fail clearly and safely.

Use appropriate strict error handling, such as:

```powershell
$ErrorActionPreference = "Stop"
```

where suitable.

Errors should identify:

* what operation failed;
* what can be inspected;
* whether registration may have partially completed.

Never include secret values in error output.

Do not automatically destroy partially functioning registration state after an error.

---

# 43. Logging

Do not log:

* Activation Code;
* AWS secret credentials;
* temporary AWS role credentials;
* session tokens.

Take particular care not to echo registration command lines containing activation values.

Avoid temporary files containing secrets where possible.

Delete them securely/appropriately when unavoidable.

---

# 44. Implementation style

Prefer:

* simple Terraform;
* simple PowerShell;
* standard AWS mechanisms;
* explicit checks;
* understandable failure modes.

Avoid:

* unnecessary Terraform modules;
* custom management services;
* permanent AWS credentials;
* unnecessary AWS resources;
* elaborate recovery frameworks;
* attempting to make unsupported Windows Server-specific functionality work.

The repository should establish a small, inspectable foundation for managing a Windows 11 machine through SSM.

---

# 45. Definition of done

The implementation is complete when:

1. A fresh Git clone contains no secrets or identifying information.

2. Terraform runs using normal external AWS credential discovery.

3. The expected AWS SSO profile can be selected externally without its name appearing in the repository.

4. Nothing assumes the Terraform runner uses Windows.

5. Nothing assumes the Terraform runner performs ongoing management of the Windows machine.

6. Bootstrap Terraform creates the S3 backend.

7. Bootstrap state is migrated to S3.

8. Main infrastructure state uses S3 from its first apply.

9. S3 state has:

   * encryption;
   * versioning;
   * public access blocking;
   * state locking.

10. A fresh Terraform environment can recover the configuration from S3.

11. Terraform creates the managed-node IAM role.

12. Terraform creates a single-registration SSM hybrid activation.

13. No required SSM AWS resources are manually configured.

14. Windows setup requires only:

    * the repository scripts;
    * region;
    * Activation ID;
    * Activation Code.

15. Windows setup does not require AWS CLI.

16. Windows setup does not require AWS SSO.

17. Windows setup does not require `AWS_PROFILE`.

18. Windows has no static AWS credentials as part of this system.

19. SSM Agent installs successfully on Windows 11.

20. The machine registers as an SSM hybrid managed node.

21. The node reports `Online`.

22. Run Command successfully executes PowerShell.

23. Session Manager works.

24. Restarting SSM Agent retains the same identity.

25. Rebooting Windows results in automatic reconnection.

26. Sleep/wake reconnection works where applicable.

27. Re-running `setup.ps1` is safe and does not create another registration.

28. README records the tested Windows/SSM Agent versions and compatibility results.

29. No runtime identifiers, Terraform state, activation secrets, AWS credentials, or identifying values have entered Git history.

# Behaviour

Be extremely concise. Sacrifice grammar for the sake of concision
Use subagents for tasks - the main agent should only be used for coordination and communication with the human

# Plan

**Goal:** implement this SPEC as the `aws-pc-mgr` repository (public GitHub, remote `origin` already set).
**Stack:** Terraform >= 1.11 + AWS provider ~> 6.62 (mocked `terraform test`), PowerShell 5.1-compatible module + entry scripts (Pester 5, two tiers), POSIX sh helpers, GitHub Actions CI (no secrets).
**Decisions settled during grilling are normative. Where they conflict with §1–45, §1–45 wins.**

## Test seams (approving this plan confirms them)

1. **Terraform stacks** — `terraform test` (`*.tftest.hcl`, `mock_provider "aws" {}`, `command = apply`, in-memory state, backend ignored, credential-free). Asserts config wiring: resource attributes, trust policy, outputs derived from config.
2. **`scripts/windows/SSMHybrid.psm1` exported functions** — pure logic, tested by `tests/unit/*.Tests.ps1` under PowerShell 7 (Docker `mcr.microsoft.com/powershell:7.4-ubuntu-22.04` locally; same image in CI).
3. **`setup.ps1` / `check.ps1` end-to-end behavior** — `tests/windows/*.Tests.ps1`, Pester 5 on the real machine, post-enrollment, Skip-guarded when unregistered.
4. **`scripts/*.sh` CLI contract** — `tf-init.sh -n` dry-run output and `audit.sh --selftest` asserted by `tests/*.test.sh` in CI (plain sh).

Forbidden (SPEC Plan 2b): any test that greps a script's text for commands.

## Deviations from §8 layout

* No `data.tf`: nothing needs dynamic account/partition/region values (trust principal is a service; policy ARN is global), and §17 forbids hard-coding the account ID — which never appears. Nothing is hard-coded in their place.
* Added beyond §8: `SSMHybrid.psm1`, `tests/`, `scripts/tf-init.sh`, `scripts/audit.sh`, `.github/workflows/ci.yml`, `.PSScriptAnalyzerSettings.psd1`, `terraform/bootstrap/terraform.tfvars.example`. All serve §1 required outputs.
* TDD caveat, stated honestly: the module and shell layers are strict red-first. `setup.ps1`/`check.ps1` thin entry scripts cannot run red on macOS (Windows-only surface), so their tests are written with the scripts and executed red-then-green on the machine in V4 — a script is not "done" until its Windows-tier test has run there.

## Repository layout

```text
/
├── README.md
├── .gitignore
├── .PSScriptAnalyzerSettings.psd1
├── .github/workflows/ci.yml
├── terraform/
│   ├── bootstrap/
│   │   ├── versions.tf        # required_version >= 1.11, aws ~> 6.62
│   │   ├── providers.tf       # provider "aws" {} — no profile, no region
│   │   ├── backend.tf         # terraform { backend "s3" {} }
│   │   ├── variables.tf       # bucket_name (validated)
│   │   ├── state.tf           # bucket + versioning + SSE + PAB + ownership + prevent_destroy
│   │   ├── outputs.tf         # state_bucket_name
│   │   ├── terraform.tfvars.example
│   │   └── tests/bootstrap.tftest.hcl
│   └── infrastructure/
│       ├── versions.tf / providers.tf / backend.tf   # same shape as bootstrap
│       ├── iam.tf             # role + AmazonSSMManagedInstanceCore attachment
│       ├── ssm.tf             # activation: limit 1, generic description, no expiry
│       ├── outputs.tf         # activation_id/activation_code (sensitive), role name
│       └── tests/infrastructure.tftest.hcl
├── scripts/
│   ├── tf-init.sh             # POSIX; bucket from tfvars, region from AWS_REGION
│   ├── audit.sh               # tracked files + history scan; --selftest mode
│   └── windows/
│       ├── SSMHybrid.psm1
│       ├── setup.ps1
│       └── check.ps1
└── tests/
    ├── unit/SSMHybrid.Tests.ps1
    ├── windows/{Setup,Check}.Tests.ps1
    ├── tf-init.test.sh
    └── fixtures/              # synthetic audit fixtures + tfvars fixture
```

---

## Task T0 — scaffold

**Files:** `.gitignore`; first commit.

`.gitignore` (never `.terraform.lock.hcl`):

```gitignore
.terraform/
*.tfstate
*.tfstate.*
*.tfvars
*.tfvars.json
.env
*.log
override.tf
override.tf.json
crash.log
*.exe
```

Steps: write `.gitignore`; `git add SPEC.md .gitignore; git commit -m "chore: spec + plan"`.

## Task T1 — bootstrap stack (TDD, cycles T1.1–T1.6)

Common: `cd terraform/bootstrap && terraform init -backend=false` once (provider download, no creds). Red run: `terraform test` (from stack dir). Commit after each green cycle.

**T1.1 skeleton** — write `versions.tf` (`required_version >= 1.11`, `aws = { source = "hashicorp/aws", version = "~> 6.62" }`), `providers.tf` (`provider "aws" {}`), `backend.tf` (`terraform { backend "s3" {} }`), `variables.tf`:

```hcl
variable "bucket_name" {
  description = "Globally unique S3 bucket for Terraform state. Supply via untracked terraform.tfvars."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.bucket_name)) && !can(regex("--", var.bucket_name))
    error_message = "3-63 chars: lowercase letters, digits, hyphens; no leading/trailing/double hyphen."
  }
}
```

Red test `variables_validation` first (run block with invalid `bucket_name`, `expect_failures` — verify exact syntax against <https://developer.hashicorp.com/terraform/language/tests> during execution), then variables.tf, green, commit. `terraform.tfvars.example`: `bucket_name = "win11-ssm-tfstate-replaceme"`.

**T1.2 bucket + output** — red:

```hcl
mock_provider "aws" {}
run "bucket_from_variable" {
  command = apply
  variables { bucket_name = "win11-ssm-tfstate-replaceme" }
  assert {
    condition     = aws_s3_bucket.state.bucket == "win11-ssm-tfstate-replaceme"
    error_message = "bucket name must come from var.bucket_name"
  }
  assert {
    condition     = output.state_bucket_name == "win11-ssm-tfstate-replaceme"
    error_message = "state_bucket_name output must expose the bucket"
  }
}
```

Green: `state.tf` `resource "aws_s3_bucket" "state { bucket = var.bucket_name; lifecycle { prevent_destroy = true } }` + `outputs.tf`.

**T1.3 versioning** — assert `aws_s3_bucket_versioning.state.versioning_configuration[0].status == "Enabled"`.
**T1.4 public access** — assert all four `aws_s3_bucket_public_access_block.state` booleans `== true`.
**T1.5 SSE** — assert `aws_s3_bucket_server_side_encryption_configuration.state.rule[0].apply_server_side_encryption_by_default[0].sse_algorithm == "AES256"`.
**T1.6 ownership** — assert `aws_s3_bucket_ownership_controls.state.rule[0].object_ownership == "BucketOwnerEnforced"`.

All asserts target config-set attributes; no computed overrides needed. `prevent_destroy` is not test-assertable — verified manually in V1 (destroy-mode plan must refuse).

## Task T2 — infrastructure stack (TDD)

Same skeleton (T2.1, minus variables). Then:

**T2.2 IAM** — red asserts: `aws_iam_role.ssm_hybrid_node.name == "win11-ssm-hybrid-node"`; `jsondecode(aws_iam_role.ssm_hybrid_node.assume_role_policy).Statement[0].Principal.Service == "ssm.amazonaws.com"`; `aws_iam_role_policy_attachment.ssm_core.policy_arn == "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"`. Green:

```hcl
resource "aws_iam_role" "ssm_hybrid_node" {
  name               = "win11-ssm-hybrid-node"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ssm.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  # No aws:SourceAccount/aws:SourceArn conditions: the mi-... identity does not
  # exist until registration, so SourceArn is unknowable at create time and the
  # hybrid-activation role guidance uses the plain service principal.
}
```

**T2.3 activation** — red asserts: `registration_limit == 1`, `description == "Windows hybrid managed node"`, `iam_role == aws_iam_role.ssm_hybrid_node.name`, `expiration_date == null` (deliberately unset — AWS default 24h, avoids ForceNew churn, §40). No tags (tags propagate to the node; nothing identifying).
**T2.4 outputs** — red asserts `output.managed_node_role_name == "win11-ssm-hybrid-node"`. `activation_id`/`activation_code` outputs `sensitive = true` — sensitivity not test-assertable; verified in V2 via `terraform output -json` showing `"sensitive": true`.

## Task T3 — `SSMHybrid.psm1` (strict TDD, one function per cycle)

Local runner:

```sh
docker run --rm -v "$PWD:/src" -w /src mcr.microsoft.com/powershell:7.4-ubuntu-22.04 \
  pwsh -c "Install-Module Pester -MinimumVersion 5.5 -Scope CurrentUser -Force; Invoke-Pester /src/tests/unit -Output Detailed"
```

Contracts (final names; entry scripts and Windows tests must use exactly these):

| Function | Contract |
|---|---|
| `Test-SsmRegion -Region` | true iff `^[a-z]{2}(-gov)?-[a-z]+-\d$` |
| `Test-SsmActivationId -ActivationId` | true iff UUID format |
| `Get-SsmSetupCliUrl -Region` | `https://amazon-ssm-<r>.s3.<r>.amazonaws.com/latest/windows_amd64/ssm-setup-cli.exe`; throws on invalid region |
| `ConvertFrom-SsmRegistrationJson -Json` | object `{ ManagedInstanceId, Region }`; throws on malformed JSON / missing `ManagedInstanceID` / `ManagedInstanceID` not matching `^mi-[a-f0-9]{17}$` / present-but-invalid `Region` (`Test-SsmRegion`, case-sensitive; an absent/empty `Region` is `Region = $null`, not a throw) (source key is `ManagedInstanceID`, exposed as `ManagedInstanceId`) |
| `Get-SsmNodeState -RegistrationJson -ServiceExists -ServiceStatus -ServiceStartType` | returns one of `Absent`, `InstalledUnregistered`, `RegisteredHealthy`, `RegisteredStopped`, `RegisteredUnhealthy`, `Ambiguous` |
| `Get-SsmSetupAction -State [-ForceReregister]` | maps state → `Register`, `StartService`, `NoOperation`, `ManualIntervention`, or `Reregister` (only with `-ForceReregister` + existing registration) |
| `Test-SsmSignature -Status -SignerSubject` | object `{ Valid, Reason }`; Valid iff Status `-eq 'Valid'` and subject matches `*Amazon.com Services LLC*` |
| `Read-SsmSecret -Prompt` | `Read-Host -AsSecureString` + in-memory BSTR decode → plain string; never echoes |

Classification table (`Get-SsmNodeState`):

| Inputs | State |
|---|---|
| no service, no registration file | `Absent` |
| service, no registration file | `InstalledUnregistered` |
| registration parseable + service Running + Automatic | `RegisteredHealthy` |
| registration parseable + service Stopped | `RegisteredStopped` |
| registration parseable + service missing or not Automatic | `RegisteredUnhealthy` |
| registration file present but unparseable/incomplete (including a malformed `ManagedInstanceID` or `Region`) | `Ambiguous` |

Action table (`Get-SsmSetupAction`): `Absent→Register`, `InstalledUnregistered→Register`, `RegisteredHealthy→NoOperation`, `RegisteredStopped→StartService`, `RegisteredUnhealthy→ManualIntervention`, `Ambiguous→ManualIntervention`; `ForceReregister` + any registered state → `Reregister`. Never destructive without the flag (§22/§23).

Red-test example (cycle 1, URL):

```powershell
Describe 'Get-SsmSetupCliUrl' {
  It 'builds the per-region URL' {
    Get-SsmSetupCliUrl -Region 'ap-southeast-2' | Should -Be 'https://amazon-ssm-ap-southeast-2.s3.ap-southeast-2.amazonaws.com/latest/windows_amd64/ssm-setup-cli.exe'
  }
  It 'rejects an invalid region' { { Get-SsmSetupCliUrl -Region 'nope' } | Should -Throw }
}
```

Table-driven Describe blocks for classification/actions (all six states + all five actions + flag combinations), one behavior per It. Windows-only adapters (`Get-SsmServiceInfo`, `Get-SsmRegistrationFileJson`, enrollment runner) live in the module, are NOT unit-tested, and stay thin enough that Windows-tier tests cover them.

## Task T4 — `setup.ps1` (+ `tests/windows/Setup.Tests.ps1`)

`param([string]$Region, [string]$ActivationId, [switch]$ForceReregister)` — activation code always via `Read-SsmSecret` (never a parameter, never history, §20). `$ErrorActionPreference = 'Stop'`. Flow: elevation check → validate inputs (`Test-SsmRegion`, `Test-SsmActivationId`, code non-empty) → gather state via adapters → `Get-SsmSetupAction`:

* `NoOperation` → print mi-id (via `ConvertFrom-SsmRegistrationJson`), verify service, exit 0
* `StartService` → `Start-Service AmazonSSMAgent`, re-verify, exit 0
* `Register` → TLS 1.2 (`[Net.ServicePointManager]::SecurityProtocol -bor Tls12`), download from `Get-SsmSetupCliUrl` to temp, `Get-AuthenticodeSignature` + `Test-SsmSignature` → **refuse on failure**, run `& $exe -register -activation-code=$code -activation-id=$id -region=$region` (command line never echoed/logged, §43), verify registration file + service (exists/running/Automatic), print mi-id, delete temp exe, exit 0
* `ManualIntervention` / `Reregister` → explain implications; `Reregister` requires interactive confirm then `amazon-ssm-agent.exe -register -clear` before re-enrollment; exit 3

Windows-tier tests (run on machine in V4): second-run idempotence (§36 — same mi-id, `NoOperation`, exit 0), signature check on a downloaded exe, refusal path on an unsigned file.

## Task T5 — `check.ps1` (+ `tests/windows/Check.Tests.ps1`)

Read-only; reports §24 items (edition/build via `Get-CimInstance Win32_OperatingSystem`, agent presence/version, service existence/startup/state, registration presence, mi-id, recent `amazon-ssm-agent.log` warnings). Never prints activation code or any credential. Exit 0 healthy / 1 problems found. Windows-tier test asserts mi-id matches registration file and output contains no secure-string material.

## Task T6 — `scripts/tf-init.sh` + `tests/tf-init.test.sh`

POSIX sh (macOS-compatible). Usage: `scripts/tf-init.sh <bootstrap|infrastructure> [-n]`. Region from `AWS_REGION` (required, error if unset); bucket from `$TFVARS_FILE` (default `terraform/bootstrap/terraform.tfvars`, parsed for `bucket_name`); key `<stack>/terraform.tfstate`; `-backend-config use_lockfile=true`; `-migrate-state` appended only when `terraform/<stack>/terraform.tfstate` exists locally. `-n` prints the command without running. Red first: `tests/tf-init.test.sh` (fixture `tests/fixtures/tfvars/terraform.tfvars` via `TFVARS_FILE`) asserts exact printed command for both stacks and errors on missing `AWS_REGION`; run via `sh tests/tf-init.test.sh` in CI. Green: implement. `terraform/bootstrap/terraform.tfvars` is the user's real untracked file — never committed.

## Task T7 — `scripts/audit.sh` + fixtures + self-test

Default mode: scan `git ls-files -z` text + `git log -p --all` (excluding `tests/fixtures/audit/`) for: `AKIA[0-9A-Z]{16}`, `ASIA[0-9A-Z]{16}`, secret-key assignments, `mi-[a-f0-9]{8,}`, UUID literals, `https://…awsapps.com/start`, email addresses, 12-digit account IDs in AWS-keyed contexts. Also: if local `terraform/bootstrap/terraform.tfvars` exists, its bucket name, plus `whoami`/hostname values, must not appear in tracked files. Exit 1 on any finding. `--selftest`: run the same engine over `tests/fixtures/audit/` (synthetic values only) and exit 0 iff every fixture is detected. Red first: `sh -c 'scripts/audit.sh --selftest'` fails before implementation. CI runs both modes.

## Task T8 — CI + analyzer settings

`.github/workflows/ci.yml`, three jobs, no secrets:
1. **terraform** — hashicorp/setup-terraform (1.14.x); per stack: `fmt -check -recursive`, `init -backend=false`, `validate`, `test`; plus `tflint` (no AWS plugin).
2. **pwsh** — same PowerShell container as local; `Invoke-Pester tests/unit`; `Invoke-ScriptAnalyzer -Path scripts/windows -Recurse -Settings .PSScriptAnalyzerSettings.psd1`.
3. **shell** — `sh tests/tf-init.test.sh`, `scripts/audit.sh --selftest`, `scripts/audit.sh`.

`.PSScriptAnalyzerSettings.psd1`: `PSUseCompatibleSyntax` with `TargetVersions = @('5.1','7.0')`. CI itself is validated on first push (V0).

## Task T9 — README

Must contain: overview + architecture (§4 diagram); unsupported-OS statement (§3); prerequisites (TF >= 1.11, external AWS auth e.g. `AWS_PROFILE` after SSO login, Win11 box); tfvars setup (`cp terraform.tfvars.example terraform.tfvars`, pick a globally-unique generic name); full bootstrap workflow (§39 adapted to `tf-init.sh`, incl. migration verify-then-delete-local); Windows setup usage (§20/§21 summary, what setup prints, `-ForceReregister` warning); `check.ps1` usage; activation lifecycle (§40: consumed/expired = no drift, all args ForceNew, re-registration runbook `terraform apply -replace='aws_ssm_activation.node'`); destruction/deregistration sequence (§41: AWS-side `ssm deregister-managed-instance`, local `-register -clear` + `IdentityConsumptionOrder` removal); Session Manager/Run Command pay-as-you-go from 2026-09-30 note; Windows 11 compatibility record template (§38 fields + PASS/FAIL table, sleep/wake row pre-filled N/A) to be filled from V5 results.

## Task T10 — repo audit gate

Run `scripts/audit.sh` (clean pass required), `git log -p | grep` spot-check, walk §27 list. All work committed on `main`. **Push to public GitHub only after explicit user approval** (publishing action).

## Validation phase V (user-executed; I coordinate and record)

* **V0** — push (after approval); CI green.
* **V1** — SSO login, `export AWS_PROFILE=… AWS_REGION=ap-southeast-2`; `cp` tfvars; bootstrap: `mv backend.tf backend.tf.off` → `init` → `apply` (writes local state; `-backend=false` does not select a local backend, so the block must be absent) → `mv backend.tf.off backend.tf`; `scripts/tf-init.sh bootstrap` (migration); `terraform plan` clean; destroy-mode plan refuses (`prevent_destroy`); then delete local state files.
* **V2** — `scripts/tf-init.sh infrastructure`; `apply`; `terraform output -json` shows sensitive flags; record activation outputs for enrollment.
* **V3** — fresh clone to `/tmp`, init via script, `plan` reads state (§14).
* **V4** — clone repo on Windows; elevated `setup.ps1`; run `tests/windows` Pester (red-then-green for entry scripts happens here).
* **V5** — battery: `PingStatus=Online`; Run Command `AWS-RunPowerShellScript` → `ssm-run-command-ok`; Session Manager interactive open/exec/close; agent restart (same mi-id, Online); reboot (auto-reconnect, pre-login if practical, Run Command + Session work); re-run `setup.ps1` (idempotent); agent upgrade if cheap. Sleep/wake: **N/A** (machine does not sleep).
* **V6** — fill compatibility record from V5.
* **V7** — walk §45 definition-of-done 1–29 + final `audit.sh`; push final.

## Security analysis (Plan step 3)

Every §7 bullet → enforcement:

* No inbound exposure — SSM outbound-only; nothing in Terraform/PowerShell opens ports; V5 confirms no firewall changes.
* No IAM user / static keys / SSO on Windows — enrollment needs only region+activation pair (§6); setup.ps1 touches no `~/.aws` path (§25); V4/V5 prove independence (§32).
* Terraform creds external — `provider "aws" {}` and `backend "s3" {}` carry no profile/keys (§5, §13); nothing identifying committed (audit.sh + V7).
* State: BPA ✓ SSE-AES256 ✓ versioning ✓ `use_lockfile` ✓ `prevent_destroy` ✓ private-by-ACL-ownership ✓ — each test-asserted (T1) except prevent_destroy (V1).
* Activation: limit=1, 24h default expiry, `sensitive` outputs, code never a parameter/log/commit; audit.sh patterns catch leakage; registration command line never echoed (§43).
* Supply chain: HTTPS from `amazon-ssm-{region}.s3.{region}.amazonaws.com`, Authenticode + signer check before execution, ssm-setup-cli's own signature validation left enabled, binaries downloaded not committed.
* Least privilege: single AWS-managed policy, service-principal-only trust; SourceArn/SourceAccount omitted because mi-id is unknowable pre-registration (comment in `iam.tf`).
* No silent overwrite: `Get-SsmSetupAction` maps registered states to non-destructive actions; destructive path behind `-ForceReregister` + confirm.
* Remaining accepted risks, stated: activation code briefly visible in process command line during enrollment (no env-var support in ssm-setup-cli; single-user machine; never logged); post-2026-09-30 hybrid Session/Run Command pricing (README note).

## Self-review notes

§1 repo contents → T0–T9. §3/§38 → T9, V5, V6. §5/§13/§15 → T1/T2 skeletons, T6. §7 → analysis above. §8/§9/§26 → T0, T1. §10–§14 → T1, T6, V1–V3. §16–§19 → T2, V2. §20–§25 → T3–T5, V4. §27 → T7, T10, V7. §28 → V1–V3. §29–§37 → V4/V5. §39 → T9. §40/§41 → T9. §42/§43 → T3–T5. §44 → throughout. §45 → V7. Function names single-sourced in the T3 contract table. No placeholder steps.

# Checklist

Execution order; tick as completed.

* [x] T0 — scaffold `.gitignore`, first commit
* [x] T1.1–T1.6 — bootstrap stack, red→green per cycle, committed
* [x] T2.1–T2.4 — infrastructure stack, red→green per cycle, committed
* [x] T3 — `SSMHybrid.psm1`, one function per red→green cycle (8 cycles)
* [x] T4 — `setup.ps1` + `tests/windows/Setup.Tests.ps1`
* [x] T5 — `check.ps1` + `tests/windows/Check.Tests.ps1`
* [x] T6 — `tf-init.sh` + dry-run test (red first)
* [x] T7 — `audit.sh` + fixtures + self-test (red first)
* [x] T8 — CI workflow + `.PSScriptAnalyzerSettings.psd1`
* [x] T9 — README (all sections listed in T9)
* [x] T10 — audit gate pass, all work committed
* [ ] V0 — user approves push; CI green on GitHub
* [ ] V1 — bootstrap apply + state migration + prevent_destroy check (user, SSO)
* [ ] V2 — infrastructure apply; sensitive outputs verified (user)
* [ ] V3 — fresh-checkout plan recovery test (user)
* [ ] V4 — Windows enrollment + on-machine Pester red→green (user)
* [ ] V5 — validation battery: Online / Run Command / Session / restart / reboot / idempotence / upgrade (user; sleep = N/A)
* [ ] V6 — compatibility record filled in README
* [ ] V7 — §45 definition-of-done walk + final audit + final push (user approves)
