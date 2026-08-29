<#
.SYNOPSIS
    Read-only SSM hybrid enrollment diagnostic for this Windows machine
    (SPEC 24).

.DESCRIPTION
    Prints clearly labeled sections:

      - Windows edition/version and build;
      - SSM Agent installation status and version;
      - AmazonSSMAgent service existence, startup type, running state;
      - whether a local SSM registration exists, and the managed node ID;
      - recent warning/error lines from the SSM Agent log.

    Strictly read-only: starts nothing, changes nothing, deletes nothing.

    It never prints the activation code or any credential material. The raw
    registration file is parsed for the managed node ID and region only and
    is never dumped, because it may contain key material (SPEC 24/43).
    Warning/error lines excerpted from the agent log are tested against
    credential patterns first (activation code, activation IDs, access key
    IDs, secret access keys, session tokens, private keys); matching lines
    are withheld behind a placeholder and only counted, never printed.

    Exit codes: 0 = healthy, 1 = problems found. Recent log warnings are
    reported for context but do not by themselves count as problems, because
    a healthy agent can log transient warnings; a log that is missing or
    cannot be read does count as a problem, because the log diagnostic was
    then never performed.

.PARAMETER AgentLogPath
    Agent log to excerpt warning/error lines from. Defaults to the
    conventional hybrid-agent location under ProgramData; overridable so
    Windows-tier tests can point the script at a fixture log (the same
    seam pattern as Get-SsmRegistrationFileJson's -Path).

.PARAMETER RegistrationPath
    Registration file to inspect. Defaults to the conventional hybrid-agent
    location under ProgramData (mirroring Get-SsmRegistrationFileJson's -Path
    default); overridable so Windows-tier tests can point the script at a
    fixture file, the same seam pattern as -AgentLogPath.

.EXAMPLE
    .\check.ps1
#>

param(
    [string]$AgentLogPath,
    [string]$RegistrationPath
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$problems = New-Object -TypeName System.Collections.Generic.List[string]

# A log line matching this pattern may carry credential material (activation
# code, activation IDs, access key IDs, secret access keys, session tokens,
# private keys).
# Such lines are never printed: the agent log can echo these back, and this
# diagnostic must not reproduce them (SPEC 24/43). The whole pattern is
# case-insensitive, so the AKIA/ASIA key shapes also match lower-case
# spellings.
#
# Single-source construction: every credential LABEL alternation is built by
# Get-SsmCredentialLabelPattern from a word array joined with '[\s_-]*', so
# matching every spelling of a label - any case variant and any mix of
# whitespace, '-' and '_' separators INSIDE the label ('ActivationCode=',
# 'Activation Code =', 'activation_code', 'ACTIVATION-CODE') - is a property
# of the construction, not of a hand-written and hand-maintained alternation.
# Word lists:
#   activation/code    ActivationCode (the agent log spelling), spaced,
#                      dashed, underscored, any case
#   activation/id      ActivationId, 'Activation ID', activation_id - an
#                      activation ID is not itself a secret, but a log echoing
#                      it identifies the enrollment (and its pairing code
#                      line), so it is withheld too
#   access/key/id      AccessKeyId, 'Access Key ID', access_key_id
#   secret/access/key  SecretAccessKey, "Secret Access Key"
#   session/token      SessionToken, 'Session Token'
#   security/token     SecurityToken, security_token and the signed-request
#                      header spelling X-Amz-Security-Token=
#   private/key        PrivateKey, IdentityPrivateKey, PRIVATE-KEY,
#                      private_key (as substrings)
#   aws/secret/access/key  aws_secret_access_key (subsumed by
#                      secret/access/key above, kept as its own atom to match
#                      the audit-side label exactly)
# The non-label atoms appended to the alternation - the bare token\s*= (Token=
# and unavoidably PaginationToken=-style keys) and the AKIA/ASIA key-ID shapes
# - are not word lists and stay literal. Withholding too much is safe,
# leaking is not.
function Get-SsmCredentialLabelPattern {
    param([string[]]$Words)
    return ($Words -join '[\s_-]*')
}

$credentialLinePattern = '(?i)' + (@(
        (Get-SsmCredentialLabelPattern @('activation', 'code'))
        (Get-SsmCredentialLabelPattern @('activation', 'id'))
        (Get-SsmCredentialLabelPattern @('access', 'key', 'id'))
        (Get-SsmCredentialLabelPattern @('secret', 'access', 'key'))
        (Get-SsmCredentialLabelPattern @('session', 'token'))
        (Get-SsmCredentialLabelPattern @('security', 'token'))
        (Get-SsmCredentialLabelPattern @('private', 'key'))
        (Get-SsmCredentialLabelPattern @('aws', 'secret', 'access', 'key'))
        'token\s*='
        'AKIA[0-9A-Z]{16}'
        'ASIA[0-9A-Z]{16}'
    ) -join '|')
$withheldLineCount = 0

function Write-Section {
    param([string]$Name)
    Write-Host ''
    Write-Host ('=== ' + $Name + ' ===')
}

function Add-Problem {
    param([string]$Message)
    $script:problems.Add($Message)
    Write-Host ('  [PROBLEM] ' + $Message) -ForegroundColor Red
}

$modulePath = Join-Path -Path $PSScriptRoot -ChildPath 'SSMHybrid.psm1'
$moduleLoaded = $false
if (Test-Path -LiteralPath $modulePath -PathType Leaf) {
    Import-Module -Name $modulePath -Force
    $moduleLoaded = $true
} else {
    Add-Problem ("SSMHybrid.psm1 was not found next to this script: " + $modulePath)
}

# Both conventional locations are guarded: on a host without the Windows
# ProgramFiles/ProgramData variables (a non-Windows test container) Join-Path
# would throw on the null parent and abort the report mid-way. On Windows both
# variables are always set, so the guarded form resolves the same paths.
$agentExePath = ''
if (-not [string]::IsNullOrEmpty($env:ProgramFiles)) {
    $agentExePath = Join-Path -Path $env:ProgramFiles -ChildPath 'Amazon\SSM\amazon-ssm-agent.exe'
}
if ([string]::IsNullOrEmpty($AgentLogPath) -and
    -not [string]::IsNullOrEmpty($env:ProgramData)) {
    $AgentLogPath = Join-Path -Path $env:ProgramData -ChildPath 'Amazon\SSM\Logs\amazon-ssm-agent.log'
}

# --- Windows -----------------------------------------------------------------

Write-Section 'Windows'
try {
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    Write-Host ('  Edition / version : ' + $osInfo.Caption)
    Write-Host ('  Version            : ' + $osInfo.Version)
    Write-Host ('  Build              : ' + $osInfo.BuildNumber)
} catch {
    Add-Problem ('Could not read Win32_OperatingSystem: ' + $_.Exception.Message)
}

# --- SSM Agent installation --------------------------------------------------

Write-Section 'SSM Agent installation'
$agentInstalled = Test-Path -LiteralPath $agentExePath -PathType Leaf
if ($agentInstalled) {
    Write-Host ('  Path    : ' + $agentExePath)

    $versionText = ''
    $previousEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $versionOutput = @(& $agentExePath --version 2>&1)
        if ($LASTEXITCODE -eq 0) {
            $versionText = (($versionOutput | ForEach-Object { $_.ToString() }) -join ' ').Trim()
        }
    } catch {
        $versionText = ''
    } finally {
        $ErrorActionPreference = $previousEap
    }
    if ([string]::IsNullOrEmpty($versionText)) {
        # Fall back to the file's version resource.
        $versionInfo = (Get-Item -LiteralPath $agentExePath).VersionInfo
        $versionText = $versionInfo.ProductVersion
        if ([string]::IsNullOrEmpty($versionText)) {
            $versionText = $versionInfo.FileVersion
        }
    }
    if ([string]::IsNullOrEmpty($versionText)) {
        $versionText = 'unknown'
    }
    Write-Host ('  Version : ' + $versionText)
} else {
    Write-Host ('  SSM Agent was not found at ' + $agentExePath)
    Add-Problem 'SSM Agent does not appear to be installed.'
}

# --- AmazonSSMAgent service --------------------------------------------------

Write-Section 'AmazonSSMAgent service'
try {
    $service = Get-Service -Name 'AmazonSSMAgent' -ErrorAction SilentlyContinue
    $serviceCim = Get-CimInstance -ClassName Win32_Service -Filter "Name='AmazonSSMAgent'"
    if ($null -ne $service) {
        Write-Host ('  Name        : AmazonSSMAgent')
        Write-Host ('  Status      : ' + $service.Status)
        if ($null -ne $serviceCim) {
            Write-Host ('  StartupType : ' + $serviceCim.StartMode + ' (Win32_Service StartMode)')
        }
        if ($service.Status -ne 'Running') {
            Add-Problem ('AmazonSSMAgent is not running (status: ' + $service.Status + ').')
        }
        if (($null -ne $serviceCim) -and ($serviceCim.StartMode -ne 'Auto')) {
            Add-Problem ("AmazonSSMAgent startup type is '" + $serviceCim.StartMode + "', expected 'Auto' (Automatic).")
        }
    } else {
        Write-Host '  The AmazonSSMAgent service does not exist.'
        Add-Problem 'AmazonSSMAgent service does not exist.'
    }
} catch {
    Add-Problem ('Could not query the AmazonSSMAgent service: ' + $_.Exception.Message)
}

# --- SSM registration --------------------------------------------------------

Write-Section 'SSM registration'
if ($moduleLoaded) {
    # Resolved here, mirroring Get-SsmRegistrationFileJson's -Path default, so
    # the read-failure report below can name the file; -RegistrationPath
    # overrides it for tests (the same seam pattern as -AgentLogPath).
    if ([string]::IsNullOrEmpty($RegistrationPath) -and
        -not [string]::IsNullOrEmpty($env:ProgramData)) {
        $RegistrationPath = Join-Path -Path $env:ProgramData -ChildPath 'Amazon\SSM\InstanceData\registration'
    }

    if ([string]::IsNullOrEmpty($RegistrationPath) -or
        -not (Test-Path -LiteralPath $RegistrationPath -PathType Leaf)) {
        # State 1: no registration file on disk.
        Write-Host '  No local SSM registration file was found.'
        Add-Problem 'No local SSM registration: this machine is not enrolled as a hybrid managed node.'
    } else {
        # The file exists, and that fact is kept apart from whether it could be
        # read. This script documents that it runs without elevation, and an
        # unelevated session can be denied the registration file's ACL: a read
        # failure must be REPORTED as a read failure, because folding it into
        # the 'no registration file' report above would misdiagnose an
        # enrolled machine as unenrolled (SPEC 24).
        $registrationJson = $null
        $readFailure = $null
        try {
            $registrationJson = Get-SsmRegistrationFileJson -Path $RegistrationPath
        } catch {
            $readFailure = $_
        }

        if ($null -ne $readFailure) {
            # State 2a: present but unreadable. The error's message text is
            # never printed: it can quote file content, and the registration
            # file may carry key material (SPEC 24/43). Only the coarse
            # failure category is reported, never the content.
            $failureCategory = 'read error'
            if (($readFailure.Exception -is [System.UnauthorizedAccessException]) -or
                ($readFailure.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::PermissionDenied)) {
                $failureCategory = 'access denied'
            }
            Write-Host '  The registration file exists but could not be read (try an elevated session):'
            Write-Host ('  ' + $RegistrationPath)
            Write-Host ('  Failure category : ' + $failureCategory)
            Add-Problem ('The registration file exists but could not be read (' + $failureCategory + '): ' + $RegistrationPath)
        } else {
            # The raw file is never printed: it may contain key material. Only
            # the parsed managed node ID and region are shown (SPEC 24/43).
            try {
                $registration = ConvertFrom-SsmRegistrationJson -Json $registrationJson
                # State 3: read and parsed.
                Write-Host ('  Managed node ID : ' + $registration.ManagedInstanceId)
                Write-Host ('  Region          : ' + $registration.Region)
            } catch {
                # State 2b: present and readable but not valid registration
                # data (empty, malformed JSON, or missing the managed-instance
                # key). The parser's message is never printed either: it can
                # quote the file's contents (SPEC 24/43).
                Write-Host '  The registration file exists but could not be parsed.'
                Write-Host ('  ' + $RegistrationPath)
                Add-Problem ('The registration file exists but is not valid registration data: ' + $RegistrationPath)
            }
        }
    }
} else {
    Write-Host '  Skipped: SSMHybrid.psm1 is required to read the registration file.'
}

# --- recent agent log warnings/errors ----------------------------------------

Write-Section 'Recent SSM Agent warnings/errors'
if (Test-Path -LiteralPath $AgentLogPath -PathType Leaf) {
    try {
        $matchingLines = Get-Content -LiteralPath $AgentLogPath -Tail 500 -ErrorAction Stop |
            Where-Object { $_ -match '(?i)warn|error' } |
            Select-Object -Last 50
        if ($matchingLines) {
            if ($matchingLines -is [string]) {
                $matchingLines = @($matchingLines)
            }
            Write-Host ('  Last ' + $matchingLines.Count + ' warning/error line(s) from:')
            Write-Host ('  ' + $AgentLogPath)
            foreach ($line in $matchingLines) {
                if ($line -match $credentialLinePattern) {
                    # Never print a line that may carry credential material;
                    # withhold it behind a placeholder and count it for the
                    # summary (SPEC 24/43).
                    $withheldLineCount = $withheldLineCount + 1
                    Write-Host '  [line withheld: possible credential material]'
                    continue
                }
                Write-Host ('  ' + $line)
            }
        } else {
            Write-Host ('  No warning/error lines in the last 500 lines of:')
            Write-Host ('  ' + $AgentLogPath)
        }
    } catch {
        # Like the registration read failure above, this must be recorded as a
        # problem, not just hinted at: otherwise a machine whose only fault is
        # an unreadable log would exit 0 with 'All checks passed' even though
        # this diagnostic was never performed. And, also like it, only the
        # coarse failure category is reported, never the raw error text.
        $logReadFailure = $_
        $failureCategory = 'read error'
        if (($logReadFailure.Exception -is [System.UnauthorizedAccessException]) -or
            ($logReadFailure.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::PermissionDenied)) {
            $failureCategory = 'access denied'
        }
        Write-Host ('  The log exists but could not be read (try an elevated session):')
        Write-Host ('  ' + $AgentLogPath)
        Write-Host ('  Failure category : ' + $failureCategory)
        Add-Problem ('The agent log exists but could not be read (' + $failureCategory + '): ' + $AgentLogPath)
    }
} else {
    # Same reasoning as the unreadable log above: a missing log means the
    # diagnostic was never performed, so it must not be possible to exit 0
    # with 'All checks passed' over it.
    Write-Host ('  Log file not found: ' + $AgentLogPath)
    Add-Problem ('The agent log was not found: ' + $AgentLogPath)
}

# --- summary -----------------------------------------------------------------

Write-Section 'Summary'
if ($withheldLineCount -gt 0) {
    Write-Host ('  ' + $withheldLineCount + ' recent log warning/error line(s) withheld as possible credential material.')
}
if ($problems.Count -eq 0) {
    Write-Host '  All checks passed; this machine looks like a healthy SSM hybrid managed node.'
    exit 0
}
Write-Host ('  Problems found (' + $problems.Count + '):')
foreach ($problem in $problems) {
    Write-Host ('  - ' + $problem)
}
exit 1
