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
    credential patterns first (activation code, access key IDs, secret
    access keys, session tokens, private keys); matching lines are withheld
    behind a placeholder and only counted, never printed.

    Exit codes: 0 = healthy, 1 = problems found. Recent log warnings are
    reported for context but do not by themselves count as problems, because
    a healthy agent can log transient warnings.

.PARAMETER AgentLogPath
    Agent log to excerpt warning/error lines from. Defaults to the
    conventional hybrid-agent location under ProgramData; overridable so
    Windows-tier tests can point the script at a fixture log (the same
    seam pattern as Get-SsmRegistrationFileJson's -Path).

.EXAMPLE
    .\check.ps1
#>

param(
    [string]$AgentLogPath
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$problems = New-Object -TypeName System.Collections.Generic.List[string]

# A log line matching this pattern may carry credential material (activation
# code, access key IDs, secret access keys, session tokens, private keys).
# Such lines are never printed: the agent log can echo these back, and this
# diagnostic must not reproduce them (SPEC 24/43). The whole pattern is
# case-insensitive, so the AKIA/ASIA key shapes also match lower-case
# spellings; activation[-_]?code matches ActivationCode, activation-code and
# activation_code; and private[-_]?key matches PrivateKey, IdentityPrivateKey,
# PRIVATE-KEY and private_key as substrings - withholding too much is safe,
# leaking is not.
$credentialLinePattern = '(?i)activation[-_]?code|accesskeyid|secretaccesskey|sessiontoken|private[-_]?key|aws_secret_access_key|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}'
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

$agentExePath = Join-Path -Path $env:ProgramFiles -ChildPath 'Amazon\SSM\amazon-ssm-agent.exe'
if ([string]::IsNullOrEmpty($AgentLogPath)) {
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
    $registrationJson = $null
    try {
        $registrationJson = Get-SsmRegistrationFileJson
    } catch {
        $registrationJson = $null
    }
    if ([string]::IsNullOrEmpty($registrationJson)) {
        Write-Host '  No local SSM registration file was found.'
        Add-Problem 'No local SSM registration: this machine is not enrolled as a hybrid managed node.'
    } else {
        # The raw file is never printed: it may contain key material. Only the
        # parsed managed node ID and region are shown (SPEC 24/43).
        try {
            $registration = ConvertFrom-SsmRegistrationJson -Json $registrationJson
            Write-Host ('  Managed node ID : ' + $registration.ManagedInstanceId)
            Write-Host ('  Region          : ' + $registration.Region)
        } catch {
            Write-Host '  A registration file exists but it could not be parsed.'
            Add-Problem ('The registration file is present but unparseable: ' + $_.Exception.Message)
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
        Write-Host ('  The log exists but could not be read (try an elevated session):')
        Write-Host ('  ' + $AgentLogPath)
    }
} else {
    Write-Host ('  Log file not found: ' + $AgentLogPath)
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
