<#
.SYNOPSIS
    Enrolls this Windows 11 machine as an AWS Systems Manager (SSM) hybrid
    managed node (SPEC 20-23).

.DESCRIPTION
    Elevated entry script. All decision logic lives in SSMHybrid.psm1; this
    script gathers local facts, asks the module what to do, then does it.

    Flow: elevation check -> validate any supplied parameters (fast exit 2
    on invalid supplied values) -> classify local state -> execute the
    mapped action.

    Actions and exit codes:
        NoOperation          already registered and healthy         exit 0
        StartService         registration present, service stopped exit 0
        Register             install + register this machine       exit 0
        ManualIntervention   ambiguous/unhealthy; nothing changed  exit 3
        Reregister           -ForceReregister + confirmation:
                             stop agent, clear registration,
                             leave agent stopped                  exit 3

    Any other refusal or failure exits 1; invalid inputs exit 2.

    Interactive prompts happen only when enrollment is actually required:
    region and activation ID supplied as parameters are validated up front,
    but when omitted they are asked for ONLY inside the Register branch.
    NoOperation, StartService, ManualIntervention, and Reregister never need
    an activation, so a parameterless re-run on an already-enrolled machine
    asks for nothing at all and simply reports health (SPEC 20/22/36).

    The activation code is never a parameter and never appears on a command
    line (SPEC 20): it is read with a masked prompt via Read-SsmSecret, and
    only when a registration is actually about to run. It is never printed
    or logged, and the registration command line is executed by the module
    without echoing it (SPEC 43).

    The script never deregisters, deletes registration data, or consumes
    another activation on its own (SPEC 22), never runs 'aws configure',
    never performs an SSO login, and never writes under the user's .aws
    directory (SPEC 25).

.PARAMETER Region
    AWS region of the hybrid activation, for example ap-southeast-2.
    Validated immediately when supplied. Prompted for only when the Register
    action is about to run and no valid region is known yet.

.PARAMETER ActivationId
    SSM hybrid activation ID (UUID), from
    'terraform output -raw activation_id'. Validated immediately when
    supplied. Prompted for only when the Register action is about to run and
    no valid activation ID is known yet. A value typed on the command line is
    recorded in PSReadLine history in plain text, so the parameterless
    interactive run is preferred (SPEC 20).

.PARAMETER ForceReregister
    Destructive: after an explicit interactive confirmation, stops the
    AmazonSSMAgent service, clears the existing local registration, and
    leaves the service STOPPED, then exits 3. Re-enrollment is a fresh run
    of this script with a new activation; that Register run starts the
    service again.

.EXAMPLE
    .\setup.ps1

    Preferred: fully interactive. Region and activation ID are prompted for,
    the activation code is prompted for masked, and nothing entered at a
    prompt reaches the command line or PSReadLine history (SPEC 20).

.EXAMPLE
    .\setup.ps1 -Region ap-southeast-2

    Scripted use. -ActivationId exists for scripting too, but a value typed
    on the command line is recorded in PSReadLine history; prefer the prompts.
#>
param(
    [string]$Region,
    [string]$ActivationId,
    [switch]$ForceReregister
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# --- helpers ----------------------------------------------------------------

function Write-Step {
    param([string]$Message)
    Write-Host "[setup] $Message"
}

function Write-Fail {
    param([string]$Message)
    Write-Host "[setup] ERROR: $Message" -ForegroundColor Red
}

# Resolve one required input: keep the parameter when it is already valid,
# otherwise prompt (up to three attempts). Returns $null when no valid value
# was obtained, so the caller can exit with code 2.
function Resolve-SsmInput {
    param(
        [string]$Value,
        [string]$Label,
        [string]$Example,
        [scriptblock]$IsValid
    )

    if (& $IsValid $Value) {
        return $Value
    }

    if (-not [string]::IsNullOrEmpty($Value)) {
        Write-Host "The supplied $Label is not valid."
    }
    Write-Host "Enter the $Label (for example $Example)."

    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $candidate = Read-Host -Prompt $Label
        if (& $IsValid $candidate) {
            return $candidate
        }
        $remaining = 4 - $attempt
        Write-Host "Invalid $Label. Attempt(s) remaining: $remaining."
    }
    return $null
}

# Read the activation code with a masked prompt. It is only requested when
# the Register action is about to run, never for already-registered states,
# so an idempotent re-run never asks for bootstrap secrets (SPEC 20/36).
function Read-ActivationCode {
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $code = Read-SsmSecret -Prompt 'SSM activation code (input is masked)'
        if (-not [string]::IsNullOrEmpty($code)) {
            return $code
        }
        Write-Host 'The activation code must not be empty.'
    }
    return $null
}

# Parsed local registration, or $null when no registration file exists.
# Throws when the file exists but cannot be parsed.
function Get-SsmRegistration {
    $json = Get-SsmRegistrationFileJson
    if ([string]::IsNullOrEmpty($json)) {
        return $null
    }
    return ConvertFrom-SsmRegistrationJson -Json $json
}

# Registration RE-read for an action that already relies on one, or the
# ambiguous exit. Classification read and parsed this file moments ago, so
# when Get-SsmRegistration now returns $null (file deleted or emptied under
# us) or throws (file rewritten into something unreadable or unparseable,
# or its read now fails), the script's decision no longer matches the
# machine: another actor changed it between the classification and this
# read. That is exactly the ambiguity an unparseable registration earns at
# classification, so the same verdict is given here (exit 3, nothing
# modified, a human decides - SPEC 23) instead of acting on stale facts.
# Returns the parsed registration, or never returns.
function Get-SsmRegistrationOrAmbiguousExit {
    $registration = $null
    try {
        $registration = Get-SsmRegistration
    } catch {
        # Thrown means the file exists NOW but cannot be read or parsed NOW.
        $registration = $null
    }

    if ($null -ne $registration) {
        return $registration
    }

    Write-Fail 'The local registration vanished or changed since the state was classified above.'
    Write-Host 'It was readable and parseable moments ago, and now it is gone, empty, unreadable,'
    Write-Host 'or unparseable. Nothing was modified and nothing was deleted. The machine is in'
    Write-Host 'the same ambiguous state an unparseable registration earns at classification'
    Write-Host '(SPEC 23): no automatic action is taken from here.'
    Write-Host ('Inspect: the registration file under ' + $env:ProgramData + '\Amazon\SSM\InstanceData;')
    Write-Host 'Get-Service AmazonSSMAgent; the SSM Agent log. Repair the cause manually, or'
    Write-Host 're-run with -ForceReregister to discard the local registration and enroll'
    Write-Host 'afresh (destructive; consumes a new activation).'
    exit 3
}

# Service facts, or fail closed. Get-SsmServiceInfo never throws for a
# MISSING service (it reports Exists = $false) but DOES throw for a FAILED
# query, because a failed query must never be readable as the service being
# absent - notably in the Reregister path, where that would let the clear
# proceed against an agent that may still be running. Every call site after
# the initial classification (which has its own try/catch) goes through this
# wrapper, so a mid-script query failure stops the script with exit 1.
function Get-ServiceInfoOrFail {
    try {
        return Get-SsmServiceInfo
    } catch {
        Write-Fail ("Could not query the AmazonSSMAgent service: " + $_.Exception.Message)
        Write-Host 'A failed service query must not be read as the service being absent.'
        Write-Host 'Nothing further was changed. Inspect the error and re-run.'
        exit 1
    }
}

# --- 1. elevation (SPEC 21 step 1) ------------------------------------------

$windowsPrincipal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList ([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $windowsPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Fail 'This script must run in an elevated PowerShell session.'
    Write-Host 'Inspect/action: reopen PowerShell with "Run as administrator" and run the'
    Write-Host 'script again. Nothing was changed.'
    exit 1
}

# --- 2. module --------------------------------------------------------------

$modulePath = Join-Path -Path $PSScriptRoot -ChildPath 'SSMHybrid.psm1'
if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
    Write-Fail "Required module not found next to this script: $modulePath"
    exit 1
}
Import-Module -Name $modulePath -Force

# --- 3. supplied inputs (SPEC 20) -------------------------------------------
# A parameter actually supplied on the command line is validated NOW, so a bad
# supplied value fails fast with exit 2 before anything is inspected or
# classified. Values NOT supplied are deliberately NOT prompted for here:
# region and activation ID are only consumed by the Register action, so they
# are resolved inside that branch below. NoOperation, StartService,
# ManualIntervention, and Reregister therefore run to completion on a
# parameterless invocation without ever asking for activation values (SPEC
# 20/22/36).

if (-not [string]::IsNullOrEmpty($Region)) {
    $Region = Resolve-SsmInput -Value $Region -Label 'AWS region' -Example 'ap-southeast-2' -IsValid { param($Value) Test-SsmRegion -Region $Value }
    if ([string]::IsNullOrEmpty($Region)) {
        Write-Fail 'No valid AWS region was provided.'
        exit 2
    }
}

if (-not [string]::IsNullOrEmpty($ActivationId)) {
    $ActivationId = Resolve-SsmInput -Value $ActivationId -Label 'SSM activation ID' -Example 'a UUID, from: terraform output -raw activation_id' -IsValid { param($Value) Test-SsmActivationId -ActivationId $Value }
    if ([string]::IsNullOrEmpty($ActivationId)) {
        Write-Fail 'No valid SSM activation ID was provided.'
        exit 2
    }
}

# --- 4. local state (SPEC 21 steps 3-5, SPEC 23) ----------------------------

Write-Step 'Inspecting the local SSM Agent installation and registration...'

$serviceInfo = $null
try {
    $serviceInfo = Get-SsmServiceInfo
} catch {
    Write-Fail ("Could not query the AmazonSSMAgent service. Nothing was changed. Inspect the error: " + $_.Exception.Message)
    exit 1
}

$registrationJson = $null
try {
    $registrationJson = Get-SsmRegistrationFileJson
} catch {
    Write-Fail ("Could not read the local SSM registration file. Nothing was changed and nothing was deleted. Inspect the error: " + $_.Exception.Message)
    Write-Host 'Registration may be partially complete; resolve the read problem manually.'
    exit 3
}

$nodeState = Get-SsmNodeState -RegistrationJson $registrationJson -ServiceExists $serviceInfo.Exists -ServiceStatus $serviceInfo.Status -ServiceStartType $serviceInfo.StartType
$action = Get-SsmSetupAction -State $nodeState -ForceReregister:$ForceReregister
Write-Step ("State: " + $nodeState + ". Planned action: " + $action + ".")

# --- 5. actions -------------------------------------------------------------

if ($action -eq 'NoOperation') {
    $registration = Get-SsmRegistrationOrAmbiguousExit

    # Re-verify the service before declaring health (SPEC 22). The health
    # verdict requires AmazonSSMAgent to be BOTH Running AND Automatic at
    # re-query time - not merely as classified above. Drift that appeared in
    # between, for example the service stopping or Group Policy flipping the
    # startup type to Manual/Disabled, is repaired the same way the
    # StartService path repairs it (start the service, restore Automatic),
    # and the invariant is then re-queried and must hold, or the run fails
    # closed.
    $serviceStarted = $false
    $startupRestored = $false
    $currentService = Get-ServiceInfoOrFail
    if ($currentService.Status -ne 'Running') {
        Write-Step 'AmazonSSMAgent stopped since the check above; starting it (registration untouched).'
        Start-Service -Name 'AmazonSSMAgent'
        $serviceStarted = $true
        $currentService = Get-ServiceInfoOrFail
    }
    if ($currentService.StartType -ne 'Automatic') {
        Write-Step ("Restoring AmazonSSMAgent startup type to Automatic (was '" + $currentService.StartType + "').")
        Set-Service -Name 'AmazonSSMAgent' -StartupType Automatic
        $startupRestored = $true
        $currentService = Get-ServiceInfoOrFail
    }
    if (($currentService.Status -ne 'Running') -or ($currentService.StartType -ne 'Automatic')) {
        Write-Fail ("AmazonSSMAgent is not Running/Automatic at the re-check (status '" + $currentService.Status + "', startup '" + $currentService.StartType + "').")
        Write-Host 'Another actor may be re-applying a service configuration, for example Group'
        Write-Host 'Policy. Inspect: Get-Service AmazonSSMAgent and the SSM Agent log under'
        Write-Host ($env:ProgramData + '\Amazon\SSM\Logs. The existing registration was NOT modified.')
        exit 1
    }

    Write-Host ''
    Write-Host ('Managed node ID : ' + $registration.ManagedInstanceId)
    # The region shown here comes from the local registration record, not from
    # an operator-supplied value: this path never asks for one, so the line is
    # simply omitted when the record carries no Region.
    if (-not [string]::IsNullOrEmpty($registration.Region)) {
        Write-Host ('Region          : ' + $registration.Region)
    }
    Write-Host ('Service         : AmazonSSMAgent ' + $currentService.Status + ' / startup ' + $currentService.StartType)
    if ($serviceStarted -or $startupRestored) {
        Write-Step 'Drift found at the re-check was repaired; the existing registration was untouched and no activation was consumed (SPEC 22/36).'
    } else {
        Write-Step 'Already registered and healthy. No changes made; no activation consumed (SPEC 22/36).'
    }
    exit 0
}

if ($action -eq 'StartService') {
    $registration = Get-SsmRegistrationOrAmbiguousExit
    Write-Step 'Registration exists and AmazonSSMAgent is stopped; starting the existing service (SPEC 23).'

    # Restore Automatic startup before starting, like the Register path: a
    # Manual/Disabled start type would leave the node offline again after the
    # next reboot even though it is Running now.
    $currentService = Get-ServiceInfoOrFail
    $startupRestored = $false
    if ($currentService.StartType -ne 'Automatic') {
        Write-Step ("Restoring AmazonSSMAgent startup type to Automatic (was '" + $currentService.StartType + "').")
        Set-Service -Name 'AmazonSSMAgent' -StartupType Automatic
        $startupRestored = $true
    }

    Start-Service -Name 'AmazonSSMAgent'
    $currentService = Get-ServiceInfoOrFail

    # The verdict needs BOTH facts, so BOTH are re-verified after the start:
    # the restore above can itself be undone between the Set-Service and
    # this re-query (Group Policy re-applying a Manual/Disabled start type),
    # and a service that is Running but not Automatic is the same
    # offline-after-next-reboot state the restore exists to prevent.
    if ($currentService.StartType -ne 'Automatic') {
        Write-Step ("Restoring AmazonSSMAgent startup type to Automatic (was '" + $currentService.StartType + "').")
        Set-Service -Name 'AmazonSSMAgent' -StartupType Automatic
        $startupRestored = $true
        $currentService = Get-ServiceInfoOrFail
    }
    if (($currentService.Status -ne 'Running') -or ($currentService.StartType -ne 'Automatic')) {
        Write-Fail ("AmazonSSMAgent is not Running/Automatic after starting it (status '" + $currentService.Status + "', startup '" + $currentService.StartType + "').")
        Write-Host 'Another actor may be re-applying a service configuration, for example Group'
        Write-Host 'Policy. Inspect: Get-Service AmazonSSMAgent and the SSM Agent log. The existing'
        Write-Host 'registration was NOT modified and no activation was consumed.'
        exit 1
    }

    Write-Host ''
    Write-Host ('Managed node ID : ' + $registration.ManagedInstanceId)
    Write-Host ('Service         : AmazonSSMAgent ' + $currentService.Status + ' / startup ' + $currentService.StartType)
    if ($startupRestored) {
        Write-Step 'Service started and Automatic startup restored; existing registration preserved.'
    } else {
        Write-Step 'Service started; existing registration preserved.'
    }
    exit 0
}

if ($action -eq 'Register') {
    Write-Host 'This machine is not registered as an SSM managed node yet.'
    Write-Host 'The AWS ssm-setup-cli will be downloaded over HTTPS, its Authenticode'
    Write-Host 'signature verified (Amazon.com Services LLC), and only then executed.'

    # Activation values are resolved HERE, only once a registration is actually
    # about to run (SPEC 20): values already supplied as parameters were
    # validated up front and pass straight through; missing ones are prompted
    # for now, and the code is always read masked. Every other action above
    # completed without asking for any of these.
    $Region = Resolve-SsmInput -Value $Region -Label 'AWS region' -Example 'ap-southeast-2' -IsValid { param($Value) Test-SsmRegion -Region $Value }
    if ([string]::IsNullOrEmpty($Region)) {
        Write-Fail 'No valid AWS region was provided.'
        exit 2
    }

    $ActivationId = Resolve-SsmInput -Value $ActivationId -Label 'SSM activation ID' -Example 'a UUID, from: terraform output -raw activation_id' -IsValid { param($Value) Test-SsmActivationId -ActivationId $Value }
    if ([string]::IsNullOrEmpty($ActivationId)) {
        Write-Fail 'No valid SSM activation ID was provided.'
        exit 2
    }

    # The trailing marker is the audit's documented exemption for a
    # label-shape collision (see the audit.sh header): the lowercased,
    # separator-wildcarded activation-code detector correctly cannot tell
    # this assignment from a leak, and must not be narrowed to miss one, so
    # this known-safe line - the value is a function invocation, not a
    # credential - carries the marker instead.
    $activationCode = Read-ActivationCode # audit-allow:synthetic
    if ([string]::IsNullOrEmpty($activationCode)) {
        Write-Fail 'No activation code was provided.'
        exit 2
    }

    $setupCliUrl = Get-SsmSetupCliUrl -Region $Region
    Write-Step ("Downloading and verifying the AWS setup CLI for region " + $Region + ".")
    Write-Step ("URL: " + $setupCliUrl)

    try {
        # Invoke-SsmEnrollment (SSMHybrid.psm1) performs SPEC 21 steps 6-9:
        # forces TLS 1.2 where needed, downloads ssm-setup-cli to a temp file,
        # REFUSES to run any binary whose Authenticode signature is not Valid
        # and signed by Amazon.com Services LLC, runs the registration without
        # ever echoing or logging the command line (SPEC 43), and removes the
        # temp download directory afterwards (SPEC 21 step 16) with bounded
        # retries. A leftover after a successful enrollment is NOT a failure:
        # the module warns naming the path and reports it on this result, so
        # the summary at the end can stay truthful.
        $enrollmentResult = Invoke-SsmEnrollment -Region $Region -ActivationId $ActivationId -ActivationCode $activationCode
    } catch {
        Write-Fail ('Registration did not complete: ' + $_.Exception.Message)
        Write-Host 'Activation values were not logged. Registration may have partially'
        Write-Host 'completed: inspect the local registration file, the AmazonSSMAgent'
        Write-Host 'service, and the SSM Agent log before re-running. Nothing was deleted.'
        exit 1
    } finally {
        # Clear bootstrap secrets from memory as soon as possible (SPEC 21 step 17).
        $activationCode = $null
        Remove-Variable -Name activationCode -ErrorAction SilentlyContinue
    }

    Write-Step 'Registration command finished. Verifying the local result...'

    $registrationAfter = $null
    try {
        $registrationAfter = Get-SsmRegistration
    } catch {
        Write-Fail 'The local registration file is present but could not be parsed.'
        Write-Host 'Registration may have partially completed. Inspect: the registration file'
        Write-Host 'under ProgramData\Amazon\SSM, Get-Service AmazonSSMAgent, and the SSM Agent'
        Write-Host 'log. Nothing was deleted; do not re-run with -ForceReregister blindly.'
        exit 1
    }
    if ($null -eq $registrationAfter) {
        Write-Fail 'No local registration file was found after registration.'
        Write-Host 'The registration may have partially completed or failed silently.'
        Write-Host 'Inspect: the SSM Agent log and the AmazonSSMAgent service. Nothing was deleted.'
        exit 1
    }

    $serviceAfter = Get-ServiceInfoOrFail
    if (-not $serviceAfter.Exists) {
        Write-Fail 'The AmazonSSMAgent service does not exist after registration.'
        Write-Host 'Inspect: installed services and the SSM Agent installation log. The'
        Write-Host 'registration data was NOT deleted.'
        exit 1
    }
    if ($serviceAfter.StartType -ne 'Automatic') {
        Write-Step ("Setting AmazonSSMAgent startup type to Automatic (was '" + $serviceAfter.StartType + "').")
        Set-Service -Name 'AmazonSSMAgent' -StartupType Automatic
        $serviceAfter = Get-ServiceInfoOrFail
    }
    if ($serviceAfter.Status -ne 'Running') {
        Write-Step 'AmazonSSMAgent is not running after registration; starting it.'
        Start-Service -Name 'AmazonSSMAgent'
        $serviceAfter = Get-ServiceInfoOrFail
    }
    if (($serviceAfter.Status -ne 'Running') -or ($serviceAfter.StartType -ne 'Automatic')) {
        Write-Fail ("AmazonSSMAgent is not Running/Automatic (status '" + $serviceAfter.Status + "', startup '" + $serviceAfter.StartType + "').")
        Write-Host 'Registration data was NOT deleted. Inspect: Get-Service AmazonSSMAgent and the'
        Write-Host 'SSM Agent log; the node may still be completing its first connection.'
        exit 1
    }

    Remove-Variable -Name ActivationId -ErrorAction SilentlyContinue

    Write-Host ''
    Write-Host 'Registration complete.'
    Write-Host ('Managed node ID : ' + $registrationAfter.ManagedInstanceId)
    Write-Host ('Region          : ' + $registrationAfter.Region)
    Write-Host ('Service         : AmazonSSMAgent ' + $serviceAfter.Status + ' / startup ' + $serviceAfter.StartType)
    Write-Host 'It can take a few minutes before the node reports Online in AWS Systems Manager.'
    if ($enrollmentResult.TempDownloadRemoved) {
        Write-Step 'Temporary download removed; activation values cleared from memory.'
    } else {
        # The module already warned when its removal retries ran out (SPEC 21
        # step 16 is a postcondition, but a leftover is not a failed
        # enrollment). The summary must not repeat the unconditional removal
        # claim while the download is still on disk: nothing secret is in it -
        # it is the AWS ssm-setup-cli executable - but the operator's mental
        # model must match the filesystem, so name the path and the fix.
        Write-Host ('WARNING: the temporary download could not be removed and is still on disk:') -ForegroundColor Yellow
        Write-Host ('  ' + $enrollmentResult.TempDownloadPath)
        Write-Host 'Nothing secret is in it (the AWS ssm-setup-cli executable); delete it manually'
        Write-Host 'once any antivirus scan has released the lock, for example:'
        Write-Host ("  Remove-Item -LiteralPath '" + $enrollmentResult.TempDownloadPath + "' -Recurse -Force")
        Write-Step 'Activation values cleared from memory.'
    }
    exit 0
}

if ($action -eq 'ManualIntervention') {
    Write-Fail ("This machine is in the '" + $nodeState + "' state; nothing was changed automatically (SPEC 23).")
    if ($nodeState -eq 'RegisteredUnhealthy') {
        Write-Host 'A local registration record parses, but the AmazonSSMAgent service is missing,'
        Write-Host 'not Running, or not configured for Automatic startup.'
        Write-Host 'Inspect: Get-Service AmazonSSMAgent;'
        Write-Host ('          Get-CimInstance Win32_Service -Filter "Name=''AmazonSSMAgent''" (State, StartMode);')
        Write-Host ('          the SSM Agent log under ' + $env:ProgramData + '\Amazon\SSM\Logs.')
    } else {
        Write-Host 'A local registration file exists but cannot be parsed, so its contents cannot'
        Write-Host 'be trusted for an automatic decision (SPEC 23).'
        Write-Host ('Inspect: the registration file under ' + $env:ProgramData + '\Amazon\SSM\InstanceData;')
        Write-Host '          Get-Service AmazonSSMAgent; the SSM Agent log.'
    }
    Write-Host 'Registration may be partially complete. Nothing was deleted or deregistered.'
    Write-Host 'Repair the cause manually, or re-run with -ForceReregister to discard the local'
    Write-Host 'registration and enroll afresh (destructive; consumes a new activation).'
    exit 3
}

if ($action -eq 'Reregister') {
    Write-Host 'Reregistration was requested with -ForceReregister. This is DESTRUCTIVE:'
    Write-Host '  - AmazonSSMAgent is stopped first and left STOPPED after the clear;'
    Write-Host '  - the local SSM registration will be cleared (amazon-ssm-agent -register -clear);'
    Write-Host '  - the current managed node ID stops being used by this machine;'
    Write-Host '  - the node remains registered in AWS until separately deregistered there;'
    Write-Host '  - re-enrollment consumes a NEW activation and yields a NEW managed node ID.'

    $confirmation = Read-Host -Prompt 'Type yes to clear the local registration'
    if ($confirmation -cne 'yes') {
        Write-Host 'Not confirmed. Nothing was changed.'
        exit 3
    }

    $agentExe = Join-Path -Path $env:ProgramFiles -ChildPath 'Amazon\SSM\amazon-ssm-agent.exe'
    if (-not (Test-Path -LiteralPath $agentExe -PathType Leaf)) {
        Write-Fail ("amazon-ssm-agent.exe was not found at " + $agentExe + ".")
        Write-Host 'Nothing was changed. Clear the registration manually once the agent exists:'
        Write-Host ("  Stop-Service AmazonSSMAgent")
        Write-Host ("  & '" + $agentExe + "' -register -clear")
        exit 3
    }

    # Stop the agent BEFORE the clear, the same sequence the README's manual
    # reset documents: a running agent can hold or rewrite its registration
    # data while -register -clear runs. Already-stopped and service-missing
    # are both tolerated; the clear only proceeds once the service is verified
    # stopped. The service is deliberately NOT started again in this run: with
    # no registration left it has nothing to run with, and the fresh Register
    # run (a new activation) brings it back.
    $serviceBeforeClear = Get-ServiceInfoOrFail
    if (-not $serviceBeforeClear.Exists) {
        Write-Step 'AmazonSSMAgent service not found; nothing to stop before the clear.'
    } elseif ($serviceBeforeClear.Status -eq 'Stopped') {
        Write-Step 'AmazonSSMAgent is already stopped.'
    } else {
        Write-Step ("Stopping AmazonSSMAgent before the clear (was '" + $serviceBeforeClear.Status + "').")
        try {
            Stop-Service -Name 'AmazonSSMAgent'
        } catch {
            Write-Fail ("Stopping AmazonSSMAgent failed: " + $_.Exception.Message)
            Write-Host 'Nothing was changed and the registration was NOT cleared. Inspect:'
            Write-Host 'Get-Service AmazonSSMAgent and the SSM Agent log, then re-run.'
            exit 3
        }
    }

    $serviceAtClear = Get-ServiceInfoOrFail
    if ($serviceAtClear.Exists -and ($serviceAtClear.Status -ne 'Stopped')) {
        Write-Fail ("AmazonSSMAgent did not stop (status '" + $serviceAtClear.Status + "'); the registration was NOT cleared.")
        Write-Host 'Inspect: Get-Service AmazonSSMAgent and the SSM Agent log, then re-run.'
        exit 3
    }

    Write-Step 'Clearing the local registration (amazon-ssm-agent -register -clear).'
    # Native-call discipline, mirroring Invoke-SsmEnrollment in
    # SSMHybrid.psm1: under this script's $ErrorActionPreference = 'Stop',
    # redirected stderr from a native command can surface on Windows
    # PowerShell 5.1 as a terminating NativeCommandError, which would bypass
    # the $LASTEXITCODE branch below entirely - and a clear that succeeded
    # while merely writing a warning to stderr would be misreported as a
    # failure. So: relax ErrorActionPreference around the call, discard BOTH
    # streams (the agent's text never reaches the console), restore the
    # preference in finally, and judge the outcome by $LASTEXITCODE alone -
    # but only once $LASTEXITCODE has proved the agent actually launched: a
    # launch that never happened (the executable quarantined or deleted
    # between the existence check above and the invocation) leaves it
    # holding whatever an earlier native call in this session left there -
    # commonly 0 - which the exit-code branch would read as a successful
    # clear. The sentinel closes that hole: $LASTEXITCODE is reset to $null
    # before the call, and a still-$null value after it is a hard failure
    # of the clear. Only a genuinely captured exit code 0 may print the
    # success message below.
    $previousEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $clearExitCode = $null
    try {
        $global:LASTEXITCODE = $null
        & $agentExe -register -clear 2>&1 | Out-Null
        $clearExitCode = $LASTEXITCODE
    } catch {
        # The launch failure itself (nonexistent or non-runnable image). It
        # can surface as a terminating error even under 'Continue'; it is
        # absorbed here so the sentinel branch below reports the failure in
        # this block's own terms (nothing on this command line is secret).
        $clearExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousEap
    }
    if ($null -eq $clearExitCode) {
        Write-Fail ("Clearing the local registration failed: " + $agentExe + " could not be launched, so the clear never ran.")
        Write-Host 'Nothing was cleared. The agent executable passed the existence check above but could'
        Write-Host 'not be started (for example quarantined while the service was being stopped). Inspect'
        Write-Host 'the agent installation and re-run.'
        exit 3
    }
    if ($clearExitCode -ne 0) {
        Write-Fail ("Clearing the local registration failed with exit code " + $clearExitCode + ".")
        Write-Host 'The registration may be partially cleared. Inspect the registration file and'
        Write-Host 'the SSM Agent log before re-running.'
        exit 3
    }

    Write-Step 'Local registration cleared.'
    Write-Host 'AmazonSSMAgent has deliberately been left STOPPED: without a registration it'
    Write-Host 'has nothing to run with. Re-enroll by running this script again WITHOUT'
    Write-Host '-ForceReregister, providing a fresh activation (the previous one is consumed);'
    Write-Host 'that Register run starts AmazonSSMAgent again with the new identity.'
    exit 3
}

Write-Fail ("Unexpected action '" + $action + "' for state '" + $nodeState + "'. Nothing was changed.")
exit 1
