# SSMHybrid.psm1
#
# Pure decision logic for enrolling a Windows 11 machine as an AWS Systems
# Manager (SSM) hybrid managed node, plus thin Windows-only adapters that
# gather local machine facts.
#
# Design rules:
#   - PowerShell 5.1-compatible syntax only (no ternary, no ??, no chain
#     operators). Verified with PSUseCompatibleSyntax targeting 5.1 and 7.0.
#   - Windows-only cmdlets (Get-Service, Get-CimInstance, ...) appear ONLY
#     inside function bodies, never at module scope, so the module imports
#     cleanly on any OS (unit tests import it on Linux).
#   - Never logs or echoes credential material (SPEC 42/43).

$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
Decides what the enrollment runner should do for a given node state.

.DESCRIPTION
Maps a Get-SsmNodeState result to the setup action:

  Absent                -> Register
  InstalledUnregistered -> Register
  RegisteredHealthy     -> NoOperation
  RegisteredStopped     -> StartService (non-destructive repair, SPEC 23)
  RegisteredUnhealthy   -> ManualIntervention
  Ambiguous             -> ManualIntervention

With -ForceReregister, any state that implies an existing registration
(RegisteredHealthy, RegisteredStopped, RegisteredUnhealthy, Ambiguous) maps
to Reregister instead. The flag never turns a registration-less state
destructive: Absent and InstalledUnregistered still map to Register.
Reregister is the only destructive action and callers must confirm it
interactively (SPEC 22).

.PARAMETER State
One of the six Get-SsmNodeState values.

.PARAMETER ForceReregister
Explicitly requests replacing an existing registration.

.OUTPUTS
[System.String] Register, StartService, NoOperation, ManualIntervention,
or Reregister.
#>
function Get-SsmSetupAction {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Absent', 'InstalledUnregistered', 'RegisteredHealthy', 'RegisteredStopped', 'RegisteredUnhealthy', 'Ambiguous')]
        [string]$State,

        [switch]$ForceReregister
    )

    $existingRegistrationStates = @(
        'RegisteredHealthy',
        'RegisteredStopped',
        'RegisteredUnhealthy',
        'Ambiguous'
    )

    if ($ForceReregister) {
        if ($existingRegistrationStates -contains $State) {
            return 'Reregister'
        }
    }

    switch ($State) {
        'Absent' { return 'Register' }
        'InstalledUnregistered' { return 'Register' }
        'RegisteredHealthy' { return 'NoOperation' }
        'RegisteredStopped' { return 'StartService' }
        'RegisteredUnhealthy' { return 'ManualIntervention' }
        'Ambiguous' { return 'ManualIntervention' }
    }

    # Unreachable: ValidateSet restricts $State to the values above.
    throw "Get-SsmSetupAction: unhandled state '$State'."
}

<#
.SYNOPSIS
Classifies the local SSM hybrid enrollment state of this machine.

.DESCRIPTION
Combines the local registration record with AmazonSSMAgent service facts and
returns exactly one node state:

  Absent                 no service and no registration file
  InstalledUnregistered  service present, no registration file
  RegisteredHealthy      registration parseable, service Running and Automatic
  RegisteredStopped      registration parseable, service Stopped
  RegisteredUnhealthy    registration parseable, service missing or otherwise
                         not Running+Automatic (for example not Automatic, or
                         a status that is neither Running nor Stopped)
  Ambiguous              registration file present but unparseable or
                         incomplete (ConvertFrom-SsmRegistrationJson throws)

Classification never destroys registration state; Ambiguous is reported
rather than repaired so an operator can decide (SPEC 22/23).

.PARAMETER RegistrationJson
Raw registration file JSON, or an empty string when no file exists.

.PARAMETER ServiceExists
Whether the AmazonSSMAgent service exists.

.PARAMETER ServiceStatus
Service status, for example 'Running' or 'Stopped'.

.PARAMETER ServiceStartType
Service start type, for example 'Automatic' or 'Manual'.

.OUTPUTS
[System.String] One of the six state names above.
#>
function Get-SsmNodeState {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$RegistrationJson,

        [bool]$ServiceExists = $false,

        [AllowEmptyString()]
        [string]$ServiceStatus = '',

        [AllowEmptyString()]
        [string]$ServiceStartType = ''
    )

    $hasRegistrationJson = -not [string]::IsNullOrEmpty($RegistrationJson)

    if (-not $hasRegistrationJson) {
        if ($ServiceExists) {
            return 'InstalledUnregistered'
        }
        return 'Absent'
    }

    # A registration file exists: it must parse cleanly, otherwise the
    # situation is ambiguous and must not be auto-repaired.
    try {
        ConvertFrom-SsmRegistrationJson -Json $RegistrationJson -ErrorAction Stop | Out-Null
    } catch {
        return 'Ambiguous'
    }

    if (-not $ServiceExists) {
        return 'RegisteredUnhealthy'
    }

    if ($ServiceStatus -eq 'Running') {
        if ($ServiceStartType -eq 'Automatic') {
            return 'RegisteredHealthy'
        }
        return 'RegisteredUnhealthy'
    }

    if ($ServiceStatus -eq 'Stopped') {
        return 'RegisteredStopped'
    }

    return 'RegisteredUnhealthy'
}

<#
.SYNOPSIS
Parses local SSM hybrid registration JSON into a stable object.

.DESCRIPTION
The registration record an enrolled hybrid node keeps locally uses the key
'ManagedInstanceID' (capital ID). This function parses that record and
returns an object with the properties:

  ManagedInstanceId - the mi-... managed-node identifier (string)
  Region            - the AWS region recorded at registration (string; $null
                      when the record carries no Region value)

Throws when the JSON is malformed, is not an object, lacks a non-empty
'ManagedInstanceID' key. Callers treat a throw as "registration present but
unparseable/incomplete" and classify the node as Ambiguous rather than
destroying registration state (SPEC 23).

.PARAMETER Json
Raw JSON text read from the local registration file.

.OUTPUTS
[PSCustomObject] with ManagedInstanceId and Region.

.EXAMPLE
ConvertFrom-SsmRegistrationJson -Json '{"ManagedInstanceID":"mi-0123","Region":"ap-southeast-2"}'
#>
function ConvertFrom-SsmRegistrationJson {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Json
    )

    if ([string]::IsNullOrEmpty($Json)) {
        throw 'ConvertFrom-SsmRegistrationJson: registration JSON is empty.'
    }

    $parsed = $null
    try {
        $parsed = ConvertFrom-Json -InputObject $Json -ErrorAction Stop
    } catch {
        throw "ConvertFrom-SsmRegistrationJson: registration data is not valid JSON: $($_.Exception.Message)"
    }

    $isPropertyBag = ($null -ne $parsed) -and ($parsed -is [System.Management.Automation.PSCustomObject])
    if (-not $isPropertyBag) {
        throw 'ConvertFrom-SsmRegistrationJson: registration data is not a JSON object.'
    }

    $idProperty = $parsed.PSObject.Properties |
        Where-Object { $_.Name -eq 'ManagedInstanceID' } |
        Select-Object -First 1
    if ($null -eq $idProperty -or [string]::IsNullOrEmpty([string]$idProperty.Value)) {
        throw "ConvertFrom-SsmRegistrationJson: registration data has no non-empty 'ManagedInstanceID' key."
    }

    $region = $null
    $regionProperty = $parsed.PSObject.Properties |
        Where-Object { $_.Name -eq 'Region' } |
        Select-Object -First 1
    if ($null -ne $regionProperty -and -not [string]::IsNullOrEmpty([string]$regionProperty.Value)) {
        $region = [string]$regionProperty.Value
    }

    return [PSCustomObject]@{
        ManagedInstanceId = [string]$idProperty.Value
        Region            = $region
    }
}

<#
.SYNOPSIS
Builds the regional download URL for the AWS ssm-setup-cli hybrid enrollment
executable (Windows amd64).

.DESCRIPTION
Returns https://amazon-ssm-<region>.s3.<region>.amazonaws.com/latest/windows_amd64/ssm-setup-cli.exe
for a validated region. Throws for any region that does not pass
Test-SsmRegion, so an unusable URL can never be constructed.

.PARAMETER Region
AWS region code, for example ap-southeast-2.

.OUTPUTS
[System.String] The download URL.

.EXAMPLE
Get-SsmSetupCliUrl -Region 'ap-southeast-2'
#>
function Get-SsmSetupCliUrl {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    if (-not (Test-SsmRegion -Region $Region)) {
        throw "Get-SsmSetupCliUrl: '$Region' is not a valid AWS region code (expected the form 'us-east-1')."
    }
    return ('https://amazon-ssm-{0}.s3.{0}.amazonaws.com/latest/windows_amd64/ssm-setup-cli.exe' -f $Region)
}

<#
.SYNOPSIS
Tests whether a string is a well-formed UUID, as an SSM activation ID must be.

.DESCRIPTION
True iff the string matches the canonical 8-4-4-4-12 hexadecimal UUID format
(for example 08e51e79-2c3f-4a5d-8f6e-9a7b0c1d2e3f). Upper- and lower-case
hex digits are both accepted; braces and undashed forms are rejected.

.PARAMETER ActivationId
Candidate activation ID. Empty and null are rejected.

.OUTPUTS
[System.Boolean]
#>
function Test-SsmActivationId {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$ActivationId
    )

    if ($null -eq $ActivationId) {
        return $false
    }
    return ($ActivationId -cmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
}

<#
.SYNOPSIS
Tests whether a string is a well-formed AWS region code.

.DESCRIPTION
True iff the string matches ^[a-z]{2}(-gov)?-[a-z]+-\d$ (for example
us-east-1, us-gov-west-1, ap-southeast-2). The match is case-sensitive;
the region code used by AWS endpoints is lowercase.

.PARAMETER Region
Candidate region code. Empty and null are rejected.

.OUTPUTS
[System.Boolean]
#>
function Test-SsmRegion {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Region
    )

    if ($null -eq $Region) {
        return $false
    }
    return ($Region -cmatch '^[a-z]{2}(-gov)?-[a-z]+-\d$')
}

Export-ModuleMember -Function @(
    'Test-SsmRegion',
    'Test-SsmActivationId',
    'Get-SsmSetupCliUrl',
    'ConvertFrom-SsmRegistrationJson',
    'Get-SsmNodeState',
    'Get-SsmSetupAction'
)
