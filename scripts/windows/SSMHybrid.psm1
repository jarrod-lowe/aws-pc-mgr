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

# ---------------------------------------------------------------------------
# Windows-only adapters
#
# The functions below are thin fact-gatherers / runners for the Windows side
# of enrollment. They are exported (setup.ps1 and check.ps1 call them
# directly after Import-Module). With one exception they are NOT unit-tested
# here: they call Windows-only cmdlets (Get-AuthenticodeSignature,
# Invoke-WebRequest against Windows TLS settings, executing a .exe), which do
# not exist in the Linux unit-test container. Windows-tier tests
# (tests/windows/*.Tests.ps1) exercise them on the real machine. The
# exception is Get-SsmServiceInfo, whose Get-CimInstance call is unit-tested
# in tests/unit against a stub planted in this module's scope.
#
# Windows-only cmdlets appear only inside function bodies (never at module
# scope) so importing this module on any OS succeeds.
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
Reads AmazonSSMAgent service facts on Windows into the shape
Get-SsmNodeState consumes.

.DESCRIPTION
Uses Get-CimInstance Win32_Service (available on Windows PowerShell 5.1 and
PowerShell 7) rather than Get-Service, because Win32_Service exposes both
State and StartMode on every supported version. Win32_Service StartMode
values (Auto/Manual/Disabled) are translated to the Automatic/Manual/Disabled
vocabulary the decision functions compare against.

.OUTPUTS
[PSCustomObject] with Exists ([bool]), Status ([string], '' when absent) and
StartType ([string], '' when absent). Never throws for a MISSING service: a
successful query that matches nothing simply reports Exists = $false. A
FAILED query (for example a CIM provider error) DOES throw, so callers fail
closed instead of misreading the failure as the service being absent.
#>
function Get-SsmServiceInfo {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='AmazonSSMAgent'" -ErrorAction Stop

    if ($null -eq $service) {
        return [PSCustomObject]@{
            Exists     = $false
            Status     = ''
            StartType  = ''
        }
    }

    $startType = ''
    if ($service.StartMode -eq 'Auto') {
        $startType = 'Automatic'
    } else {
        $startType = [string]$service.StartMode
    }

    return [PSCustomObject]@{
        Exists     = $true
        Status     = [string]$service.State
        StartType  = $startType
    }
}

<#
.SYNOPSIS
Reads the local SSM hybrid registration record as raw JSON text.

.DESCRIPTION
Returns the raw text of the local registration file, or $null when no
registration file exists. The default path is the conventional hybrid-agent
location under ProgramData; it is overridable so Windows-tier tests can
point the adapter at a fixture. NOTE: the exact on-disk location is
confirmed on the machine during validation (V4); if AWS keeps it elsewhere
only this default changes.

.PARAMETER Path
Registration file path. Defaults to
$env:ProgramData\Amazon\SSM\InstanceData\registration.

.OUTPUTS
[System.String] raw JSON, or $null when the file does not exist.
#>
function Get-SsmRegistrationFileJson {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$Path = (Join-Path $env:ProgramData 'Amazon\SSM\InstanceData\registration')
    )

    if ([string]::IsNullOrEmpty($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return (Get-Content -LiteralPath $Path -Raw)
}

<#
.SYNOPSIS
Downloads, signature-checks and runs the AWS ssm-setup-cli enrollment
executable (Windows runner helper).

.DESCRIPTION
Thin runner for the Register action:

  1. builds the regional URL with Get-SsmSetupCliUrl;
  2. downloads ssm-setup-cli.exe over HTTPS to a temp file (TLS 1.2 forced
     on Windows PowerShell 5.1);
  3. verifies the Authenticode signature with Get-AuthenticodeSignature and
     Test-SsmSignature and REFUSES to run anything that is not Valid and
     signed by Amazon.com Services LLC (SPEC 21 steps 6-8);
  4. registers with -region/-activation-id/-activation-code;
  5. removes the temp executable.

SECURITY: the activation code is passed to the executable only. The command
line is never echoed, written or logged, and the tool's stdout AND stderr are
both discarded (redirected together and piped to Out-Null under a temporarily
relaxed $ErrorActionPreference), because they may reflect arguments (SPEC 43).
Only a success/failure verdict is returned: a non-zero exit code throws, and
the tool's own text never reaches the console or any log.

.PARAMETER Region
Validated AWS region code.

.PARAMETER ActivationId
SSM hybrid activation ID (UUID).

.PARAMETER ActivationCode
SSM hybrid activation code. Treated as a secret; supply it directly from
Read-SsmSecret, never from command history.

.PARAMETER Url
Override the download URL (testing seam). Defaults to Get-SsmSetupCliUrl.

.OUTPUTS
None. Throws on any failure, including an unacceptable signature.
#>
function Invoke-SsmEnrollment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $true)]
        [string]$ActivationId,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ActivationCode,

        [string]$Url
    )

    if ([string]::IsNullOrEmpty($ActivationCode)) {
        throw 'Invoke-SsmEnrollment: activation code is empty.'
    }

    if (-not (Test-SsmActivationId -ActivationId $ActivationId)) {
        throw "Invoke-SsmEnrollment: '$ActivationId' is not a valid activation ID (UUID)."
    }

    if ([string]::IsNullOrEmpty($Url)) {
        $Url = Get-SsmSetupCliUrl -Region $Region
    }

    if ($PSVersionTable.PSVersion.Major -lt 6) {
        # Windows PowerShell 5.1 defaults may not negotiate TLS 1.2.
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }

    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ssm-setup-" + [System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    $exePath = Join-Path $tempDir 'ssm-setup-cli.exe'

    try {
        Invoke-WebRequest -Uri $Url -OutFile $exePath -UseBasicParsing | Out-Null

        $signature = Get-AuthenticodeSignature -FilePath $exePath
        $verdict = Test-SsmSignature -Status ([string]$signature.Status) -SignerSubject ([string]$signature.SignerCertificate.Subject)
        if (-not $verdict.Valid) {
            # Never execute an invalidly signed binary (SPEC 21 step 8).
            throw "Invoke-SsmEnrollment: downloaded ssm-setup-cli failed signature verification: $($verdict.Reason)"
        }

        # Command line carries the activation code: it is executed but never
        # echoed, logged, or captured into any output the caller sees. BOTH
        # streams are discarded: on 5.1, '$null = & exe' suppresses only the
        # success stream, leaving the tool's stderr on the console, and under
        # a caller's $ErrorActionPreference = 'Stop' redirected stderr can
        # raise a NativeCommandError embedding the tool's text. Relaxing
        # ErrorActionPreference around the call keeps the merged redirect
        # quiet; $LASTEXITCODE still carries the verdict.
        $previousEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            & $exePath -register -region $Region -activation-id $ActivationId -activation-code $ActivationCode 2>&1 | Out-Null
        } finally {
            $ErrorActionPreference = $previousEap
        }
        if ($LASTEXITCODE -ne 0) {
            throw "Invoke-SsmEnrollment: ssm-setup-cli exited with code $LASTEXITCODE. Registration may have partially completed; inspect the SSM Agent log before re-running."
        }
    } finally {
        if (Test-Path -LiteralPath $tempDir) {
            Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

<#
.SYNOPSIS
Prompts the operator for a secret without echoing it and returns it as a
plain in-memory string.

.DESCRIPTION
Reads the value with Read-Host -AsSecureString so nothing appears on screen
(and the activation code never lands in PowerShell command history, SPEC 20),
then decodes the SecureString to a plain string in memory via a BSTR that is
zeroed immediately after use. The value is returned to the caller only; this
function never writes, logs, or echoes it (SPEC 43). Callers must not print
the result.

.PARAMETER Prompt
Prompt text shown to the operator, for example 'Activation Code'.

.OUTPUTS
[System.String] The secret as plain text, for short-lived in-memory use.
#>
function Read-SsmSecret {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prompt
    )

    $secure = Read-Host -Prompt $Prompt -AsSecureString

    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        if ($null -ne $bstr -and $bstr -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }

    return $plain
}

<#
.SYNOPSIS
Decides whether an Authenticode signature result is an acceptable AWS
ssm-setup-cli signature.

.DESCRIPTION
Valid is true only when both hold:

  - Status is 'Valid' (the value Get-AuthenticodeSignature reports for a
    trusted, intact signature; comparison is case-insensitive);
  - the signer subject names 'Amazon.com Services LLC' as an EXACT RDN
    component value: one of the subject's comma-separated RDN components is
    CN=<signer> or O=<signer> whose VALUE equals 'Amazon.com Services LLC'
    (surrounding whitespace trimmed; comparison case-insensitive). A subject
    that merely contains the phrase inside a larger value - for example
    'CN=Not Amazon.com Services LLC, O=Evil Corp' - is rejected, so a
    forged certificate cannot smuggle the signer name mid-value. AWS's
    ssm-setup-cli signer subject is 'CN=Amazon.com Services LLC,
    O=Amazon.com Services LLC, L=Seattle, S=Washington, C=US'.

Reason always explains the first failed check (or states why the signature
was accepted) so callers can log it. Neither parameter is secret.

.PARAMETER Status
Get-AuthenticodeSignature Status value, for example 'Valid', 'NotSigned',
'HashMismatch', 'UnknownError'.

.PARAMETER SignerSubject
Signer certificate subject of the signature's signercertificate.

.OUTPUTS
[PSCustomObject] with Valid ([bool]) and Reason ([string]).
#>
function Test-SsmSignature {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$SignerSubject
    )

    $expectedSigner = 'Amazon.com Services LLC'

    if ($Status -ne 'Valid') {
        return [PSCustomObject]@{
            Valid  = $false
            Reason = "Authenticode status is '$Status'; expected 'Valid'."
        }
    }

    # Exact RDN match: the subject is split into its comma-separated RDN
    # components and accepted only when the VALUE of a CN or O component
    # equals the expected signer exactly (whitespace trimmed; PowerShell
    # string comparison is case-insensitive). A subject that merely contains
    # the phrase inside a larger value ('CN=Not Amazon.com Services LLC,
    # O=Evil Corp') is NOT accepted.
    $signerAccepted = $false
    foreach ($rdn in @($SignerSubject -split ',')) {
        $component = $rdn.Trim()
        $separator = $component.IndexOf('=')
        if ($separator -lt 1) {
            continue
        }
        $componentName = $component.Substring(0, $separator).Trim()
        if (($componentName -ne 'CN') -and ($componentName -ne 'O')) {
            continue
        }
        $componentValue = $component.Substring($separator + 1).Trim()
        if ($componentValue -eq $expectedSigner) {
            $signerAccepted = $true
        }
    }

    if (-not $signerAccepted) {
        return [PSCustomObject]@{
            Valid  = $false
            Reason = "Signer subject '$SignerSubject' does not name '$expectedSigner' as an exact CN or O RDN value."
        }
    }

    return [PSCustomObject]@{
        Valid  = $true
        Reason = "Signature status is Valid and signer subject names '$expectedSigner' as an exact CN or O RDN value."
    }
}

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
Raw registration file JSON, $null when no file exists (adapter contract).
An empty or whitespace-only string means the file exists but is empty,
which classifies as Ambiguous.

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
        $RegistrationJson,

        [bool]$ServiceExists = $false,

        [AllowEmptyString()]
        [string]$ServiceStatus = '',

        [AllowEmptyString()]
        [string]$ServiceStartType = ''
    )

    # $null means no registration file (adapter contract); an empty or
    # whitespace-only string means the file exists but holds nothing, which
    # is ambiguous partial state and must not be auto-repaired (SPEC 23).
    if ($null -eq $RegistrationJson) {
        if ($ServiceExists) {
            return 'InstalledUnregistered'
        }
        return 'Absent'
    }

    if ([string]::IsNullOrWhiteSpace($RegistrationJson)) {
        return 'Ambiguous'
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
for a validated region. China-partition regions (cn-...) use the China DNS
suffix instead: https://amazon-ssm-<region>.s3.<region>.amazonaws.com.cn/...
GovCloud and every other valid region keep the standard amazonaws.com
suffix. Throws for any region that does not pass Test-SsmRegion, so an
unusable URL can never be constructed.

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

    # China-partition regions serve the bucket under the China DNS suffix
    # (amazonaws.com.cn); GovCloud and all other regions use amazonaws.com.
    $dnsSuffix = 'amazonaws.com'
    if ($Region -like 'cn-*') {
        $dnsSuffix = 'amazonaws.com.cn'
    }
    return ('https://amazon-ssm-{0}.s3.{0}.{1}/latest/windows_amd64/ssm-setup-cli.exe' -f $Region, $dnsSuffix)
}

<#
.SYNOPSIS
Tests whether a string is a well-formed UUID, as an SSM activation ID must be.

.DESCRIPTION
True iff the string matches the canonical 8-4-4-4-12 hexadecimal UUID format
(for example 08e51e79-2c3f-4a5d-8f6e-9a7b0c1d2e3f). Upper- and lower-case # audit-allow:synthetic
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

# Eight cross-platform contract functions plus the three Windows-only
# adapters above: setup.ps1 and check.ps1 call Get-SsmServiceInfo,
# Get-SsmRegistrationFileJson and Invoke-SsmEnrollment directly after
# Import-Module, so they must be part of the export surface.
Export-ModuleMember -Function @(
    'Test-SsmRegion',
    'Test-SsmActivationId',
    'Get-SsmSetupCliUrl',
    'ConvertFrom-SsmRegistrationJson',
    'Get-SsmNodeState',
    'Get-SsmSetupAction',
    'Test-SsmSignature',
    'Read-SsmSecret',
    'Get-SsmServiceInfo',
    'Get-SsmRegistrationFileJson',
    'Invoke-SsmEnrollment'
)
