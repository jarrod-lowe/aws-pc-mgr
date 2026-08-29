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
    'Get-SsmSetupCliUrl'
)
