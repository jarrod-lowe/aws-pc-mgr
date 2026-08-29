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
    'Test-SsmRegion'
)
