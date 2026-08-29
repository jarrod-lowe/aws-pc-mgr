BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../scripts/windows/SSMHybrid.psm1') -Force
}

Describe 'Test-SsmRegion' {
    It 'accepts <Region>' -TestCases @(
        @{ Region = 'us-east-1' }
        @{ Region = 'us-gov-west-1' }
        @{ Region = 'ap-southeast-2' }
        @{ Region = 'eu-west-1' }
        @{ Region = 'us-gov-east-1' }
    ) {
        param($Region)
        Test-SsmRegion -Region $Region | Should -BeTrue
    }

    It 'rejects <Region>' -TestCases @(
        @{ Region = 'NOPE' }
        @{ Region = 'us-east-1-' }
        @{ Region = 'US-EAST-1' }
        @{ Region = 'us east 1' }
        @{ Region = '' }
        @{ Region = $null }
    ) {
        param($Region)
        Test-SsmRegion -Region $Region | Should -BeFalse
    }
}
