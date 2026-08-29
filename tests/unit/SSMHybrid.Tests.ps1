BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../scripts/windows/SSMHybrid.psm1') -Force
}

Describe 'Get-SsmSetupCliUrl' {
    It 'builds the per-region URL' {
        Get-SsmSetupCliUrl -Region 'ap-southeast-2' | Should -Be 'https://amazon-ssm-ap-southeast-2.s3.ap-southeast-2.amazonaws.com/latest/windows_amd64/ssm-setup-cli.exe'
    }

    It 'builds the URL for a gov-cloud region' {
        Get-SsmSetupCliUrl -Region 'us-gov-west-1' | Should -Be 'https://amazon-ssm-us-gov-west-1.s3.us-gov-west-1.amazonaws.com/latest/windows_amd64/ssm-setup-cli.exe'
    }

    It 'rejects an invalid region' {
        { Get-SsmSetupCliUrl -Region 'nope' } | Should -Throw
    }

    It 'rejects an empty region' {
        { Get-SsmSetupCliUrl -Region '' } | Should -Throw
    }
}

Describe 'Test-SsmActivationId' {
    It 'accepts <ActivationId>' -TestCases @(
        @{ ActivationId = '08e51e79-2c3f-4a5d-8f6e-9a7b0c1d2e3f' }
        @{ ActivationId = '123E4567-E89B-12D3-A456-426614174000' }
    ) {
        param($ActivationId)
        Test-SsmActivationId -ActivationId $ActivationId | Should -BeTrue
    }

    It 'rejects <ActivationId>' -TestCases @(
        @{ ActivationId = 'not-a-uuid' }
        @{ ActivationId = '08e51e792c3f4a5d8f6e9a7b0c1d2e3f' }
        @{ ActivationId = '08e51e79-2c3f-4a5d-8f6e' }
        @{ ActivationId = '{08e51e79-2c3f-4a5d-8f6e-9a7b0c1d2e3f}' }
        @{ ActivationId = '' }
        @{ ActivationId = $null }
    ) {
        param($ActivationId)
        Test-SsmActivationId -ActivationId $ActivationId | Should -BeFalse
    }
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
