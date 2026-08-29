BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../scripts/windows/SSMHybrid.psm1') -Force
}

Describe 'Read-SsmSecret' {
    It 'prompts with Read-Host -AsSecureString and returns the plain string' {
        Mock Read-Host -ModuleName SSMHybrid {
            return (ConvertTo-SecureString 'correct horse battery staple' -AsPlainText -Force)
        }

        $result = Read-SsmSecret -Prompt 'Activation Code'

        Should -Invoke Read-Host -ModuleName SSMHybrid -Exactly 1 -ParameterFilter {
            $Prompt -eq 'Activation Code' -and $AsSecureString -eq $true
        }
        $result | Should -BeOfType [string]
        $result | Should -Be 'correct horse battery staple'
    }

    It 'prompts exactly once and returns only the secret (no extra output)' {
        Mock Read-Host -ModuleName SSMHybrid {
            return (ConvertTo-SecureString 's3cret' -AsPlainText -Force)
        }

        $output = Read-SsmSecret -Prompt 'Code'
        @($output).Count | Should -Be 1
        $output | Should -Be 's3cret'
    }
}

Describe 'Module export surface' {
    It 'exports exactly the eight contract functions' {
        $exported = (Get-Module SSMHybrid).ExportedCommands.Keys | Sort-Object
        $expected = @(
            'ConvertFrom-SsmRegistrationJson',
            'Get-SsmNodeState',
            'Get-SsmSetupAction',
            'Get-SsmSetupCliUrl',
            'Read-SsmSecret',
            'Test-SsmActivationId',
            'Test-SsmRegion',
            'Test-SsmSignature'
        ) | Sort-Object
        $exported | Should -Be $expected
    }
}

Describe 'Test-SsmSignature' {
    It 'accepts a Valid status signed by Amazon.com Services LLC' {
        $result = Test-SsmSignature -Status 'Valid' -SignerSubject 'CN=Amazon.com Services LLC, O=Amazon.com Services LLC, L=Seattle, S=Washington, C=US'
        $result.Valid | Should -BeTrue
    }

    It 'rejects a non-Valid status with a reason' {
        $result = Test-SsmSignature -Status 'NotSigned' -SignerSubject 'CN=Amazon.com Services LLC, O=Amazon.com Services LLC, L=Seattle, S=Washington, C=US'
        $result.Valid | Should -BeFalse
        $result.Reason | Should -Match 'status'
    }

    It 'rejects a Valid status with the wrong signer and names the signer' {
        $result = Test-SsmSignature -Status 'Valid' -SignerSubject 'CN=Evil Corp, O=Evil Corp, C=US'
        $result.Valid | Should -BeFalse
        $result.Reason | Should -Match 'Amazon'
        $result.Reason | Should -Match 'Evil Corp'
    }

    It 'rejects a Valid status with an empty signer subject' {
        $result = Test-SsmSignature -Status 'Valid' -SignerSubject ''
        $result.Valid | Should -BeFalse
        $result.Reason | Should -Match 'Amazon'
    }

    It 'accepts the Amazon signer with extra surrounding subject text' {
        $result = Test-SsmSignature -Status 'Valid' -SignerSubject 'Microsoft Code Signing PCA 2011 - signer Amazon.com Services LLC intermediate'
        $result.Valid | Should -BeTrue
    }

    It 'exposes exactly Valid and Reason' {
        $result = Test-SsmSignature -Status 'Valid' -SignerSubject 'CN=Amazon.com Services LLC'
        $properties = @($result.PSObject.Properties | ForEach-Object { $_.Name })
        $properties | Should -Be @('Valid', 'Reason')
    }
}

Describe 'Get-SsmSetupAction' {
    It 'maps <State> without -ForceReregister to <Expected>' -TestCases @(
        @{ State = 'Absent';                Expected = 'Register' }
        @{ State = 'InstalledUnregistered'; Expected = 'Register' }
        @{ State = 'RegisteredHealthy';     Expected = 'NoOperation' }
        @{ State = 'RegisteredStopped';     Expected = 'StartService' }
        @{ State = 'RegisteredUnhealthy';   Expected = 'ManualIntervention' }
        @{ State = 'Ambiguous';             Expected = 'ManualIntervention' }
    ) {
        param($State, $Expected)
        Get-SsmSetupAction -State $State | Should -Be $Expected
    }

    It 'maps <State> with -ForceReregister to Reregister' -TestCases @(
        @{ State = 'RegisteredHealthy' }
        @{ State = 'RegisteredStopped' }
        @{ State = 'RegisteredUnhealthy' }
        @{ State = 'Ambiguous' }
    ) {
        param($State)
        Get-SsmSetupAction -State $State -ForceReregister | Should -Be 'Reregister'
    }

    It 'maps <State> with -ForceReregister to Register when no registration exists' -TestCases @(
        @{ State = 'Absent' }
        @{ State = 'InstalledUnregistered' }
    ) {
        param($State)
        Get-SsmSetupAction -State $State -ForceReregister | Should -Be 'Register'
    }

    It 'rejects an unknown state' {
        { Get-SsmSetupAction -State 'Bogus' } | Should -Throw
    }
}

Describe 'Get-SsmNodeState' {
    It 'classifies <Name> as <Expected>' -TestCases @(
        @{
            Name              = 'no service and no registration file'
            RegistrationJson  = ''
            ServiceExists     = $false
            ServiceStatus     = ''
            ServiceStartType  = ''
            Expected          = 'Absent'
        }
        @{
            Name              = 'service present but no registration file'
            RegistrationJson  = ''
            ServiceExists     = $true
            ServiceStatus     = 'Running'
            ServiceStartType  = 'Automatic'
            Expected          = 'InstalledUnregistered'
        }
        @{
            Name              = 'registration parseable, service running and automatic'
            RegistrationJson  = '{"ManagedInstanceID":"mi-0123456789abcdef0","Region":"ap-southeast-2"}'
            ServiceExists     = $true
            ServiceStatus     = 'Running'
            ServiceStartType  = 'Automatic'
            Expected          = 'RegisteredHealthy'
        }
        @{
            Name              = 'registration parseable, service stopped'
            RegistrationJson  = '{"ManagedInstanceID":"mi-0123456789abcdef0","Region":"ap-southeast-2"}'
            ServiceExists     = $true
            ServiceStatus     = 'Stopped'
            ServiceStartType  = 'Automatic'
            Expected          = 'RegisteredStopped'
        }
        @{
            Name              = 'registration parseable, service stopped with non-automatic start'
            RegistrationJson  = '{"ManagedInstanceID":"mi-0123456789abcdef0","Region":"ap-southeast-2"}'
            ServiceExists     = $true
            ServiceStatus     = 'Stopped'
            ServiceStartType  = 'Manual'
            Expected          = 'RegisteredStopped'
        }
        @{
            Name              = 'registration parseable, service missing'
            RegistrationJson  = '{"ManagedInstanceID":"mi-0123456789abcdef0","Region":"ap-southeast-2"}'
            ServiceExists     = $false
            ServiceStatus     = ''
            ServiceStartType  = ''
            Expected          = 'RegisteredUnhealthy'
        }
        @{
            Name              = 'registration parseable, service running but not automatic'
            RegistrationJson  = '{"ManagedInstanceID":"mi-0123456789abcdef0","Region":"ap-southeast-2"}'
            ServiceExists     = $true
            ServiceStatus     = 'Running'
            ServiceStartType  = 'Manual'
            Expected          = 'RegisteredUnhealthy'
        }
        @{
            Name              = 'registration file present but unparseable'
            RegistrationJson  = 'not json {'
            ServiceExists     = $true
            ServiceStatus     = 'Running'
            ServiceStartType  = 'Automatic'
            Expected          = 'Ambiguous'
        }
        @{
            Name              = 'registration file present but incomplete (missing ManagedInstanceID)'
            RegistrationJson  = '{"Region":"ap-southeast-2"}'
            ServiceExists     = $true
            ServiceStatus     = 'Running'
            ServiceStartType  = 'Automatic'
            Expected          = 'Ambiguous'
        }
    ) {
        param($RegistrationJson, $ServiceExists, $ServiceStatus, $ServiceStartType, $Expected)
        Get-SsmNodeState -RegistrationJson $RegistrationJson -ServiceExists $ServiceExists -ServiceStatus $ServiceStatus -ServiceStartType $ServiceStartType |
            Should -Be $Expected
    }
}

Describe 'ConvertFrom-SsmRegistrationJson' {
    BeforeAll {
        $script:goodJson = '{"ManagedInstanceID":"mi-0123456789abcdef0","Region":"ap-southeast-2"}'
    }

    It 'maps the source key ManagedInstanceID to ManagedInstanceId' {
        $result = ConvertFrom-SsmRegistrationJson -Json $script:goodJson
        $result.ManagedInstanceId | Should -Be 'mi-0123456789abcdef0'
    }

    It 'passes the Region through unchanged' {
        $result = ConvertFrom-SsmRegistrationJson -Json $script:goodJson
        $result.Region | Should -Be 'ap-southeast-2'
    }

    It 'exposes exactly ManagedInstanceId and Region' {
        $result = ConvertFrom-SsmRegistrationJson -Json $script:goodJson
        $properties = @($result.PSObject.Properties | ForEach-Object { $_.Name })
        $properties | Should -Be @('ManagedInstanceId', 'Region')
    }

    It 'throws on malformed JSON' {
        { ConvertFrom-SsmRegistrationJson -Json 'not json {' } | Should -Throw
    }

    It 'throws on empty JSON' {
        { ConvertFrom-SsmRegistrationJson -Json '' } | Should -Throw
    }

    It 'throws when ManagedInstanceID is missing' {
        { ConvertFrom-SsmRegistrationJson -Json '{"Region":"ap-southeast-2"}' } | Should -Throw
    }

    It 'throws when ManagedInstanceID is empty' {
        { ConvertFrom-SsmRegistrationJson -Json '{"ManagedInstanceID":"","Region":"ap-southeast-2"}' } | Should -Throw
    }

    It 'throws when the JSON is not an object' {
        { ConvertFrom-SsmRegistrationJson -Json '[1,2,3]' } | Should -Throw
    }
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
