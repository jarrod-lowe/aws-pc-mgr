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

Describe 'Get-SsmServiceInfo' {
    BeforeAll {
        # Get-CimInstance does not exist in the Linux unit-test container, and
        # Pester only mocks commands that resolve inside the target module's
        # session state. So a stub is planted in SSMHybrid's scope for the
        # Mocks below to replace; it is unexported (the module uses an
        # explicit Export-ModuleMember list) and removed again in AfterAll so
        # it never shadows the real cmdlet elsewhere.
        $script:ssmHybridModule = Get-Module SSMHybrid
        . $script:ssmHybridModule.NewBoundScriptBlock({
            function Get-CimInstance {
                [CmdletBinding()]
                param([string]$ClassName, [string]$Filter)
                # Failure mode of the real cmdlet: a NON-terminating error
                # record whose disposition follows the caller's -ErrorAction
                # (Stop makes it terminating, SilentlyContinue suppresses it).
                $PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]::new(
                        [System.InvalidOperationException]::new('simulated CIM provider failure'),
                        'SimulatedCimProviderFailure',
                        [System.Management.Automation.ErrorCategory]::NotSpecified,
                        $null))
            }
        })
    }

    AfterAll {
        . $script:ssmHybridModule.NewBoundScriptBlock({
            Remove-Item -Path Function:\Get-CimInstance -ErrorAction SilentlyContinue
        })
    }

    It 'returns Exists $false with empty Status and StartType, without throwing, when the query succeeds but matches nothing' {
        Mock Get-CimInstance -ModuleName SSMHybrid { return $null }

        $result = Get-SsmServiceInfo

        $result.Exists | Should -BeFalse
        $result.Status | Should -Be ''
        $result.StartType | Should -Be ''
    }

    It 'throws when the service query itself fails, so a failed query is never readable as the service being absent' {
        # Deliberately NO Mock here: a Pester mock body neither sees the
        # bound parameters nor inherits the caller's -ErrorAction, so a mock
        # cannot faithfully simulate a non-terminating query failure. The
        # stub planted in BeforeAll can: it fails exactly the way the real
        # Get-CimInstance does, and the adapter's -ErrorAction alone decides
        # whether that failure surfaces. Under SilentlyContinue (the old
        # behavior) this query would silently read as Exists $false - the bug
        # this test pins. The ErrorId wildcard covers the ',Get-CimInstance'
        # suffix PowerShell appends to errors from advanced functions.
        { Get-SsmServiceInfo } | Should -Throw -ErrorId 'SimulatedCimProviderFailure*'
    }

    It 'reports Exists $true and translates State/StartMode into the decision vocabulary' {
        Mock Get-CimInstance -ModuleName SSMHybrid {
            return [PSCustomObject]@{ State = 'Running'; StartMode = 'Auto' }
        }

        $result = Get-SsmServiceInfo

        $result.Exists | Should -BeTrue
        $result.Status | Should -Be 'Running'
        $result.StartType | Should -Be 'Automatic'
    }

    It 'passes a Manual StartMode through untranslated' {
        Mock Get-CimInstance -ModuleName SSMHybrid {
            return [PSCustomObject]@{ State = 'Stopped'; StartMode = 'Manual' }
        }

        $result = Get-SsmServiceInfo

        $result.Exists | Should -BeTrue
        $result.StartType | Should -Be 'Manual'
    }
}

Describe 'Module export surface' {
    It 'exports the eight contract functions plus the three Windows-only adapters (entry scripts call them after Import-Module)' {
        $exported = (Get-Module SSMHybrid).ExportedCommands.Keys | Sort-Object
        $expected = @(
            'ConvertFrom-SsmRegistrationJson',
            'Get-SsmNodeState',
            'Get-SsmRegistrationFileJson',
            'Get-SsmServiceInfo',
            'Get-SsmSetupAction',
            'Get-SsmSetupCliUrl',
            'Invoke-SsmEnrollment',
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

    It 'rejects the signer name smuggled inside a larger RDN value' {
        $result = Test-SsmSignature -Status 'Valid' -SignerSubject 'CN=Not Amazon.com Services LLC, O=Evil Corp'
        $result.Valid | Should -BeFalse
        $result.Reason | Should -Match 'Amazon'
        $result.Reason | Should -Match 'Evil Corp'
    }

    It 'rejects the signer phrase merely embedded mid-value in the subject' {
        $result = Test-SsmSignature -Status 'Valid' -SignerSubject 'Microsoft Code Signing PCA 2011 - signer Amazon.com Services LLC intermediate'
        $result.Valid | Should -BeFalse
        $result.Reason | Should -Match 'Amazon'
    }

    It 'accepts an exact CN match even without a matching O component' {
        $result = Test-SsmSignature -Status 'Valid' -SignerSubject 'CN=Amazon.com Services LLC'
        $result.Valid | Should -BeTrue
    }

    It 'accepts an exact O match even without a matching CN component' {
        $result = Test-SsmSignature -Status 'Valid' -SignerSubject 'CN=Something Else Entirely, O=Amazon.com Services LLC'
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
            RegistrationJson  = $null
            ServiceExists     = $false
            ServiceStatus     = ''
            ServiceStartType  = ''
            Expected          = 'Absent'
        }
        @{
            Name              = 'service present but no registration file'
            RegistrationJson  = $null
            ServiceExists     = $true
            ServiceStatus     = 'Running'
            ServiceStartType  = 'Automatic'
            Expected          = 'InstalledUnregistered'
        }
        @{
            Name              = 'registration file present but empty, service absent'
            RegistrationJson  = ''
            ServiceExists     = $false
            ServiceStatus     = ''
            ServiceStartType  = ''
            Expected          = 'Ambiguous'
        }
        @{
            Name              = 'registration file present but empty, service healthy'
            RegistrationJson  = ''
            ServiceExists     = $true
            ServiceStatus     = 'Running'
            ServiceStartType  = 'Automatic'
            Expected          = 'Ambiguous'
        }
        @{
            Name              = 'registration file present but whitespace-only'
            RegistrationJson  = '   '
            ServiceExists     = $true
            ServiceStatus     = 'Running'
            ServiceStartType  = 'Automatic'
            Expected          = 'Ambiguous'
        }
        @{
            Name              = 'registration parseable, service running and automatic'
            RegistrationJson  = '{"ManagedInstanceID":"mi-0123456789abcdef0","Region":"ap-southeast-2"}' # audit-allow:synthetic
            ServiceExists     = $true
            ServiceStatus     = 'Running'
            ServiceStartType  = 'Automatic'
            Expected          = 'RegisteredHealthy'
        }
        @{
            Name              = 'registration parseable, service stopped'
            RegistrationJson  = '{"ManagedInstanceID":"mi-0123456789abcdef0","Region":"ap-southeast-2"}' # audit-allow:synthetic
            ServiceExists     = $true
            ServiceStatus     = 'Stopped'
            ServiceStartType  = 'Automatic'
            Expected          = 'RegisteredStopped'
        }
        @{
            Name              = 'registration parseable, service stopped with non-automatic start'
            RegistrationJson  = '{"ManagedInstanceID":"mi-0123456789abcdef0","Region":"ap-southeast-2"}' # audit-allow:synthetic
            ServiceExists     = $true
            ServiceStatus     = 'Stopped'
            ServiceStartType  = 'Manual'
            Expected          = 'RegisteredStopped'
        }
        @{
            Name              = 'registration parseable, service missing'
            RegistrationJson  = '{"ManagedInstanceID":"mi-0123456789abcdef0","Region":"ap-southeast-2"}' # audit-allow:synthetic
            ServiceExists     = $false
            ServiceStatus     = ''
            ServiceStartType  = ''
            Expected          = 'RegisteredUnhealthy'
        }
        @{
            Name              = 'registration parseable, service running but not automatic'
            RegistrationJson  = '{"ManagedInstanceID":"mi-0123456789abcdef0","Region":"ap-southeast-2"}' # audit-allow:synthetic
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
        $script:goodJson = '{"ManagedInstanceID":"mi-0123456789abcdef0","Region":"ap-southeast-2"}' # audit-allow:synthetic
    }

    It 'maps the source key ManagedInstanceID to ManagedInstanceId' {
        $result = ConvertFrom-SsmRegistrationJson -Json $script:goodJson
        $result.ManagedInstanceId | Should -Be 'mi-0123456789abcdef0' # audit-allow:synthetic
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

    It 'builds the China-partition URL for cn regions' {
        Get-SsmSetupCliUrl -Region 'cn-north-1' | Should -Be 'https://amazon-ssm-cn-north-1.s3.cn-north-1.amazonaws.com.cn/latest/windows_amd64/ssm-setup-cli.exe'
    }

    It 'keeps the standard amazonaws.com suffix for a gov-cloud region (not the China .com.cn one)' {
        $url = Get-SsmSetupCliUrl -Region 'us-gov-west-1'
        $url | Should -Be 'https://amazon-ssm-us-gov-west-1.s3.us-gov-west-1.amazonaws.com/latest/windows_amd64/ssm-setup-cli.exe'
        $url | Should -Not -Match 'amazonaws\.com\.cn'
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
        @{ ActivationId = '08e51e79-2c3f-4a5d-8f6e-9a7b0c1d2e3f' } # audit-allow:synthetic
        @{ ActivationId = '123E4567-E89B-12D3-A456-426614174000' } # audit-allow:synthetic
    ) {
        param($ActivationId)
        Test-SsmActivationId -ActivationId $ActivationId | Should -BeTrue
    }

    It 'rejects <ActivationId>' -TestCases @(
        @{ ActivationId = 'not-a-uuid' }
        @{ ActivationId = '08e51e792c3f4a5d8f6e9a7b0c1d2e3f' }
        @{ ActivationId = '08e51e79-2c3f-4a5d-8f6e' }
        @{ ActivationId = '{08e51e79-2c3f-4a5d-8f6e-9a7b0c1d2e3f}' } # audit-allow:synthetic
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
