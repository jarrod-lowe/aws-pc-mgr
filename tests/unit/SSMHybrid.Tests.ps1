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

Describe 'Invoke-SsmEnrollment cleanup and pre-launch revalidation' {
    # The enrollment runner is a Windows-only adapter, but its temp-download
    # cleanup (SPEC 21 step 16) and its pre-launch registration
    # revalidation (SPEC 22/23) are pure cmdlet orchestration, so they ARE
    # unit-tested here: every Windows-only step is mocked, and the
    # downloaded "executable" is a copy of the Unix 'true' binary, which
    # keeps the native invocation and $LASTEXITCODE genuine. The suite's
    # runner is the Linux container; on a host without 'true' these tests
    # skip. Mocked Remove-Item failures simulate the transient antivirus
    # lock the retry exists for; successful deletions inside the mock go
    # through .NET so the mock cannot recurse into itself. Mock bodies that
    # need a knob use $global: variables on purpose: a -ModuleName mock body
    # runs in the module's session state and cannot see this file's scope.
    BeforeAll {
        # Get-AuthenticodeSignature does not exist in the Linux unit-test
        # container, and Pester only mocks commands that resolve inside the
        # target module's session state, so a stub is planted in SSMHybrid's
        # scope for the Mock below to replace - the same pattern the
        # Get-SsmServiceInfo Describe above uses for Get-CimInstance. It is
        # unexported (explicit Export-ModuleMember list) and removed again in
        # AfterAll so it never shadows the real cmdlet elsewhere.
        $script:ssmHybridModule = Get-Module SSMHybrid
        . $script:ssmHybridModule.NewBoundScriptBlock({
            function Get-AuthenticodeSignature {
                [CmdletBinding()]
                param([string]$FilePath)
            }
        })
        $script:TrueExe = (Get-Command -Name true -CommandType Application -ErrorAction SilentlyContinue).Source
        $script:EnrollParams = @{
            Region         = 'ap-southeast-2'
            ActivationId   = '08e51e79-2c3f-4a5d-8f6e-9a7b0c1d2e3f' # audit-allow:synthetic
            ActivationCode = 'not-a-real-activation-code' # audit-allow:synthetic
            Url            = 'https://example.invalid/ssm-setup-cli.exe'
        }
    }

    BeforeEach {
        Mock Invoke-WebRequest -ModuleName SSMHybrid -MockWith {
            # 'true' is resolved INSIDE the body: the body runs in the
            # module's session state, not this file's.
            $trueCmd = Get-Command -Name true -CommandType Application -ErrorAction Stop
            Copy-Item -LiteralPath $trueCmd.Source -Destination $OutFile
        }
        # Valid Amazon signature, so the REAL Test-SsmSignature accepts the
        # download and the runner reaches its executable and cleanup.
        Mock Get-AuthenticodeSignature -ModuleName SSMHybrid -MockWith {
            return [PSCustomObject]@{
                Status            = 'Valid'
                SignerCertificate = [PSCustomObject]@{
                    Subject = 'CN=Amazon.com Services LLC, O=Amazon.com Services LLC, L=Seattle, S=Washington, C=US'
                }
            }
        }
        # No local registration: the runner's pre-launch revalidation must
        # pass so it reaches its launch and cleanup. The race-abort tests
        # below re-mock this module function (a -ModuleName mock intercepts
        # the runner's own call to it) to plant a registration mid-window.
        Mock Get-SsmRegistrationFileJson -ModuleName SSMHybrid -MockWith {
            return $null
        }
        Mock Start-Sleep -ModuleName SSMHybrid -MockWith { }
        Mock Write-Warning -ModuleName SSMHybrid -MockWith {
            $global:EnrollCleanupWarnings = @($global:EnrollCleanupWarnings) + $Message
        }
        Mock Remove-Item -ModuleName SSMHybrid -MockWith {
            if ($global:RemoveItemFailuresRemaining -gt 0) {
                $global:RemoveItemFailuresRemaining--
                throw 'simulated antivirus lock on the downloaded executable'
            }
            [System.IO.Directory]::Delete($LiteralPath, $true)
        }
        $global:EnrollCleanupWarnings = @()
        $global:RemoveItemFailuresRemaining = 0
    }

    AfterEach {
        Remove-Variable -Name EnrollCleanupWarnings, RemoveItemFailuresRemaining -Scope Global -ErrorAction SilentlyContinue
    }

    AfterAll {
        . $script:ssmHybridModule.NewBoundScriptBlock({
            Remove-Item -Path Function:\Get-AuthenticodeSignature -ErrorAction SilentlyContinue
        })
    }

    It 'removes the temp download on the first attempt and reports it removed' {
        if (-not $script:TrueExe) { Set-ItResult -Skipped -Because 'no exit-0 executable available on this host'; return }

        $enrollmentResult = Invoke-SsmEnrollment @script:EnrollParams

        $enrollmentResult.RegistrationAppeared | Should -BeFalse
        $enrollmentResult.TempDownloadRemoved | Should -BeTrue
        $enrollmentResult.TempDownloadPath | Should -Match 'ssm-setup'
        Test-Path -LiteralPath $enrollmentResult.TempDownloadPath | Should -BeFalse
        Should -Invoke Remove-Item -ModuleName SSMHybrid -Exactly 1
        Should -Invoke Start-Sleep -ModuleName SSMHybrid -Exactly 0
        $global:EnrollCleanupWarnings | Should -BeNullOrEmpty
    }

    It 'retries a locked temp download and succeeds on the second attempt' {
        if (-not $script:TrueExe) { Set-ItResult -Skipped -Because 'no exit-0 executable available on this host'; return }
        $global:RemoveItemFailuresRemaining = 1

        $threw = $false
        $enrollmentResult = $null
        try {
            $enrollmentResult = Invoke-SsmEnrollment @script:EnrollParams
        } catch {
            $threw = $true
        }

        $threw | Should -BeFalse
        $enrollmentResult.TempDownloadRemoved | Should -BeTrue
        Test-Path -LiteralPath $enrollmentResult.TempDownloadPath | Should -BeFalse
        Should -Invoke Remove-Item -ModuleName SSMHybrid -Exactly 2
        Should -Invoke Start-Sleep -ModuleName SSMHybrid -Exactly 1 -ParameterFilter { $Seconds -eq 2 }
        $global:EnrollCleanupWarnings | Should -BeNullOrEmpty
    }

    It 'keeps enrollment a success when every removal attempt fails, warns naming the surviving path, and tries exactly three times' {
        if (-not $script:TrueExe) { Set-ItResult -Skipped -Because 'no exit-0 executable available on this host'; return }
        $global:RemoveItemFailuresRemaining = 99

        $threw = $false
        $enrollmentResult = $null
        try {
            $enrollmentResult = Invoke-SsmEnrollment @script:EnrollParams
        } catch {
            $threw = $true
        }

        $threw | Should -BeFalse
        $enrollmentResult.TempDownloadRemoved | Should -BeFalse
        $enrollmentResult.TempDownloadPath | Should -Match 'ssm-setup'
        Test-Path -LiteralPath $enrollmentResult.TempDownloadPath | Should -BeTrue
        Should -Invoke Remove-Item -ModuleName SSMHybrid -Exactly 3
        Should -Invoke Start-Sleep -ModuleName SSMHybrid -Exactly 2
        @($global:EnrollCleanupWarnings).Count | Should -Be 1
        $global:EnrollCleanupWarnings[0] | Should -Match 'Invoke-SsmEnrollment'
        $global:EnrollCleanupWarnings[0] | Should -Match ([Regex]::Escape($enrollmentResult.TempDownloadPath))

        # Tidy: the surviving directory is this test's own doing, not the module's.
        if ($enrollmentResult.TempDownloadPath) {
            Remove-Item -LiteralPath $enrollmentResult.TempDownloadPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'still runs cleanup when enrollment itself fails, and lets the original failure propagate' {
        if (-not $script:TrueExe) { Set-ItResult -Skipped -Because 'no exit-0 executable available on this host'; return }

        # Force the signature gate to refuse, so the runner throws BEFORE
        # the executable runs; the finally block must still attempt cleanup.
        Mock Test-SsmSignature -ModuleName SSMHybrid -MockWith {
            return [PSCustomObject]@{ Valid = $false; Reason = 'unit-test forced signature failure' }
        }

        $threw = $false
        $failureMessage = ''
        try {
            Invoke-SsmEnrollment @script:EnrollParams | Out-Null
        } catch {
            $threw = $true
            $failureMessage = $_.Exception.Message
        }

        $threw | Should -BeTrue
        $failureMessage | Should -Match 'signature'
        Should -Invoke Remove-Item -ModuleName SSMHybrid -Exactly 1
        $global:EnrollCleanupWarnings | Should -BeNullOrEmpty
    }

    It 'treats a ssm-setup-cli that cannot be launched as a failed enrollment, never as a stale-exit-code success' {
        $chmodAvailable = [bool](Get-Command -Name chmod -CommandType Application -ErrorAction SilentlyContinue)
        if (-not ($script:TrueExe -and $chmodAvailable)) { Set-ItResult -Skipped -Because 'this host cannot build a launch-failing executable fixture'; return }

        # The agent-quarantine shape: the download lands, passes the
        # signature gate, and then cannot be LAUNCHED (here: the copy of
        # 'true' has its execute bit removed). A launch that never happened
        # leaves $LASTEXITCODE at whatever ran earlier in the session, so the
        # stale 0 below is exactly the value the exit-code check must not be
        # allowed to read as success.
        Mock Invoke-WebRequest -ModuleName SSMHybrid -MockWith {
            $trueCmd = Get-Command -Name true -CommandType Application -ErrorAction Stop
            Copy-Item -LiteralPath $trueCmd.Source -Destination $OutFile
            & chmod 644 $OutFile
        }
        $global:LASTEXITCODE = 0

        $threw = $false
        $failureMessage = ''
        try {
            Invoke-SsmEnrollment @script:EnrollParams | Out-Null
        } catch {
            $threw = $true
            $failureMessage = $_.Exception.Message
        }

        $threw | Should -BeTrue
        $failureMessage | Should -Match 'launched'
        # The failed launch is still a failed enrollment: the finally block
        # ran its cleanup, and the failure is the throw, not a warning.
        Should -Invoke Remove-Item -ModuleName SSMHybrid -Exactly 1
        $global:EnrollCleanupWarnings | Should -BeNullOrEmpty
    }

    It 'exposes exactly RegistrationAppeared, TempDownloadPath and TempDownloadRemoved' {
        if (-not $script:TrueExe) { Set-ItResult -Skipped -Because 'no exit-0 executable available on this host'; return }

        $enrollmentResult = Invoke-SsmEnrollment @script:EnrollParams

        $properties = @($enrollmentResult.PSObject.Properties | ForEach-Object { $_.Name })
        $properties | Should -Be @('RegistrationAppeared', 'TempDownloadPath', 'TempDownloadRemoved')
    }

    It 'refuses to launch when a registration appears during the download/verification window, still cleans the temp download, and reports the race' {
        if (-not $script:TrueExe) { Set-ItResult -Skipped -Because 'no exit-0 executable available on this host'; return }

        # The competing enrollment's record, present by the time the
        # download and signature verification finish. A planted $LASTEXITCODE
        # value proves the launch never ran: the launch path resets the
        # sentinel to $null and a genuine 'true' launch then leaves 0, so a
        # value that survives the call unchanged means neither happened.
        Mock Get-SsmRegistrationFileJson -ModuleName SSMHybrid -MockWith {
            return '{"ManagedInstanceID":"mi-0123456789abcdef0","Region":"ap-southeast-2"}' # audit-allow:synthetic
        }
        $global:LASTEXITCODE = 7

        $enrollmentResult = Invoke-SsmEnrollment @script:EnrollParams
        $exitCodeAfter = $global:LASTEXITCODE

        # The refusal is POST-verification: the download and the signature
        # check both ran before the runner re-read the registration record.
        Should -Invoke Invoke-WebRequest -ModuleName SSMHybrid -Exactly 1
        Should -Invoke Get-AuthenticodeSignature -ModuleName SSMHybrid -Exactly 1
        $enrollmentResult.RegistrationAppeared | Should -BeTrue
        $exitCodeAfter | Should -Be 7
        # The refused launch still owes its cleanup postcondition: the temp
        # download is gone and reported removed, first attempt, no warning.
        $enrollmentResult.TempDownloadRemoved | Should -BeTrue
        $enrollmentResult.TempDownloadPath | Should -Match 'ssm-setup'
        Test-Path -LiteralPath $enrollmentResult.TempDownloadPath | Should -BeFalse
        Should -Invoke Remove-Item -ModuleName SSMHybrid -Exactly 1
        Should -Invoke Start-Sleep -ModuleName SSMHybrid -Exactly 0
        $global:EnrollCleanupWarnings | Should -BeNullOrEmpty
    }

    It 'treats a pre-launch registration re-read that fails as a race and refuses to launch (fail closed)' {
        if (-not $script:TrueExe) { Set-ItResult -Skipped -Because 'no exit-0 executable available on this host'; return }

        # The locked-mid-write shape: the competing enrollment is creating
        # its registration file right now, and the re-read cannot prove the
        # absence the launch depends on - so it must refuse, not launch.
        Mock Get-SsmRegistrationFileJson -ModuleName SSMHybrid -MockWith {
            throw 'simulated registration file locked mid-write by the competing enrollment'
        }
        $global:LASTEXITCODE = 7

        $enrollmentResult = Invoke-SsmEnrollment @script:EnrollParams
        $exitCodeAfter = $global:LASTEXITCODE

        $enrollmentResult.RegistrationAppeared | Should -BeTrue
        $exitCodeAfter | Should -Be 7
        $enrollmentResult.TempDownloadRemoved | Should -BeTrue
        Test-Path -LiteralPath $enrollmentResult.TempDownloadPath | Should -BeFalse
        Should -Invoke Remove-Item -ModuleName SSMHybrid -Exactly 1
        $global:EnrollCleanupWarnings | Should -BeNullOrEmpty
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
        @{
            # A parseable file whose ID is not a well-formed managed node ID
            # must not be classifiable as healthy even with a healthy service:
            # the shape failure throws, and the throw maps to Ambiguous.
            Name              = 'registration parseable but ManagedInstanceID malformed, service healthy'
            RegistrationJson  = '{"ManagedInstanceID":"garbage","Region":"ap-southeast-2"}'
            ServiceExists     = $true
            ServiceStatus     = 'Running'
            ServiceStartType  = 'Automatic'
            Expected          = 'Ambiguous'
        }
        @{
            # Same fail-closed rule for the other field setup.ps1/check.ps1
            # echo from this record: a corrupted Region must not classify as
            # healthy even with a healthy service, because the agent's region
            # config cannot be trusted. The Region check throws inside
            # ConvertFrom-SsmRegistrationJson, and the throw maps to Ambiguous.
            Name              = 'registration parseable but Region malformed, service healthy'
            RegistrationJson  = '{"ManagedInstanceID":"mi-0123456789abcdef0","Region":"garbage"}' # audit-allow:synthetic
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

    It 'throws when ManagedInstanceID is not a managed node ID' {
        { ConvertFrom-SsmRegistrationJson -Json '{"ManagedInstanceID":"garbage","Region":"ap-southeast-2"}' } | Should -Throw
    }

    # Case is part of the shape: AWS issues only lowercase mi- IDs, so an
    # uppercase variant is corruption and must throw, not pass.
    It 'throws when ManagedInstanceID is uppercase' {
        { ConvertFrom-SsmRegistrationJson -Json '{"ManagedInstanceID":"MI-0123456789ABCDEF0","Region":"ap-southeast-2"}' } | Should -Throw
    }

    It 'throws when ManagedInstanceID has too few hex digits' {
        { ConvertFrom-SsmRegistrationJson -Json '{"ManagedInstanceID":"mi-short","Region":"ap-southeast-2"}' } | Should -Throw
    }

    # Length is part of the shape too: AWS issues exactly 17 lowercase hex
    # digits after 'mi-', so 8, 16, and 18 digits (all of which sit inside
    # the audit's broad managed-node-id grammar) are corruption and must
    # throw rather than classify as registered.
    It 'throws when ManagedInstanceID has eight hex digits' {
        { ConvertFrom-SsmRegistrationJson -Json '{"ManagedInstanceID":"mi-deadbeef","Region":"ap-southeast-2"}' } | Should -Throw # audit-allow:synthetic
    }

    It 'throws when ManagedInstanceID has sixteen hex digits' {
        { ConvertFrom-SsmRegistrationJson -Json '{"ManagedInstanceID":"mi-0123456789abcdef","Region":"ap-southeast-2"}' } | Should -Throw # audit-allow:synthetic
    }

    It 'throws when ManagedInstanceID has eighteen hex digits' {
        { ConvertFrom-SsmRegistrationJson -Json '{"ManagedInstanceID":"mi-0123456789abcdef01","Region":"ap-southeast-2"}' } | Should -Throw # audit-allow:synthetic
    }

    It 'throws when ManagedInstanceID has trailing junk after a valid ID' {
        { ConvertFrom-SsmRegistrationJson -Json '{"ManagedInstanceID":"mi-0123456789abcdef0 extra","Region":"ap-southeast-2"}' } | Should -Throw # audit-allow:synthetic
    }

    # A present-but-invalid Region is corruption the same way a malformed
    # ManagedInstanceID is: setup.ps1 and check.ps1 echo the recorded region,
    # so a value that fails Test-SsmRegion must not parse as a healthy record
    # and classify the node RegisteredHealthy.
    It 'throws when Region is not a valid region code' {
        { ConvertFrom-SsmRegistrationJson -Json '{"ManagedInstanceID":"mi-0123456789abcdef0","Region":"garbage"}' } | Should -Throw # audit-allow:synthetic
    }

    # Case is part of the Region shape too: Test-SsmRegion matches
    # case-sensitively (the region code used by AWS endpoints is lowercase),
    # so a wrong-case region is corruption and must throw, not pass.
    It 'throws when Region is uppercase' {
        { ConvertFrom-SsmRegistrationJson -Json '{"ManagedInstanceID":"mi-0123456789abcdef0","Region":"US-EAST-1"}' } | Should -Throw # audit-allow:synthetic
    }

    It 'throws when Region has a trailing hyphen' {
        { ConvertFrom-SsmRegistrationJson -Json '{"ManagedInstanceID":"mi-0123456789abcdef0","Region":"us-east-1-"}' } | Should -Throw # audit-allow:synthetic
    }

    # The boundary that deliberately does NOT throw: an absent or empty
    # Region is a $null Region, not corruption - only a Region that is
    # present and nonempty is validated.
    It 'keeps Region $null when the record carries an empty Region' {
        $result = ConvertFrom-SsmRegistrationJson -Json '{"ManagedInstanceID":"mi-0123456789abcdef0","Region":""}' # audit-allow:synthetic
        $result.Region | Should -BeNullOrEmpty
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
