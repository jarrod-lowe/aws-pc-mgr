# tests/windows/Setup.Tests.ps1
#
# Windows-tier tests for scripts/windows/setup.ps1 (Pester 5, SPEC plan T4).
#
# Two tiers in one file:
#   - always runnable (any OS): module import, contract-function presence,
#     and a language-level syntax check of the entry script via the parser;
#   - machine-state tests: Skip-guarded unless this is Windows, elevated,
#     and (for idempotence) already enrolled. These run red-then-green on
#     the real machine during validation phase V4; they cannot run on the
#     macOS development machine.
#
# No activation code or other secret is ever passed to, or expected from,
# anything in this file.
#
# Pester 5 scoping: the file-load block below runs during discovery and is
# visible ONLY to the -Skip conditions (bound at that time). It bodies run
# later in a scope of Pester's own, where file-load variables and functions
# are not visible - so everything the run phase touches is re-derived in the
# BeforeAll block (and inline in the always-runnable parse check) from
# $PSScriptRoot, which does resolve there.

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:ModulePath = Join-Path $repoRoot 'scripts/windows/SSMHybrid.psm1'

# Evaluated at file load, before discovery, so -Skip conditions can use them.
$script:IsWindowsOs = ($env:OS -eq 'Windows_NT')
$script:IsElevated = $false
if ($script:IsWindowsOs) {
    $windowsPrincipal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList ([Security.Principal.WindowsIdentity]::GetCurrent())
    $script:IsElevated = $windowsPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Import-Module -Name $script:ModulePath -Force

# Registration facts for skip guards (raw OS queries, independent of the
# adapters under test). Any failure here simply leaves the guards at $false.
$script:ManagedInstanceId = $null
$script:RegisteredHealthy = $false
if ($script:IsWindowsOs) {
    try {
        $registrationJson = Get-SsmRegistrationFileJson
        if (-not [string]::IsNullOrEmpty($registrationJson)) {
            $script:ManagedInstanceId = (ConvertFrom-SsmRegistrationJson -Json $registrationJson).ManagedInstanceId
        }
    } catch {
        $script:ManagedInstanceId = $null
    }
    if ($script:ManagedInstanceId) {
        $service = Get-Service -Name 'AmazonSSMAgent' -ErrorAction SilentlyContinue
        $serviceCim = Get-CimInstance -ClassName Win32_Service -Filter "Name='AmazonSSMAgent'"
        if (($null -ne $service) -and
            ($service.Status -eq 'Running') -and
            ($null -ne $serviceCim) -and
            ($serviceCim.StartMode -eq 'Auto')) {
            $script:RegisteredHealthy = $true
        }
    }
}

# Run-phase setup (see the scoping note in the header). Everything the It
# bodies below touch is re-derived here: paths from $PSScriptRoot,
# registration facts from the module (imported at file load, so its command
# surface is visible), and the child-process helper defined here, where It
# bodies can call it.
BeforeAll {
    $SetupPath = Join-Path $PSScriptRoot '../../scripts/windows/setup.ps1'

    $ManagedInstanceId = $null
    if ($env:OS -eq 'Windows_NT') {
        try {
            $registrationJson = Get-SsmRegistrationFileJson
            if (-not [string]::IsNullOrEmpty($registrationJson)) {
                $ManagedInstanceId = (ConvertFrom-SsmRegistrationJson -Json $registrationJson).ManagedInstanceId
            }
        } catch {
            $ManagedInstanceId = $null
        }
    }

    # Run an entry script in a child PowerShell with stdin closed, so any
    # interactive prompt sees EOF instead of blocking, and capture its exit
    # code. Windows-only (uses the current host executable path).
    function Invoke-EntryScript {
        param(
            [string]$ScriptPath,
            [string[]]$ScriptArguments = @()
        )

        $allArguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $ScriptPath + '"'))
        $allArguments += $ScriptArguments

        $startInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = (Get-Process -Id $PID).Path
        $startInfo.Arguments = ($allArguments -join ' ')
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardInput = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.CreateNoWindow = $true

        $process = [System.Diagnostics.Process]::Start($startInfo)
        $process.StandardInput.Close()
        $errorReader = $process.StandardError.ReadToEndAsync()
        $outputText = $process.StandardOutput.ReadToEnd()
        $process.WaitForExit()

        return [PSCustomObject]@{
            Output   = ($outputText + [Environment]::NewLine + $errorReader.Result)
            ExitCode = $process.ExitCode
        }
    }
}

Describe 'setup.ps1 entry script runnability' {
    It 'parses without syntax errors (parser check)' {
        # The path is derived here rather than read from the file-load
        # $script:SetupPath: Pester 5 runs It bodies in a scope of its own
        # where that variable resolves empty (this check's original failure).
        # $PSScriptRoot does resolve inside It, and the forward-slash form
        # matches the unit suite and is valid on Windows PowerShell 5.1 too.
        $setupPath = Join-Path $PSScriptRoot '../../scripts/windows/setup.ps1'
        $tokens = $null
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($setupPath, [ref]$tokens, [ref]$errors)
        $messages = @($errors | ForEach-Object { $_.Message })
        $messages | Should -Be @()
    }

    It 'imports SSMHybrid.psm1 exposing contract function <Function>' -TestCases @(
        @{ Function = 'Test-SsmRegion' }
        @{ Function = 'Test-SsmActivationId' }
        @{ Function = 'Get-SsmSetupCliUrl' }
        @{ Function = 'ConvertFrom-SsmRegistrationJson' }
        @{ Function = 'Get-SsmNodeState' }
        @{ Function = 'Get-SsmSetupAction' }
        @{ Function = 'Test-SsmSignature' }
        @{ Function = 'Read-SsmSecret' }
        @{ Function = 'Get-SsmServiceInfo' }
        @{ Function = 'Get-SsmRegistrationFileJson' }
        @{ Function = 'Invoke-SsmEnrollment' }
    ) {
        param($Function)
        $command = Get-Command -Name $Function -ErrorAction SilentlyContinue
        $command | Should -Not -BeNullOrEmpty
    }
}

Describe 'setup.ps1 input handling' {
    # Invalid values SUPPLIED as parameters are validated before any local
    # state is inspected: the follow-up prompt sees EOF (stdin closed by
    # Invoke-EntryScript), so the script must give up with exit code 2 (SPEC
    # 42) without ever classifying or acting. Omitted (empty) values are no
    # longer prompted for at input time - only the Register action asks, see
    # the idempotence tests below.
    It 'exits 2 when region and activation ID are supplied invalid and no input is available' -Skip:(-not ($script:IsWindowsOs -and $script:IsElevated)) {
        $result = Invoke-EntryScript -ScriptPath $SetupPath -ScriptArguments @('-Region', 'not-a-region', '-ActivationId', 'not-an-id')
        $result.ExitCode | Should -Be 2
    }

    It 'exits 2 when only the region is supplied invalid, even with no activation ID given' -Skip:(-not ($script:IsWindowsOs -and $script:IsElevated)) {
        $result = Invoke-EntryScript -ScriptPath $SetupPath -ScriptArguments @('-Region', 'not-a-region')
        $result.ExitCode | Should -Be 2
    }
}

Describe 'setup.ps1 idempotence (SPEC 36)' {
    # Second invocation on an enrolled, healthy machine: existing
    # registration detected, same managed node ID reported, service checked,
    # NoOperation (no new activation consumed, no new identity created).
    # Same-mi-id output plus a NoOperation plan is the locally observable
    # evidence; "no new activation consumed" is additionally confirmed in AWS
    # during validation phase V5.
    It 'second run reports NoOperation with the same managed node ID and exits 0' -Skip:(-not ($script:IsWindowsOs -and $script:IsElevated -and $script:RegisteredHealthy)) {
        $result = Invoke-EntryScript -ScriptPath $SetupPath -ScriptArguments @(
            '-Region', 'ap-southeast-2',
            '-ActivationId', ([Guid]::NewGuid().ToString())
        )

        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match 'NoOperation'
        $result.Output | Should -Match ([Regex]::Escape($ManagedInstanceId))
        $result.Output | Should -Not -Match 'action: Register'
    }

    It 'second run does not prompt for the activation code' -Skip:(-not ($script:IsWindowsOs -and $script:IsElevated -and $script:RegisteredHealthy)) {
        $result = Invoke-EntryScript -ScriptPath $SetupPath -ScriptArguments @(
            '-Region', 'ap-southeast-2',
            '-ActivationId', ([Guid]::NewGuid().ToString())
        )
        # The masked prompt text appears only when a registration would run.
        $result.Output | Should -Not -Match 'input is masked'
    }

    # The documented safe re-run is the BARE command with no parameters at
    # all (SPEC 22/36). The script must classify local state first and reach
    # NoOperation without prompting: stdin is closed, so any prompt would
    # read EOF, exhaust its retries, and drive the exit code to 2 instead.
    It 'parameterless re-run reaches NoOperation and exits 0 without prompting' -Skip:(-not ($script:IsWindowsOs -and $script:IsElevated -and $script:RegisteredHealthy)) {
        $result = Invoke-EntryScript -ScriptPath $SetupPath

        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match 'NoOperation'
        $result.Output | Should -Match ([Regex]::Escape($ManagedInstanceId))
        $result.Output | Should -Not -Match 'input is masked'
        $result.Output | Should -Not -Match 'Enter the (AWS region|SSM activation ID)'
    }
}

Describe 'setup.ps1 post-classification revalidation (SPEC 22)' {
    # CLASS-LEVEL DISCIPLINE, not one instance: every place setup.ps1
    # re-reads state it classified moments earlier must fail closed when the
    # re-read no longer matches the classification, and must repair (not
    # merely re-observe) the drift that is safely repairable. The states
    # this discipline exists for - the registration file deleted, emptied,
    # or rewritten, or the service start type flipped to Manual/Disabled,
    # all BETWEEN the classification reads and the re-reads inside one run -
    # CANNOT be driven from outside a child process: setup.ps1 has no path
    # seams (unlike check.ps1's -RegistrationPath/-AgentLogPath), and no
    # external input decides what a read taken mid-run returns. Revalidation
    # call-site inventory and its disposition:
    #   classification reads (service, registration) - own try/catch,
    #       exit 1 (service query) / exit 3 (registration read)
    #   NoOperation registration re-read - fail-closed guard: $null (gone or
    #       emptied) or throw (unreadable/unparseable) exits 3, the same
    #       ambiguous verdict classification gives an unparseable file
    #   NoOperation service re-check - fail-closed on query failure (exit
    #       1); a stopped service is started and a non-Automatic start type
    #       restored, then BOTH Running AND Automatic are re-queried and
    #       must hold or the run exits 1
    #   StartService registration re-read - the same fail-closed guard
    #   StartService service checks - fail-closed wrapper; the start type is
    #       re-verified after the start (it can be flipped back between the
    #       pre-start Set-Service and the post-start query), and both facts
    #       are required for success
    #   Register post-enrollment registration read + service checks -
    #       fail-closed (exit 1) on unparseable/absent registration and on
    #       not Running/Automatic after the repairs, both re-verified
    #   Reregister pre-clear service reads - fail-closed wrapper plus a
    #       verified-stopped gate before anything destructive
    # This file has no static source-text assertions (its always-runnable
    # tier is the parser and contract checks only), so the committed
    # coverage is what IS drivable: the parse check above runs over the
    # edited script on every OS, and on a real enrolled Windows machine the
    # test below asserts the observable surface of the invariant. The
    # state-specific proof was a red/green demonstration against a scratch
    # copy of setup.ps1 with the module readers stubbed stateful (the same
    # scratch-copy approach Check.Tests documents for its non-drivable
    # states), run with the fix and not committed.
    It 'health report of the parameterless re-run states both re-verified facts: Running and Automatic' -Skip:(-not ($script:IsWindowsOs -and $script:IsElevated -and $script:RegisteredHealthy)) {
        $result = Invoke-EntryScript -ScriptPath $SetupPath

        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match 'NoOperation'
        # SPEC 22's health verdict requires BOTH facts at re-query time, and
        # the verdict line reports the re-queried service state: anything
        # other than Running/Automatic here would mean health was declared
        # over a start type that was not verified after classification.
        $result.Output | Should -Match 'AmazonSSMAgent Running / startup Automatic'
        $result.Output | Should -Not -Match 'startup Manual'
        $result.Output | Should -Not -Match 'startup Disabled'
        # The verdict line must also never carry a blank managed-node ID:
        # the ID is read again under the fail-closed guard, so a vanished
        # registration can no longer be printed as an empty value.
        $result.Output | Should -Not -Match '(?m)^Managed node ID : \s*$'
    }
}

Describe 'ssm-setup-cli signature verification (SPEC 21 steps 7-8)' {
    It 'accepts the Authenticode signature of the AWS-downloaded ssm-setup-cli' -Skip:(-not $script:IsWindowsOs) {
        $url = Get-SsmSetupCliUrl -Region 'ap-southeast-2'
        $tempExe = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('ssm-setup-cli-' + [Guid]::NewGuid().ToString('N') + '.exe')
        try {
            Invoke-WebRequest -Uri $url -OutFile $tempExe -UseBasicParsing
            $signature = Get-AuthenticodeSignature -FilePath $tempExe
            $verdict = Test-SsmSignature -Status ([string]$signature.Status) -SignerSubject ([string]$signature.SignerCertificate.Subject)
            $verdict.Valid | Should -BeTrue
        } finally {
            if (Test-Path -LiteralPath $tempExe) {
                Remove-Item -LiteralPath $tempExe -Force -ErrorAction SilentlyContinue
            }
        }
    }

    It 'refuses an unsigned executable' -Skip:(-not $script:IsWindowsOs) {
        $tempExe = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('unsigned-' + [Guid]::NewGuid().ToString('N') + '.exe')
        try {
            Set-Content -LiteralPath $tempExe -Value 'this is not a signed executable'
            $signature = Get-AuthenticodeSignature -FilePath $tempExe
            ([string]$signature.Status) | Should -Be 'NotSigned'
            $verdict = Test-SsmSignature -Status ([string]$signature.Status) -SignerSubject ([string]$signature.SignerCertificate.Subject)
            $verdict.Valid | Should -BeFalse
        } finally {
            if (Test-Path -LiteralPath $tempExe) {
                Remove-Item -LiteralPath $tempExe -Force -ErrorAction SilentlyContinue
            }
        }
    }

    It 'refuses to execute an unsigned download before any registration attempt' -Skip:(-not $script:IsWindowsOs) {
        $tempExe = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('unsigned-' + [Guid]::NewGuid().ToString('N') + '.exe')
        $tempCopy = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('copy-' + [Guid]::NewGuid().ToString('N') + '.exe')
        try {
            Set-Content -LiteralPath $tempExe -Value 'this is not a signed executable'
            $fileUrl = 'file:///' + ($tempExe -replace '\\', '/')

            # Confirm this host can fetch a file:// URL at all before using it
            # as the enrollment download source.
            try {
                Invoke-WebRequest -Uri $fileUrl -OutFile $tempCopy -UseBasicParsing -ErrorAction Stop
            } catch {
                Set-ItResult -Skipped -Because ('file:// download is not supported by this host: ' + $_.Exception.Message)
                return
            }

            $threw = $false
            $failureMessage = ''
            try {
                Invoke-SsmEnrollment -Region 'ap-southeast-2' -ActivationId ([Guid]::NewGuid().ToString()) -ActivationCode 'not-a-real-code' -Url $fileUrl
            } catch {
                $threw = $true
                $failureMessage = $_.Exception.Message
            }

            $threw | Should -BeTrue
            $failureMessage | Should -Match 'signature'
        } finally {
            if (Test-Path -LiteralPath $tempExe) {
                Remove-Item -LiteralPath $tempExe -Force -ErrorAction SilentlyContinue
            }
            if (Test-Path -LiteralPath $tempCopy) {
                Remove-Item -LiteralPath $tempCopy -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
