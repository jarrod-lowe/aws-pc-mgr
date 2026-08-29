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

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:ModulePath = Join-Path $repoRoot 'scripts/windows/SSMHybrid.psm1'
$script:SetupPath = Join-Path $repoRoot 'scripts/windows/setup.ps1'

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

Describe 'setup.ps1 entry script runnability' {
    It 'parses without syntax errors (parser check)' {
        $tokens = $null
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($script:SetupPath, [ref]$tokens, [ref]$errors)
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
    # Invalid parameters make the script prompt; with stdin at EOF the prompt
    # yields nothing, so the script must give up with exit code 2 (SPEC 42).
    It 'exits 2 when region and activation ID are invalid and no input is available' -Skip:(-not ($script:IsWindowsOs -and $script:IsElevated)) {
        $result = Invoke-EntryScript -ScriptPath $script:SetupPath -ScriptArguments @('-Region', 'not-a-region', '-ActivationId', 'not-an-id')
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
        $result = Invoke-EntryScript -ScriptPath $script:SetupPath -ScriptArguments @(
            '-Region', 'ap-southeast-2',
            '-ActivationId', ([Guid]::NewGuid().ToString())
        )

        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match 'NoOperation'
        $result.Output | Should -Match ([Regex]::Escape($script:ManagedInstanceId))
        $result.Output | Should -Not -Match 'action: Register'
    }

    It 'second run does not prompt for the activation code' -Skip:(-not ($script:IsWindowsOs -and $script:IsElevated -and $script:RegisteredHealthy)) {
        $result = Invoke-EntryScript -ScriptPath $script:SetupPath -ScriptArguments @(
            '-Region', 'ap-southeast-2',
            '-ActivationId', ([Guid]::NewGuid().ToString())
        )
        # The masked prompt text appears only when a registration would run.
        $result.Output | Should -Not -Match 'input is masked'
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
