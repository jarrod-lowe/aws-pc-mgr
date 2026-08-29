# tests/windows/Check.Tests.ps1
#
# Windows-tier tests for scripts/windows/check.ps1 (Pester 5, SPEC plan T5).
#
# Two tiers in one file:
#   - always runnable (any OS): language-level syntax check of the entry
#     script via the parser;
#   - machine-state tests: Skip-guarded unless this is Windows (and, for the
#     managed-node-ID assertion, enrolled). These run red-then-green on the
#     real machine during validation phase V4.
#
# The tests assert that check.ps1 is read-only in effect: it is only ever
# invoked in a child process, never dot-sourced.

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:ModulePath = Join-Path $repoRoot 'scripts/windows/SSMHybrid.psm1'
$script:CheckPath = Join-Path $repoRoot 'scripts/windows/check.ps1'

# Evaluated at file load, before discovery, so -Skip conditions can use them.
$script:IsWindowsOs = ($env:OS -eq 'Windows_NT')

Import-Module -Name $script:ModulePath -Force

# Registration facts for skip guards and expectations.
$script:ManagedInstanceId = $null
$script:RegistrationJson = $null
if ($script:IsWindowsOs) {
    try {
        $script:RegistrationJson = Get-SsmRegistrationFileJson
        if (-not [string]::IsNullOrEmpty($script:RegistrationJson)) {
            $script:ManagedInstanceId = (ConvertFrom-SsmRegistrationJson -Json $script:RegistrationJson).ManagedInstanceId
        }
    } catch {
        $script:ManagedInstanceId = $null
    }
}

# Run check.ps1 in a child PowerShell with stdin closed (it prompts for
# nothing, but this keeps it non-interactive in all cases) and capture its
# exit code. Windows-only (uses the current host executable path).
# ExtraArguments are appended after -File (used to pass -AgentLogPath).
function Invoke-CheckScript {
    param([string[]]$ExtraArguments = @())

    $allArguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $script:CheckPath + '"')) + $ExtraArguments

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

Describe 'check.ps1 entry script runnability' {
    It 'parses without syntax errors (parser check)' {
        $tokens = $null
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($script:CheckPath, [ref]$tokens, [ref]$errors)
        $messages = @($errors | ForEach-Object { $_.Message })
        $messages | Should -Be @()
    }
}

Describe 'check.ps1 output on this machine (SPEC 24)' {
    It 'reports the managed node ID that matches the local registration file' -Skip:(-not ($script:IsWindowsOs -and $script:ManagedInstanceId)) {
        $result = Invoke-CheckScript
        $result.Output | Should -Match ([Regex]::Escape($script:ManagedInstanceId))
    }

    It 'never prints the activation code or any credential material' -Skip:(-not $script:IsWindowsOs) {
        $result = Invoke-CheckScript

        # Generic secret material must never appear in diagnostic output.
        $result.Output | Should -Not -Match '(?i)activation[- ]?code'
        $result.Output | Should -Not -Match '(?i)SecretAccessKey|SessionToken|AccessKeyId|SecureString|PrivateKey|aws_secret'

        # Stronger, machine-specific check: every value in the local
        # registration file except the node ID and region must be absent from
        # the output. Whatever key material the file holds, none of it leaks.
        if (-not [string]::IsNullOrEmpty($script:RegistrationJson)) {
            $registrationObject = $script:RegistrationJson | ConvertFrom-Json
            foreach ($property in $registrationObject.PSObject.Properties) {
                if (@('managedinstanceid', 'region') -contains $property.Name.ToLowerInvariant()) {
                    continue
                }
                $value = [string]$property.Value
                if ([string]::IsNullOrEmpty($value)) {
                    continue
                }
                $result.Output | Should -Not -Match ([Regex]::Escape($value))
            }
        }
    }

    It 'exits 0 when the node is healthy and 1 when problems are found' -Skip:(-not $script:IsWindowsOs) {
        # Expected outcome from raw facts, independent of check.ps1 itself.
        $expectedHealthy = $false
        $agentExe = Join-Path -Path $env:ProgramFiles -ChildPath 'Amazon\SSM\amazon-ssm-agent.exe'
        if ($script:ManagedInstanceId -and (Test-Path -LiteralPath $agentExe -PathType Leaf)) {
            $service = Get-Service -Name 'AmazonSSMAgent' -ErrorAction SilentlyContinue
            $serviceCim = Get-CimInstance -ClassName Win32_Service -Filter "Name='AmazonSSMAgent'"
            if (($null -ne $service) -and
                ($service.Status -eq 'Running') -and
                ($null -ne $serviceCim) -and
                ($serviceCim.StartMode -eq 'Auto')) {
                $expectedHealthy = $true
            }
        }
        $expectedExitCode = 1
        if ($expectedHealthy) {
            $expectedExitCode = 0
        }

        $result = Invoke-CheckScript
        $result.ExitCode | Should -Be $expectedExitCode
    }

    It 'prints clearly labeled sections for every SPEC 24 report item' -Skip:(-not $script:IsWindowsOs) {
        $result = Invoke-CheckScript
        $sectionCount = ([Regex]::Matches($result.Output, '(?m)^=== ')).Count
        $sectionCount | Should -BeGreaterThanOrEqualTo 5
        $result.Output | Should -Match 'Windows'
        $result.Output | Should -Match 'SSM Agent installation'
        $result.Output | Should -Match 'AmazonSSMAgent service'
        $result.Output | Should -Match 'SSM registration'
    }
}

Describe 'check.ps1 log-excerpt credential redaction (SPEC 24/43)' {
    # Points check.ps1 at a synthetic fixture log via its -AgentLogPath seam
    # and asserts credential-bearing warning lines are withheld while plain
    # warning lines still appear. The synthetic literals (EXAMPLE values,
    # no real key material) do not trip the repo audit's detectors.
    It 'withholds warning lines that look like credential material and prints a placeholder instead' -Skip:(-not $script:IsWindowsOs) {
        $tempLog = Join-Path ([System.IO.Path]::GetTempPath()) ('ssm-check-redact-' + [System.IO.Path]::GetRandomFileName() + '.log')
        try {
            @(
                '2026-08-29 00:00:00 WARN agent heartbeat ok'
                '2026-08-29 00:00:01 WARN enrollment failed AccessKeyId=EXAMPLE rejected'
                '2026-08-29 00:00:02 WARN enrollment failed SecretAccessKey=EXAMPLE rejected'
                '2026-08-29 00:00:03 WARN agent heartbeat still fine'
                '2026-08-29 00:00:04 WARN enrollment failed PrivateKey=EXAMPLE rejected'
                '2026-08-29 00:00:05 WARN enrollment failed ActivationCode=EXAMPLE rejected'
                '2026-08-29 00:00:06 WARN enrollment failed X-Amz-Security-Token=EXAMPLE rejected'
                '2026-08-29 00:00:07 WARN enrollment failed Token=EXAMPLE rejected'
                '2026-08-29 00:00:08 WARN enrollment failed Activation Code = EXAMPLE rejected'
                '2026-08-29 00:00:09 WARN enrollment failed Session Token: EXAMPLE rejected'
            ) | Set-Content -LiteralPath $tempLog

            $result = Invoke-CheckScript -ExtraArguments @('-AgentLogPath', ('"' + $tempLog + '"'))

            # Plain warning lines are still printed verbatim.
            $result.Output | Should -Match ([Regex]::Escape('agent heartbeat ok'))
            $result.Output | Should -Match ([Regex]::Escape('agent heartbeat still fine'))
            # Credential-bearing lines are withheld behind the placeholder...
            $result.Output | Should -Match ([Regex]::Escape('[line withheld: possible credential material]'))
            # ...and their material never reaches the output. ActivationCode
            # covers the camelCase spelling the agent log actually uses;
            # security[-_]?token covers the X-Amz-Security-Token header
            # spelling, and the bare token\s*= covers Token=. The last two
            # lines use whitespace-separated labels ('Activation Code =',
            # 'Session Token:') - the label alternations tolerate separators
            # INSIDE the label, so those spellings are withheld too.
            $result.Output | Should -Not -Match ([Regex]::Escape('AccessKeyId=EXAMPLE'))
            $result.Output | Should -Not -Match ([Regex]::Escape('SecretAccessKey=EXAMPLE'))
            $result.Output | Should -Not -Match ([Regex]::Escape('PrivateKey=EXAMPLE'))
            $result.Output | Should -Not -Match ([Regex]::Escape('ActivationCode=EXAMPLE'))
            $result.Output | Should -Not -Match ([Regex]::Escape('X-Amz-Security-Token=EXAMPLE'))
            $result.Output | Should -Not -Match ([Regex]::Escape('Token=EXAMPLE'))
            $result.Output | Should -Not -Match ([Regex]::Escape('Activation Code = EXAMPLE'))
            $result.Output | Should -Not -Match ([Regex]::Escape('Session Token: EXAMPLE'))
            # The withheld count is reported in the summary.
            $result.Output | Should -Match '8 recent log warning/error line\(s\) withheld'
        } finally {
            Remove-Item -LiteralPath $tempLog -Force -ErrorAction SilentlyContinue
        }
    }
}
