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

Import-Module -Name $script:ModulePath -Force

# Registration facts for skip guards. Any failure here simply leaves the
# guard at $false.
$script:ManagedInstanceId = $null
if ($script:IsWindowsOs) {
    try {
        $registrationJson = Get-SsmRegistrationFileJson
        if (-not [string]::IsNullOrEmpty($registrationJson)) {
            $script:ManagedInstanceId = (ConvertFrom-SsmRegistrationJson -Json $registrationJson).ManagedInstanceId
        }
    } catch {
        $script:ManagedInstanceId = $null
    }
}

# Run-phase setup (see the scoping note in the header). Everything the It
# bodies below touch is re-derived here: paths from $PSScriptRoot,
# registration facts from the module (imported at file load, so its command
# surface is visible), and the child-process helper defined here, where It
# bodies can call it.
BeforeAll {
    $ManagedInstanceId = $null
    $RegistrationJson = $null
    if ($env:OS -eq 'Windows_NT') {
        try {
            $RegistrationJson = Get-SsmRegistrationFileJson
            if (-not [string]::IsNullOrEmpty($RegistrationJson)) {
                $ManagedInstanceId = (ConvertFrom-SsmRegistrationJson -Json $RegistrationJson).ManagedInstanceId
            }
        } catch {
            $ManagedInstanceId = $null
        }
    }

    # Run check.ps1 in a child PowerShell with stdin closed (it prompts for
    # nothing, but this keeps it non-interactive in all cases) and capture its
    # exit code. Windows-only (uses the current host executable path).
    # ExtraArguments are appended after -File (used to pass -AgentLogPath).
    function Invoke-CheckScript {
        param([string[]]$ExtraArguments = @())

        # Derived here from $PSScriptRoot (this function is defined by the
        # test file, so its $PSScriptRoot is tests/windows) rather than from
        # a file-load $script: variable, which Pester 5 It bodies cannot see.
        $checkPath = Join-Path $PSScriptRoot '../../scripts/windows/check.ps1'
        $allArguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $checkPath + '"')) + $ExtraArguments

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

Describe 'check.ps1 entry script runnability' {
    It 'parses without syntax errors (parser check)' {
        # The path is derived here rather than read from the file-load
        # $script:CheckPath: Pester 5 runs It bodies in a scope of its own
        # where that variable resolves empty (this check's original failure).
        # $PSScriptRoot does resolve inside It, and the forward-slash form
        # matches the unit suite and is valid on Windows PowerShell 5.1 too.
        $checkPath = Join-Path $PSScriptRoot '../../scripts/windows/check.ps1'
        $tokens = $null
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($checkPath, [ref]$tokens, [ref]$errors)
        $messages = @($errors | ForEach-Object { $_.Message })
        $messages | Should -Be @()
    }
}

Describe 'check.ps1 output on this machine (SPEC 24)' {
    It 'reports the managed node ID that matches the local registration file' -Skip:(-not ($script:IsWindowsOs -and $script:ManagedInstanceId)) {
        $result = Invoke-CheckScript
        $result.Output | Should -Match ([Regex]::Escape($ManagedInstanceId))
    }

    It 'never prints the activation code or any credential material' -Skip:(-not $script:IsWindowsOs) {
        $result = Invoke-CheckScript

        # Generic secret material must never appear in diagnostic output.
        $result.Output | Should -Not -Match '(?i)activation[- ]?code'
        $result.Output | Should -Not -Match '(?i)SecretAccessKey|SessionToken|AccessKeyId|SecureString|PrivateKey|aws_secret'

        # Stronger, machine-specific check: every value in the local
        # registration file except the node ID and region must be absent from
        # the output. Whatever key material the file holds, none of it leaks.
        if (-not [string]::IsNullOrEmpty($RegistrationJson)) {
            $registrationObject = $RegistrationJson | ConvertFrom-Json
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
        if ($ManagedInstanceId -and (Test-Path -LiteralPath $agentExe -PathType Leaf)) {
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
    # warning lines still appear. The synthetic literals (EXAMPLE values, no
    # real key material) do not trip the repo audit's detectors; the one
    # UUID-shaped literal does trip the audit's uuid-literal detector, so
    # that fixture line carries the documented synthetic marker.
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
                '2026-08-29 00:00:10 WARN enrollment failed ActivationId = 00000000-0000-0000-0000-000000000000 rejected' # audit-allow:synthetic
                '2026-08-29 00:00:11 WARN enrollment failed "ActivationCode": "EXAMPLE" rejected'
                '2026-08-29 00:00:12 WARN enrollment failed ACTIVATION CODE: EXAMPLE rejected'
                '2026-08-29 00:00:13 WARN enrollment failed Secret Access Key = EXAMPLE rejected'
            ) | Set-Content -LiteralPath $tempLog

            $result = Invoke-CheckScript -ExtraArguments @('-AgentLogPath', ('"' + $tempLog + '"'))

            # Plain warning lines are still printed verbatim.
            $result.Output | Should -Match ([Regex]::Escape('agent heartbeat ok'))
            $result.Output | Should -Match ([Regex]::Escape('agent heartbeat still fine'))
            # Credential-bearing lines are withheld behind the placeholder...
            $result.Output | Should -Match ([Regex]::Escape('[line withheld: possible credential material]'))
            # ...and their material never reaches the output. The fixture log
            # walks the systematic label-variant set the credential pattern
            # is built to cover: camelCase (ActivationCode, AccessKeyId,
            # SecretAccessKey, PrivateKey - the spellings the agent log
            # actually uses), JSON-style camelCase with a quoted key
            # ('"ActivationCode":'), UPPERCASE ('ACTIVATION CODE:'), spaced
            # title-case ('Activation Code =', 'Session Token:',
            # 'Secret Access Key ='), and underscore/dashed env-style where
            # they appear. check.ps1 builds every label alternation from word
            # arrays joined with [\s_-]* under (?i), so all case and
            # separator variants are covered by construction; activation
            # id-variants cover ActivationId / 'Activation ID' /
            # activation_id (the ID is not a secret, but a log echoing it
            # identifies the enrollment, so it is withheld too);
            # security-token covers the X-Amz-Security-Token header spelling,
            # and the bare token\s*= covers Token=. The EXAMPLE values stay
            # under the repo audit's value-length anchors, so this test file
            # itself stays audit-clean.
            $result.Output | Should -Not -Match ([Regex]::Escape('AccessKeyId=EXAMPLE'))
            $result.Output | Should -Not -Match ([Regex]::Escape('SecretAccessKey=EXAMPLE'))
            $result.Output | Should -Not -Match ([Regex]::Escape('PrivateKey=EXAMPLE'))
            $result.Output | Should -Not -Match ([Regex]::Escape('ActivationCode=EXAMPLE'))
            $result.Output | Should -Not -Match ([Regex]::Escape('"ActivationCode": "EXAMPLE"'))
            $result.Output | Should -Not -Match ([Regex]::Escape('ACTIVATION CODE: EXAMPLE'))
            $result.Output | Should -Not -Match ([Regex]::Escape('Secret Access Key = EXAMPLE'))
            $result.Output | Should -Not -Match ([Regex]::Escape('X-Amz-Security-Token=EXAMPLE'))
            $result.Output | Should -Not -Match ([Regex]::Escape('Token=EXAMPLE'))
            $result.Output | Should -Not -Match ([Regex]::Escape('Activation Code = EXAMPLE'))
            $result.Output | Should -Not -Match ([Regex]::Escape('Session Token: EXAMPLE'))
            $result.Output | Should -Not -Match ([Regex]::Escape('ActivationId = 00000000-0000-0000-0000-000000000000')) # audit-allow:synthetic
            # The withheld count is reported in the summary.
            $result.Output | Should -Match '12 recent log warning/error line\(s\) withheld'
        } finally {
            Remove-Item -LiteralPath $tempLog -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'check.ps1 read-failure reporting (SPEC 24)' {
    # A registration file - and likewise the agent log - can exist and still
    # be UNREADABLE: check.ps1 is documented as runnable without elevation,
    # and an unelevated session can be denied the file's ACL. That state must
    # be reported as a read failure - path plus coarse category, never the
    # file's content - and must count as a problem: folding a registration
    # read failure into the 'no registration file' report would misdiagnose
    # an enrolled machine as unenrolled, and leaving an agent-log read
    # failure uncounted would let an otherwise healthy machine exit 0 with
    # 'All checks passed' even though the log diagnostic was never performed.
    # This block is the inverse polarity of the machine-state blocks above:
    # it runs wherever an unreadable file can be arranged without elevation
    # (the Linux test container, via check.ps1's -RegistrationPath and
    # -AgentLogPath seams) and is Skip-guarded on Windows, where an
    # unreadable fixture needs an ACL the test itself cannot set unelevated.
    # Tests that break an input by making it MISSING need no unreadability
    # arrangement, so they carry no Skip guard and run on every OS (the
    # missing-log test below, and the class-invariant block nested at the
    # end of this Describe).
    BeforeAll {
        # Same child-process pattern as Invoke-CheckScript, with an optional
        # launcher executable prepended to the command line: a root test
        # process bypasses file modes (CAP_DAC_OVERRIDE), so making the
        # fixture genuinely unreadable for the child can require running the
        # child as an unprivileged user through setpriv(1). -AgentLogPath is
        # appended only when given, so registration-only invocations are
        # unchanged.
        function Invoke-CheckScriptViaLauncher {
            param(
                [string]$RegistrationPath = '',
                [string]$AgentLogPath = '',
                [string]$CheckPath = '',
                [string]$LauncherExe = '',
                [string[]]$LauncherArguments = @()
            )

            # -CheckPath defaults to the real script, so every invocation that
            # does not pass it runs the committed check.ps1 exactly as before;
            # the override exists so the class-invariant block below can be
            # pointed at a scratch copy of check.ps1 (red/green demonstration
            # of the invariant against a deliberately broken copy).
            if ([string]::IsNullOrEmpty($CheckPath)) {
                $CheckPath = Join-Path $PSScriptRoot '../../scripts/windows/check.ps1'
            }
            $childArguments = @(
                '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $CheckPath + '"'),
                '-RegistrationPath', ('"' + $RegistrationPath + '"')
            )
            if (-not [string]::IsNullOrEmpty($AgentLogPath)) {
                $childArguments += @('-AgentLogPath', ('"' + $AgentLogPath + '"'))
            }

            $startInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
            if ([string]::IsNullOrEmpty($LauncherExe)) {
                $startInfo.FileName = (Get-Process -Id $PID).Path
                $startInfo.Arguments = ($childArguments -join ' ')
            } else {
                $startInfo.FileName = $LauncherExe
                $startInfo.Arguments = (($LauncherArguments + $childArguments) -join ' ')
            }
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

    It 'reports a registration file that exists but cannot be read as a read failure, not as absence' -Skip:($script:IsWindowsOs) {
        $fixture = Join-Path ([System.IO.Path]::GetTempPath()) ('ssm-check-unreadable-' + [System.IO.Path]::GetRandomFileName())
        # Distinctive non-credential body: none of it may reach the output.
        $sentinel = 'ssm-check-fixture-body-sentinel'
        try {
            Set-Content -LiteralPath $fixture -Value $sentinel
            & chmod 000 $fixture

            # The fixture must be genuinely unreadable by whichever principal
            # runs the child, or the test would exercise the wrong state. An
            # unprivileged test process is already denied by the file mode; a
            # root one bypasses it, so the child runs as nobody via setpriv(1)
            # - and if even that cannot arrange a denial here, the test skips
            # rather than assert against a readable fixture.
            $launcherExe = ''
            $launcherArguments = @()
            $unreadableDirectly = $false
            try {
                $null = Get-Content -LiteralPath $fixture -Raw -ErrorAction Stop
            } catch {
                $unreadableDirectly = $true
            }
            if (-not $unreadableDirectly) {
                $setpriv = Get-Command -Name setpriv -ErrorAction SilentlyContinue
                $cat = Get-Command -Name cat -ErrorAction SilentlyContinue
                if (($null -ne $setpriv) -and ($null -ne $cat)) {
                    $probeInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
                    $probeInfo.FileName = $setpriv.Source
                    $probeInfo.Arguments = ('--reuid=nobody --regid=nogroup --clear-groups ' + $cat.Source + ' ' + $fixture)
                    $probeInfo.UseShellExecute = $false
                    $probeInfo.RedirectStandardOutput = $true
                    $probeInfo.RedirectStandardError = $true
                    $probeInfo.CreateNoWindow = $true
                    $probe = [System.Diagnostics.Process]::Start($probeInfo)
                    $null = $probe.StandardOutput.ReadToEnd()
                    $null = $probe.StandardError.ReadToEnd()
                    $probe.WaitForExit()
                    if ($probe.ExitCode -ne 0) {
                        $launcherExe = $setpriv.Source
                        $launcherArguments = @('--reuid=nobody', '--regid=nogroup', '--clear-groups', (Get-Process -Id $PID).Path)
                    }
                }
            }
            if ((-not $unreadableDirectly) -and [string]::IsNullOrEmpty($launcherExe)) {
                Set-ItResult -Skipped -Because 'this host cannot make the fixture unreadable for the child process (root without setpriv)'
                return
            }

            $result = Invoke-CheckScriptViaLauncher -RegistrationPath $fixture -LauncherExe $launcherExe -LauncherArguments $launcherArguments

            # The read failure is reported distinctly, with the path and a
            # coarse failure category...
            $result.Output | Should -Match 'registration file exists but could not be read'
            $result.Output | Should -Match ([Regex]::Escape($fixture))
            $result.Output | Should -Match 'Failure category'
            # ...never as the absence report for an unenrolled machine...
            $result.Output | Should -Not -Match 'No local SSM registration file was found'
            $result.Output | Should -Not -Match 'No local SSM registration:'
            # ...it counts as a problem found, since health could not be
            # verified...
            $result.ExitCode | Should -Be 1
            # ...and nothing from inside the file - nor error text quoting it -
            # ever reaches the output.
            $result.Output | Should -Not -Match ([Regex]::Escape($sentinel))
        } finally {
            Remove-Item -LiteralPath $fixture -Force -ErrorAction SilentlyContinue
        }
    }

    It 'reports an unparseable registration file as invalid data, not as absence' -Skip:($script:IsWindowsOs) {
        $fixture = Join-Path ([System.IO.Path]::GetTempPath()) ('ssm-check-unparseable-' + [System.IO.Path]::GetRandomFileName())
        # Truncated JSON whose body must stay out of the output: the parser's
        # own error text can quote the payload, so it is never printed either.
        $sentinel = 'ssm-check-parse-sentinel'
        try {
            Set-Content -LiteralPath $fixture -Value ('{"ManagedInstanceID":"' + $sentinel)

            $result = Invoke-CheckScriptViaLauncher -RegistrationPath $fixture

            $result.Output | Should -Match 'registration file exists but could not be parsed'
            $result.Output | Should -Match ([Regex]::Escape($fixture))
            $result.Output | Should -Not -Match 'No local SSM registration file was found'
            $result.Output | Should -Not -Match 'No local SSM registration:'
            $result.ExitCode | Should -Be 1
            $result.Output | Should -Not -Match ([Regex]::Escape($sentinel))
        } finally {
            Remove-Item -LiteralPath $fixture -Force -ErrorAction SilentlyContinue
        }
    }

    It 'reports an agent log that exists but cannot be read as a problem, so the check cannot pass' -Skip:($script:IsWindowsOs) {
        $fixture = Join-Path ([System.IO.Path]::GetTempPath()) ('ssm-check-unreadable-log-' + [System.IO.Path]::GetRandomFileName() + '.log')
        # Distinctive non-credential body: none of it may reach the output.
        $sentinel = 'ssm-check-log-fixture-body-sentinel'
        try {
            Set-Content -LiteralPath $fixture -Value $sentinel
            & chmod 000 $fixture

            # Same unreadability arrangement as the registration fixture
            # above: the fixture must be genuinely unreadable by whichever
            # principal runs the child, or the test would exercise the wrong
            # state. An unprivileged test process is already denied by the
            # file mode; a root one bypasses it, so the child runs as nobody
            # via setpriv(1) - and if even that cannot arrange a denial here,
            # the test skips rather than assert against a readable fixture.
            $launcherExe = ''
            $launcherArguments = @()
            $unreadableDirectly = $false
            try {
                $null = Get-Content -LiteralPath $fixture -Raw -ErrorAction Stop
            } catch {
                $unreadableDirectly = $true
            }
            if (-not $unreadableDirectly) {
                $setpriv = Get-Command -Name setpriv -ErrorAction SilentlyContinue
                $cat = Get-Command -Name cat -ErrorAction SilentlyContinue
                if (($null -ne $setpriv) -and ($null -ne $cat)) {
                    $probeInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
                    $probeInfo.FileName = $setpriv.Source
                    $probeInfo.Arguments = ('--reuid=nobody --regid=nogroup --clear-groups ' + $cat.Source + ' ' + $fixture)
                    $probeInfo.UseShellExecute = $false
                    $probeInfo.RedirectStandardOutput = $true
                    $probeInfo.RedirectStandardError = $true
                    $probeInfo.CreateNoWindow = $true
                    $probe = [System.Diagnostics.Process]::Start($probeInfo)
                    $null = $probe.StandardOutput.ReadToEnd()
                    $null = $probe.StandardError.ReadToEnd()
                    $probe.WaitForExit()
                    if ($probe.ExitCode -ne 0) {
                        $launcherExe = $setpriv.Source
                        $launcherArguments = @('--reuid=nobody', '--regid=nogroup', '--clear-groups', (Get-Process -Id $PID).Path)
                    }
                }
            }
            if ((-not $unreadableDirectly) -and [string]::IsNullOrEmpty($launcherExe)) {
                Set-ItResult -Skipped -Because 'this host cannot make the fixture unreadable for the child process (root without setpriv)'
                return
            }

            $result = Invoke-CheckScriptViaLauncher -AgentLogPath $fixture -LauncherExe $launcherExe -LauncherArguments $launcherArguments

            # The read failure is reported distinctly, with the path and a
            # coarse failure category - never as the plain 'log file not
            # found' absence report for a missing log...
            $result.Output | Should -Match 'log exists but could not be read'
            $result.Output | Should -Match ([Regex]::Escape($fixture))
            $result.Output | Should -Match 'Failure category'
            $result.Output | Should -Not -Match 'Log file not found'
            # ...it counts as a problem found, listed in the summary (the
            # '^  - ' anchor matches a summary bullet, not the inline hint),
            # so a healthy-looking 'All checks passed' with exit 0 is
            # impossible when the log diagnostic was never performed...
            $result.Output | Should -Match '(?m)^  - .*log exists but could not be read'
            $result.Output | Should -Not -Match 'All checks passed'
            $result.ExitCode | Should -Be 1
            # ...and nothing from inside the file - nor error text quoting it -
            # ever reaches the output.
            $result.Output | Should -Not -Match ([Regex]::Escape($sentinel))
        } finally {
            Remove-Item -LiteralPath $fixture -Force -ErrorAction SilentlyContinue
        }
    }

    It 'reports an agent log that is missing as a problem, so the check cannot pass' {
        # No unreadability arrangement needed - just a path that does not
        # exist - so unlike the fixtures above this runs on Windows too.
        $missingLog = Join-Path ([System.IO.Path]::GetTempPath()) ('ssm-check-missing-log-' + [System.IO.Path]::GetRandomFileName() + '.log')

        $result = Invoke-CheckScriptViaLauncher -AgentLogPath $missingLog

        # The absence is reported inline with its path...
        $result.Output | Should -Match 'Log file not found'
        $result.Output | Should -Match ([Regex]::Escape($missingLog))
        # ...and, like the unreadable log, it counts as a problem found: a
        # summary bullet, no 'All checks passed', exit 1. The log diagnostic
        # was never performed, so a passing check must be impossible.
        $result.Output | Should -Match '(?m)^  - .*agent log was not found'
        $result.Output | Should -Not -Match 'All checks passed'
        $result.ExitCode | Should -Be 1
    }

    Describe 'class invariant: an unperformed diagnostic is always a recorded problem' {
        # CLASS-LEVEL INVARIANT, not an instance fix: NO diagnostic in
        # check.ps1 may be skipped silently. Whenever a diagnostic could not
        # be performed - its input missing, or present but unreadable - the
        # run must (1) exit 1, (2) never print 'All checks passed', (3) carry
        # a Summary bullet for THAT diagnostic, and (4) never print that
        # diagnostic's success line. Unperformed = problem, in every break
        # mode, for every diagnostic. Two review rounds in a row (unreadable
        # agent log, then missing agent log) each found a DIFFERENT instance
        # of this class that the previous instance-level fix did not
        # prevent, so this block breaks every independently-breakable
        # diagnostic input AT ONCE and asserts the class property itself.
        #
        # Diagnostic-input inventory (check.ps1 param block + sections):
        #   -RegistrationPath : param seam - broken below, both missing and
        #                       present-but-unreadable
        #   -AgentLogPath     : param seam - broken below, missing
        #   module path       : derived from check.ps1's $PSScriptRoot - NOT
        #                       breakable from outside; absence is itself an
        #                       Add-Problem in check.ps1
        #   agent exe path    : derived from $env:ProgramFiles - NOT
        #                       breakable from outside; absence is an
        #                       Add-Problem ('not installed') in check.ps1
        #   OS query          : Get-CimInstance Win32_OperatingSystem - NOT
        #                       breakable from outside; its catch records an
        #                       Add-Problem in check.ps1
        #   service query     : Get-Service / Win32_Service - NOT breakable
        #                       from outside; failure and absence are each an
        #                       Add-Problem in check.ps1
        # Only the two param seams can be driven from outside a child
        # process, so they carry the invariant here; each non-seam
        # diagnostic already routes every failure path through Add-Problem.
        BeforeAll {
            # Both helpers normalize CRLF away so their line anchors hold on
            # Windows hosts too (the missing-input It below runs on every OS).

            # The set of sections announced by Write-Section must be exactly
            # the SPEC 24 report items plus the script's own Summary footer -
            # no more, no fewer. SPEC.md #24 requires reporting Windows
            # edition/version and build; SSM Agent installation status and
            # version; AmazonSSMAgent service existence, startup
            # configuration and running state; whether local SSM
            # registration appears to exist and the managed-node ID where
            # locally discoverable; and relevant recent SSM Agent
            # warnings/errors. check.ps1 groups these into the five
            # diagnostic sections below and closes with its Summary. Exact
            # set equality (not mere presence) is deliberate: if a future
            # diagnostic section is added or renamed, this fails and forces
            # this invariant block to be revisited - because a NEW section
            # needs a problem-recording path for every way it can fail to
            # run, and this block is where that is asserted.
            function Assert-AnnouncedSectionSet {
                param([string]$Output)
                $expectedSections = @(
                    'Windows',
                    'SSM Agent installation',
                    'AmazonSSMAgent service',
                    'SSM registration',
                    'Recent SSM Agent warnings/errors',
                    'Summary'
                )
                $announcedSections = [Regex]::Matches(($Output -replace "`r", ''), '(?m)^=== (.+) ===$') |
                    ForEach-Object { $_.Groups[1].Value }
                $announcedSections | Should -Be $expectedSections
            }

            # The Summary must be a faithful list of exactly the recorded
            # problems: one '  - ' bullet and one inline '[PROBLEM]' line per
            # entry, matching the count in 'Problems found (N):'. A
            # diagnostic that could not be performed is only safe if its
            # problem actually reaches the Summary, and no bullet may exist
            # that does not correspond to a recorded problem.
            function Assert-SummaryListsEveryProblem {
                param([string]$Output)
                $normalized = $Output -replace "`r", ''
                $normalized | Should -Match 'Problems found \(\d+\):'
                $announcedCount = [int][Regex]::Match($normalized, 'Problems found \((\d+)\):').Groups[1].Value
                $inlineCount = ([Regex]::Matches($normalized, '(?m)^  \[PROBLEM\]')).Count
                $bulletCount = ([Regex]::Matches($normalized, '(?m)^  - ')).Count
                $inlineCount | Should -Be $announcedCount
                $bulletCount | Should -Be $announcedCount
            }
        }

        It 'records a problem for every unperformed diagnostic when both param-seam inputs are missing' {
            # Every independently-breakable input broken at once, in the
            # missing form, which needs no unreadability arrangement and so
            # runs on every OS - including a healthy enrolled Windows host,
            # where this is the invariant at its strongest: a machine whose
            # every performed diagnostic passes must still fail when one
            # could not be performed.
            $missingRegistration = Join-Path ([System.IO.Path]::GetTempPath()) ('ssm-check-invariant-missing-reg-' + [System.IO.Path]::GetRandomFileName())
            $missingLog = Join-Path ([System.IO.Path]::GetTempPath()) ('ssm-check-invariant-missing-log-' + [System.IO.Path]::GetRandomFileName() + '.log')

            $result = Invoke-CheckScriptViaLauncher -RegistrationPath $missingRegistration -AgentLogPath $missingLog

            # Never exit 0 over an unperformed diagnostic...
            $result.ExitCode | Should -Be 1
            $result.Output | Should -Not -Match 'All checks passed'
            # ...each unperformed diagnostic gets its own Summary bullet
            # (the '^  - ' anchor matches a Summary bullet, not the inline
            # hint)...
            $result.Output | Should -Match '(?m)^  - .*No local SSM registration'
            $result.Output | Should -Match '(?m)^  - .*agent log was not found'
            # ...and no diagnostic that never ran may print its success
            # line - a performed-and-clean claim over an unperformed
            # diagnostic is the silent skip this invariant forbids.
            $result.Output | Should -Not -Match '(?m)^  Managed node ID'
            $result.Output | Should -Not -Match 'No warning/error lines in the last 500 lines of'
            Assert-SummaryListsEveryProblem -Output $result.Output
            Assert-AnnouncedSectionSet -Output $result.Output
        }

        It 'records a problem for every unperformed diagnostic when the registration file is unreadable and the log is missing' -Skip:($script:IsWindowsOs) {
            # Same invariant with the OTHER break mode of the registration
            # seam: present but unreadable. Same unreadability arrangement as
            # the read-failure tests above (chmod 000, plus setpriv(1)
            # running the child as nobody when the test process itself is
            # root and would bypass the file mode), hence the same Windows
            # Skip guard.
            $fixture = Join-Path ([System.IO.Path]::GetTempPath()) ('ssm-check-invariant-unreadable-' + [System.IO.Path]::GetRandomFileName())
            try {
                Set-Content -LiteralPath $fixture -Value 'ssm-check-invariant-registration-sentinel'
                & chmod 000 $fixture

                $launcherExe = ''
                $launcherArguments = @()
                $unreadableDirectly = $false
                try {
                    $null = Get-Content -LiteralPath $fixture -Raw -ErrorAction Stop
                } catch {
                    $unreadableDirectly = $true
                }
                if (-not $unreadableDirectly) {
                    $setpriv = Get-Command -Name setpriv -ErrorAction SilentlyContinue
                    $cat = Get-Command -Name cat -ErrorAction SilentlyContinue
                    if (($null -ne $setpriv) -and ($null -ne $cat)) {
                        $probeInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
                        $probeInfo.FileName = $setpriv.Source
                        $probeInfo.Arguments = ('--reuid=nobody --regid=nogroup --clear-groups ' + $cat.Source + ' ' + $fixture)
                        $probeInfo.UseShellExecute = $false
                        $probeInfo.RedirectStandardOutput = $true
                        $probeInfo.RedirectStandardError = $true
                        $probeInfo.CreateNoWindow = $true
                        $probe = [System.Diagnostics.Process]::Start($probeInfo)
                        $null = $probe.StandardOutput.ReadToEnd()
                        $null = $probe.StandardError.ReadToEnd()
                        $probe.WaitForExit()
                        if ($probe.ExitCode -ne 0) {
                            $launcherExe = $setpriv.Source
                            $launcherArguments = @('--reuid=nobody', '--regid=nogroup', '--clear-groups', (Get-Process -Id $PID).Path)
                        }
                    }
                }
                if ((-not $unreadableDirectly) -and [string]::IsNullOrEmpty($launcherExe)) {
                    Set-ItResult -Skipped -Because 'this host cannot make the fixture unreadable for the child process (root without setpriv)'
                    return
                }

                $missingLog = Join-Path ([System.IO.Path]::GetTempPath()) ('ssm-check-invariant-missing-log-' + [System.IO.Path]::GetRandomFileName() + '.log')

                $result = Invoke-CheckScriptViaLauncher -RegistrationPath $fixture -AgentLogPath $missingLog -LauncherExe $launcherExe -LauncherArguments $launcherArguments

                $result.ExitCode | Should -Be 1
                $result.Output | Should -Not -Match 'All checks passed'
                $result.Output | Should -Match '(?m)^  - .*registration file exists but could not be read'
                $result.Output | Should -Match '(?m)^  - .*agent log was not found'
                $result.Output | Should -Not -Match '(?m)^  Managed node ID'
                $result.Output | Should -Not -Match 'No warning/error lines in the last 500 lines of'
                Assert-SummaryListsEveryProblem -Output $result.Output
                Assert-AnnouncedSectionSet -Output $result.Output
            } finally {
                Remove-Item -LiteralPath $fixture -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
