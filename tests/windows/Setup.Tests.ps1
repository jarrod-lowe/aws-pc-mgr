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
# Not drivable from a child process: the Reregister clear's launch-failure
# path (amazon-ssm-agent.exe quarantined or removed between the existence
# check and the invocation, while the service is being stopped). No path
# seam decides it, so the proof was a red/green demonstration against a
# scratch copy of setup.ps1 - elevation check stubbed, a global
# Get-CimInstance stub, registration/agent fixtures under temp ProgramData/
# ProgramFiles, the copy run as the -File entry script with a prior native
# call planting a stale exit code 0 (the same scratch-copy approach the
# revalidation block below documents). Pre-fix, every launch-failure mode
# let the raw invocation error kill the script (exit 1); in the contained
# mode a non-terminating Windows PowerShell 5.1 invocation error produces,
# the stale 0 is read as success and 'Local registration cleared.' prints
# over a clear that never ran. Post-fix, the $LASTEXITCODE sentinel plus a
# catch around the invocation make every launch-failure mode report the
# launch failure with a nothing-was-cleared message and exit 3, while a
# genuinely launched exit 0 still prints the success line and a launched
# nonzero exit code still takes the exit-code branch. The module's mirror
# of the same discipline (Invoke-SsmEnrollment) IS drivable and is covered
# by a committed unit test.
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
    #       1); repairs run through the shared Repair-SsmServiceForHealth
    #       (see the service-repair ordering entry below), then BOTH
    #       Running AND Automatic are re-queried and must hold or the run
    #       exits 1
    #   StartService registration re-read - the same fail-closed guard
    #   StartService service checks - the same shared repair sequence
    #       (Repair-SsmServiceForHealth); both facts are required for
    #       success, the start is conditional on the re-read status, and
    #       the summary lines state what actually ran (started /
    #       restored / already running again)
    #   Register pre-enrollment re-classification - the LAST statement
    #       before Invoke-SsmEnrollment: the service and registration are
    #       re-read (fail-closed wrapper; a failed registration re-read
    #       exits 3 like classification's own) and Get-SsmNodeState is
    #       re-run with them; any state other than Absent/
    #       InstalledUnregistered - the file present in ANY form,
    #       Ambiguous, or an unreadable re-read - aborts exit 3 with
    #       nothing changed and no activation consumed, because the
    #       prompts above gave another setup process time to complete a
    #       registration. This is the FREE refusal, before any download;
    #       the slow steps it cannot see through are the next entry.
    #       Not drivable from a child process (same lack of seams as
    #       above); proven red/green against a scratch copy whose
    #       stateful module readers flip to 'a foreign registration
    #       appeared' on their second call, the enrollment stubbed to a
    #       sentinel that the pre-fix run wrote (exit 0, 'Registration
    #       complete.' over the other process's identity) and the fixed
    #       run did not reach
    #   Register pre-LAUNCH revalidation (inside Invoke-SsmEnrollment) -
    #       the download and the signature verification run INSIDE the
    #       enrollment runner, after every script-side check, so the class
    #       rule (a state revalidation sits adjacent to the side effect it
    #       guards) puts the last check there: after verification and
    #       immediately before the native launch, the runner re-reads the
    #       local registration record and refuses to launch when the file
    #       is present in ANY form or cannot be re-read (fail closed),
    #       reporting the refusal as RegistrationAppeared on its result.
    #       The caller maps that outcome to the same shared race report
    #       the script-side guard uses (already-registered handling:
    #       report, exit 3, nothing changed, no activation consumed,
    #       executable never run), never the catch-all failure dump. The
    #       runner's abort branch IS drivable and is covered by committed
    #       unit tests (tests/unit/SSMHybrid.Tests.ps1: a registration
    #       planted after verification aborts before the launch, a failed
    #       re-read aborts the same way, and the temp download is cleaned
    #       up on both); the caller's mapping over that tested result is
    #       not child-process-drivable - the activation-code prompt blocks
    #       on closed stdin before the enrollment call - the same seamless
    #       shape as every entry above
    #   Register post-enrollment registration read + service checks -
    #       fail-closed (exit 1) on unparseable/absent registration and on
    #       not Running/Automatic after the repairs, both re-verified
    #   success-boundary revalidation (ALL THREE exit-0 branches) - the
    #       class rule applied to the report itself: a success report must
    #       state only facts read at the last possible moment, with no
    #       mutation between the read and the report (round 59
    #       strengthened this to EVERY claimed fact: the service guard
    #       runs first, this registration guard last - see the round-59
    #       entry below). NoOperation (clean
    #       and repair paths), StartService, and Register each hold a
    #       registration read taken BEFORE their slow, mutating repair
    #       steps (Set-Service/Start-Service), so each branch calls
    #       Get-SsmRegistrationForSuccessReport AFTER its final mutation
    #       and immediately before its summary; the branch prints its
    #       managed node ID and exits 0 only when the record re-reads as
    #       present, parseable (a failed read or parse is drift, not a
    #       pass), and STILL the same managed node ID the branch verified
    #       earlier. Gone, emptied, rewritten, unreadable, or replaced by
    #       another identity is reported as drift with exit 3 - the
    #       manual-intervention/race disposition, because every action
    #       this run attempted succeeded and the next step (accept the
    #       replacement identity, or enroll afresh with a NEW activation)
    #       is a human decision - and the cached ID is never printed; the
    #       report names what the run already changed ($ChangesSoFar)
    #       instead of claiming nothing changed. Not drivable from a child
    #       process: the same lack of path seams as every entry above, and
    #       the Register caller cannot even reach the boundary past the
    #       activation-code prompt on closed stdin. The committed pins are
    #       this disposition, the parse check over the edited script, and
    #       the idempotence tests above - a guard that false-positived on
    #       a healthy machine (two reads, ID mismatch by construction)
    #       would fail their exit-0/same-ID assertions on the validation
    #       machine. The drift-specific red/green demonstration (scratch
    #       copy whose module readers flip to a vanished registration on
    #       the boundary read; pre-fix, the stale ID prints with exit 0;
    #       post-fix, the drift report and exit 3 replace it) runs on the
    #       validation machine in phase V4, the same scratch-copy form the
    #       entries above document.
    #   Reregister pre-clear service reads - fail-closed wrapper plus a
    #       verified-stopped gate before anything destructive
    #   service-repair ordering (round 51 class sweep) - every multi-
    #       mutation repair sequence must be ordered so each step is
    #       executable given the state the previous steps produced. One
    #       shared helper, Repair-SsmServiceForHealth, now owns the
    #       ordering for ALL THREE healthy-verdict branches (NoOperation,
    #       StartService, Register): existence verified before
    #       configuration (a service vanished since classification fails
    #       closed with a crafted report, not a raw terminating error),
    #       startup type restored BEFORE the start (a Disabled service
    #       cannot be started at all - Start-Service fails on it, which
    #       is the bug this round fixed: the old NoOperation copy started
    #       first and aborted on a Stopped+Disabled service before
    #       Automatic was ever restored), re-query after every mutation,
    #       one bounded re-repair of a start type flipped back after the
    #       start, then the verdict requires both facts or exits 1. Sweep
    #       verdicts: NoOperation repairs - VIOLATION, fixed by the
    #       helper; StartService branch - was ordered correctly, now
    #       unified (its unconditional Start-Service became conditional,
    #       keeping the flags and summary truthful when another actor
    #       already started the service); Register post-enrollment
    #       repairs - was ordered correctly, now unified; Reregister
    #       pre-clear steps - PASS (agent-exe existence checked before
    #       the launch with the $LASTEXITCODE sentinel covering a vanish
    #       inside the window, service existence re-read before
    #       Stop-Service, verified-stopped gate before the clear);
    #       module-internal enrollment ordering (download, signature
    #       verify, pre-launch re-read, launch) - PASS, verify before
    #       execute, out of this file's scope
    #   pre-stop + pre-clear registration revalidation (Reregister) -
    #       destructive-sequence adjacency: in a destructive sequence
    #       every side-effectful mutation is damage-if-stale, not mere
    #       preparation for the next, so Assert-SsmRegistrationBeforeClear
    #       is called TWICE - immediately before the service STOP (a
    #       stale run must not take a replacement identity's agent
    #       offline and leave the newly enrolled node dark until
    #       repaired) and again immediately before
    #       amazon-ssm-agent -register -clear, both after the operator
    #       confirmation. The comparison basis is the FINEST AVAILABLE
    #       for each classified shape, so every classified state can
    #       detect replacement: parseable -> the managed node ID (same
    #       ID with different auxiliary fields proceeds - the identity
    #       is the confirmed unit; a different ID, gone, emptied,
    #       rewritten-unusable, or an unreadable re-read aborts);
    #       unusable (empty or unparseable, cleared sight-unseen by
    #       design) -> the RAW record content (byte-identical to the
    #       classification read proceeds - the exact bytes the
    #       confirmation covered; content that DIFFERS aborts, e.g. a
    #       competing enrollment part-way through writing its own
    #       record; a record that now PARSES aborts; the file gone
    #       aborts). Drift exits 3 (race/manual-intervention family;
    #       the operator re-confirms against the new state) naming what
    #       the run already did ($stopNote: stopped the service /
    #       already stopped / service missing). The clear is justified
    #       by a SECOND fact too - the service being stopped - so it is
    #       re-read AT the clear boundary, FIRST (round 58: boundary
    #       reads are ordered, the most damage-carrying validation
    #       closest to the act, so the identity guard - not a slower
    #       service query - is the final read before the native
    #       command; the R53 order ran the service query between the
    #       accepted identity and the clear, and inside that CIM query
    #       another setup could replace the registration): a service
    #       another actor restarted aborts the clear (a running agent
    #       can hold or rewrite its registration data mid-clear; the
    #       post-clear guard could only report that partial clear, not
    #       prevent it), deliberately without re-stopping - bounded,
    #       an actively-restarting actor is the operator's fight.
    #       Not child-process-drivable (no seams, and the confirmation
    #       prompt blocks on closed stdin before the branch acts); the
    #       committed pin is this disposition plus the parse check, and
    #       the scratch-copy red/green demonstrations (module readers
    #       flip to a replaced identity at the pre-stop read - pre-fix
    #       the stop still ran and left the replacement's agent dark;
    #       flip to different still-unparseable content - pre-fix the
    #       clear destroyed content the operator never confirmed; a
    #       service reader flips to Running at the boundary - pre-fix
    #       the clear ran against the restarted agent; post-fix each
    #       is exit 3 with the mutation withheld) run on the validation
    #       machine in phase V4
    #   Reregister adversarial closure matrix (round 53) - state class x
    #       mutation x window, 'can the script damage or misreport on
    #       stale state here?', every cell fixed or adjudicated:
    #       W1 classification -> pre-stop revalidation: any
    #       registration drift (replaced identity, replaced unusable
    #       content, became-parseable, vanished) is caught BEFORE any
    #       mutation - FIXED this round (was: stop ran first)
    #       W2 pre-stop revalidation -> Stop-Service: no statement
    #       between the guard and the mutation beyond the branch
    #       decision; check-then-act at irreducible scale, the stop is
    #       reversible, and the pre-clear guard re-runs - ADJUDICATED
    #       W3 stop -> clear: identity/raw drift caught by the pre-clear
    #       revalidation; a service restarted in the window caught by
    #       the stopped re-verification AT the clear boundary (boundary
    #       check fixed round 53; read ORDER corrected round 58 - the
    #       service query had sat between the accepted identity and the
    #       clear, and inside that CIM query another setup could
    #       replace the registration the already-run guard had
    #       accepted; the identity guard is now the final read before
    #       the native command);
    #       same-ID-different-fields proceeds - ADJUDICATED (the
    #       identity is the confirmed unit); between the identity read
    #       and the native command only the sentinel/EAP statements
    #       remain - RE-ADJUDICATED (round 58): the round-53 residue
    #       cell called 'statements between' irreducible, but the
    #       service query was a removable statement and reordering
    #       removed it; what remains is genuinely statement-only
    #       residue, R47-scale
    #       W4 clear -> post-clear read: a surviving or reappearing
    #       record caught by the post-clear guard (one branch for
    #       remained/reappeared - a captured exit 0 cannot distinguish
    #       them, and the disposition is identical) - ADJUDICATED
    #       (round 51)
    #       W5 post-clear read -> report: reads only between; the
    #       completion message's STOPPED claim is read at the boundary
    #       (stopped / restarted-by-another-actor / service-vanished
    #       each print their truthful variant) - FIXED this round
    #       misreport cells: every exit-3 report in the branch states
    #       only run-history facts ('the clear did NOT run', $stopNote)
    #       and machine facts read immediately above its own print; no
    #       code path prints a managed node ID that was not just
    #       re-read; the not-confirmed and exe-missing exits precede
    #       any mutation - ADJUDICATED
    #       outside Reregister: repairs (helper reads before each
    #       mutation, both-facts verdict after, registration guarded at
    #       the report boundary - rounds 49/51), enrollment launch
    #       (R47 pre-launch re-read, sentinel, verify-before-execute),
    #       temp cleanup (self-owned artifact), check.ps1 (read-only)
    #       - CLOSED, no further cells
    #   report-only query soft-fail (round 54 class sweep) - failure
    #       handling proportional to the query's role: fail-closed (exit)
    #       belongs to DECISION queries, where acting on unknown state is
    #       dangerous; a query is REPORT-only when nothing but console
    #       output follows it, and after a completed-and-verified
    #       irreversible act it must fail SOFT - degraded wording, full
    #       result still reported. Sweep of every query after such an
    #       act: Reregister FINAL service read (the completion message's
    #       status arm) - was routed through Get-ServiceInfoOrFail, whose
    #       exit-1 suppressed 'Local registration cleared.' and the
    #       fresh-activation guidance over a TRANSIENT query failure;
    #       VIOLATION, fixed: the read is taken locally in try/catch and
    #       a failed read prints its own arm (status unknown, explicitly
    #       not a claim of stopped or running, plus $stopNote for what
    #       the run actually did to the service) while the verified clear
    #       result and the re-enrollment guidance always print; the
    #       read-ok arms (stopped / restarted-by-another / vanished) are
    #       unchanged from round 53. Register post-enrollment
    #       registration read - ADJUDICATED: that read IS the act's
    #       verification (it runs before 'completed-and-verified'
    #       applies), and its failure exits 1 with
    #       partial-completion guidance. Register post-enrollment
    #       service queries (the exists check plus the repair helper's
    #       reads) - ADJUDICATED: decision queries, repairs and the
    #       health verdict still hang on them, fail-closed is
    #       proportionate, and the failure exit is truthful (nothing
    #       further was changed by THIS run, inspect, re-run - the
    #       persisted registration makes the re-run classify and act
    #       safely). Register success-boundary guard - ADJUDICATED: a
    #       verdict gate that REPLACES the success report with an
    #       accurate drift report (naming the consumed activation), not
    #       an abort of reporting. Post-clear registration guard -
    #       ADJUDICATED: the clear's verifier; its failure mode IS the
    #       drift report. NoOperation/StartService - no irreversible act
    #       precedes their queries. Net: exactly one report-only query
    #       ran after a point of no return; it is now soft. Not
    #       child-process-drivable (the confirmation prompt blocks closed
    #       stdin first); the pin is this disposition, same V4
    #       scratch-copy form (the service reader throws at the final
    #       read; pre-fix, exit 1 with the clear unreported; post-fix,
    #       the clear result, the unknown arm, and the guidance all
    #       print, exit 3 per the branch contract)
    #   mutation-failure handling (rounds 55+56 class sweep) - the
    #       mutation-side companion of the round-54 rule: queries fail
    #       soft or closed proportional to role; MUTATIONS never fail
    #       raw (round 55), and a mutation's catch never CLAIMS the
    #       machine untouched when the mutation may have partially
    #       applied (round 56) - the changed/nothing-changed basis of
    #       every failure report is a boundary re-read, not an
    #       assumption. Every mutation catch is checked for BOTH (a)
    #       routed, guided reporting and (b) a re-read (or determinate
    #       evidence) behind any changed/nothing-changed claim.
    #       VIOLATIONS (a): the shared repair helper's three mutation
    #       calls (Set-Service restore, Start-Service, the flipped-back
    #       re-restore) let a thrown command escape - all three
    #       healthy-verdict branches could end in raw PowerShell output
    #       over a machine the preceding Set-Service had already
    #       changed. FIXED: the sequence runs inside one try/catch with
    #       a $repairStep label before each command; the catch reports
    #       the failing step, the flag-backed completed-steps list
    #       (run-history facts only - each flag is set after its
    #       command returned), the machine-now state from a soft-fail
    #       re-read (a thrown Start-Service can leave the service
    #       StartPending, so the failed command's own effect is never
    #       claimed), the inspect pointer, and the branch's
    #       -FailureGuidance lines (the parameter's designed purpose),
    #       exit 1; the fail-closed reads inside the try are unaffected
    #       (exit is not caught). VIOLATION (b): the Reregister
    #       Stop-Service catch reported 'Nothing was changed' without
    #       re-reading - but Stop-Service can throw AFTER sending the
    #       stop request (a slow transition), leaving the node offline
    #       while the operator is told nothing changed. FIXED: the catch
    #       re-queries the service and reports four truthful arms
    #       (stopped-despite-the-error / still-Running-nothing-changed /
    #       transitional-may-still-complete / query-failed-unknown, the
    #       round-54 soft-fail wording family), always preserving that
    #       the registration was NOT cleared and the clear will not
    #       run, exit 3. Sweep verdicts for every other mutation catch
    #       in the script: native clear launch failure - PASS (the
    #       $LASTEXITCODE sentinel is determinate evidence that nothing
    #       launched, so 'Nothing was cleared' is evidenced, not
    #       assumed); native clear nonzero exit - PASS ('may be
    #       partially cleared' acknowledges the indeterminacy instead of
    #       claiming either way); Register enrollment catch - PASS
    #       ('may have partially completed' acknowledges indeterminacy,
    #       the deletion claim scoped to run-history registration data
    #       by this run, and the secret-bearing command line is never
    #       echoed); module temp-dir New-Item/Remove-Item - PASS
    #       (inside the runner's try / bounded-retry cleanup that warns
    #       and never throws outward); Remove-Variable - script-state
    #       secret hygiene, not machine state, out of the class by
    #       definition. Not child-process-drivable (driving a thrown
    #       Start-Service or a throw-after-send Stop-Service needs a
    #       service that misbehaves; no seam reaches either from closed
    #       stdin); the pin is the disposition, same V4 scratch-copy
    #       form (a service stub that accepts Set-Service then throws
    #       from Start-Service; a stop stub that throws after accepting
    #       the stop while the state reader flips to StopPending or
    #       Stopped; pre-fix, raw error output / an unverified
    #       nothing-changed claim; post-fix, the guided reports above
    #       with boundary re-reads)
    #   boundary-read ORDER (round 58 class sweep) - at every guarded
    #       act and every report, the boundary reads are ordered so the
    #       validation whose staleness causes the most damage is read
    #       CLOSEST to the act: service-state and other non-identity
    #       facts first, the registration identity LAST - the final
    #       read before the mutation (or the print), so no slower query
    #       can open a window between accepting an identity and acting
    #       on it. Pre-act read sequences, in execution order, verdict
    #       each:
    #       Reregister STOP - service facts (stop decision) then the
    #       registration guard, then only the branch decision before
    #       Stop-Service - identity last, PASS
    #       Reregister CLEAR - VIOLATION (the finding): the R53 order
    #       ran the registration guard, THEN the stopped re-verification
    #       query, THEN the clear, and inside that CIM query another
    #       setup could replace the registration the already-run guard
    #       had accepted - FIXED: stopped re-verification first, the
    #       guard the final read, only sentinel/EAP statements between
    #       it and the native command
    #       Reregister COMPLETION REPORT - VIOLATION by the same
    #       standard: the post-clear registration guard ran, THEN the
    #       service wording read, THEN the print - FIXED: service read
    #       first (its soft-fail arms unchanged), the postcondition
    #       guard LAST, closest to the print whose primary claim it is
    #       Enrollment launch (module, R47) - signature verification,
    #       then the registration re-read, then only sentinel/EAP
    #       statements before the native launch - identity last, PASS
    #       Repair mutations (shared helper) - no identity read
    #       participates: repairs are service-state acts justified by
    #       immediately-adjacent service reads, and identity protection
    #       lives at the report boundary (the success-boundary guard) -
    #       ADJUDICATED, no identity read to order
    #       NoOperation report - service boundary guard (fresh Running/
    #       Automatic read, round 59), then the registration guard, then
    #       prints - identity last, PASS
    #       StartService report - same shape - identity last, PASS
    #       Register report - same shape - identity last, PASS
    #       check.ps1 - strictly read-only, no acts - out of the class
    #       by definition
    #       Net: two boundaries carried a post-identity query (the
    #       clear boundary this finding names, and - by the sweep's own
    #       standard - the completion report); both now read the
    #       identity last. The round-53 'irreducible residue'
    #       adjudication is revised honestly above: the service query
    #       was a removable statement, and reordering removed it
    #   service facts at the success boundary (round 59) - the mirror
    #       of the round-58 finding, and the strengthened invariant: a
    #       success report must re-read EVERY fact it claims, at the
    #       boundary - R49 bound the registration, this binds the
    #       service-health facts. The three healthy-verdict branches
    #       printed a service line built from the repair helper's LAST
    #       re-query, a read that predates the final registration
    #       read, so drift inside that window (service stopping, GPO
    #       flipping the start type) printed as health from a stale
    #       snapshot with exit 0. FIXED: Get-SsmServiceForSuccessReport
    #       re-queries at the boundary, FIRST (round-58 order: cheap
    #       non-identity facts first, identity last, closest to the
    #       print), and withholds success unless BOTH current facts
    #       satisfy Running/Automatic; the returned fresh facts are
    #       what the report prints. Dispositions: drift (missing, not
    #       Running, or not Automatic NOW) exits 3 in the drift-report
    #       family with SERVICE-specific wording (the consistency
    #       check: the operator is told WHICH fact drifted - the
    #       service report states the registration was NOT re-verified
    #       on that path, and the registration guard's report stays
    #       registration-specific, so neither mislabels the other); a
    #       failed QUERY is a verdict query failing closed - exit 1,
    #       the service-family code, with a truthful report of what
    #       the run already did. Strengthened-invariant sweep:
    #       NoOperation clean - service guard runs there too (both
    #       boundary reads run unconditionally), FIXED; NoOperation
    #       repair - FIXED; StartService - FIXED; Register - FIXED;
    #       Reregister completion - ADJUDICATED, not exempt by
    #       omission: its report claims DIFFERENT facts (the clear's
    #       postcondition, and a service-status wording arm, not a
    #       Running/Automatic health verdict - the branch's success
    #       deliberately means stopped-and-unregistered), every claim
    #       it makes is already boundary-read (service wording
    #       soft-fail round 54, registration postcondition last round
    #       58), so the strengthened rule holds without importing a
    #       Running/Automatic requirement that branch never claims;
    #       check.ps1 - read-only, claims are printed adjacent to
    #       their own reads, out of class. Honest residue, per the
    #       round-58 lesson: the identity read following the service
    #       guard takes time and service drift inside it is a
    #       statement-scale window - recorded here, not claimed away
    #       (the matrix does not say zero window). Not child-process-
    #       drivable (the drift needs a service change inside one
    #       run's boundary window; no seam drives it from closed
    #       stdin); the pin is the disposition plus the parse check,
    #       and the V4 scratch-copy form (a service reader that
    #       flips to Stopped at the boundary read; pre-fix, the
    #       healthy line prints the helper's snapshot with exit 0;
    #       post-fix, the service-drift report and exit 3 replace it)
    #       documents the red/green demonstration for the validation
    #       machine
    #   post-clear absence revalidation (Reregister) - the postcondition-
    #       adjacency member of the class invariant, and the clear's
    #       POST-condition joining the PRE-condition above:
    #       Assert-SsmRegistrationCleared re-reads the raw record
    #       immediately after the native clear and the completion message
    #       'Local registration cleared.' prints only when it re-reads as
    #       GONE ($null - the file absent). Still present in ANY form
    #       (parseable, empty - an empty leftover classifies Ambiguous,
    #       not registration-less - or unreadable) or a failed re-read is
    #       drift, exit 3 (race/manual-intervention family; the service
    #       stays stopped, the operator decides against the actual
    #       state), never an automatic retry. REMAINED vs REAPPEARED is
    #       ONE branch by design: after a captured exit code 0 the script
    #       cannot distinguish a clear that lied from a concurrent
    #       enrollment that wrote afterwards, and the disposition is
    #       identical, so the code does not pretend to the distinction.
    #       Same drivability shape as the pre-stop/pre-clear entry above
    #       (the confirmation prompt blocks closed stdin first); same V4
    #       scratch-copy proof form (readers flip to present-at-the-post-
    #       read; pre-fix, 'Local registration cleared.' prints over the
    #       surviving record; post-fix, the drift report and exit 3
    #       replace it). The completion message that follows is itself
    #       report-adjacent (round 53): its STOPPED claim is read at the
    #       boundary, so a service another actor restarted (or removed)
    #       prints its truthful variant instead of the stopped claim
    #       from the stop sequence's earlier state - and (round 54) a
    #       FAILED read prints an explicit unknown arm, which is not a
    #       claim, instead of aborting the report; the reads follow the
    #       round-58 order even here (service wording first, the
    #       registration postcondition verified LAST, closest to the
    #       print).
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
