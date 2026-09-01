<#
.SYNOPSIS
    Enrolls this Windows 11 machine as an AWS Systems Manager (SSM) hybrid
    managed node (SPEC 20-23).

.DESCRIPTION
    Elevated entry script. All decision logic lives in SSMHybrid.psm1; this
    script gathers local facts, asks the module what to do, then does it.

    Flow: elevation check -> validate any supplied parameters (fast exit 2
    on invalid supplied values) -> classify local state -> execute the
    mapped action.

    Actions and exit codes:
        NoOperation          already registered and healthy         exit 0
        StartService         registration present, service stopped exit 0
        Register             install + register this machine       exit 0
        ManualIntervention   ambiguous/unhealthy; nothing changed  exit 3
        Reregister           -ForceReregister + confirmation:
                             stop agent, clear registration,
                             leave agent stopped                  exit 3

    Any other refusal or failure exits 1; invalid inputs exit 2.

    Interactive prompts happen only when enrollment is actually required:
    region and activation ID supplied as parameters are validated up front,
    but when omitted they are asked for ONLY inside the Register branch.
    NoOperation, StartService, ManualIntervention, and Reregister never need
    an activation, so a parameterless re-run on an already-enrolled machine
    asks for nothing at all and simply reports health (SPEC 20/22/36).

    Inside the Register branch the registration absence is revalidated at
    TWO points, because the slow steps sit in different windows (SPEC
    22/23): once in this script immediately before the enrollment runner
    is invoked - after the interactive prompts, before any download - and
    once INSIDE the runner, because the setup-CLI download and signature
    verification run there: Invoke-SsmEnrollment re-reads the registration
    record immediately before launching ssm-setup-cli and refuses to
    launch when a registration appeared in that window. Either refusal
    aborts with exit 3 - nothing changed, no activation consumed -
    instead of silently replacing the new identity. The script-side guard
    is defense in depth where refusal is still free; the module-side one
    is the last point that can still refuse.

    Success, too, is revalidated: every branch that reports it (NoOperation,
    StartService, Register) re-reads the registration AFTER its last
    mutation - the service repairs - and immediately before printing the
    managed node ID, and reports success only when the record is still
    present, still parseable, and still the same registration the branch
    verified earlier. A registration cleared or replaced while the repairs
    ran is reported as drift and exits 3 - the same human-decides
    disposition as the other registration ambiguities - never a cached
    managed node ID printed with exit 0 (SPEC 22/23).

    Service repairs are shared and dependency-ordered: every branch that
    repairs AmazonSSMAgent toward the healthy verdict (NoOperation,
    StartService, Register) runs ONE sequence - restore the Automatic
    startup type FIRST, then start the service (a Disabled service cannot
    be started at all), re-verify after every step, and fail closed when
    the Running/Automatic invariant still does not hold - so the branches
    cannot drift apart in ordering again.

    The destructive sequence is guarded the same way the launch and the
    success report are: Reregister revalidates the registration
    immediately before EVERY side-effectful step - once before the
    service stop (a stale run must not take a replacement identity's
    agent offline) and again immediately before
    amazon-ssm-agent -register -clear - comparing the classification-time
    record on the finest basis each state class offers: the parsed
    identity where the record parsed, the RAW content where it did not,
    so every classified state can detect replacement. The service must
    also still be stopped at the clear boundary (a restarted agent is
    exactly what the stop-before-clear sequence exists to prevent), and
    the clear's own postcondition is verified immediately after the
    native command: 'Local registration cleared.' prints only when the
    record re-reads as gone, because a captured exit code 0 is the
    agent's claim, not proof the file left the disk. The completion
    message's STOPPED claim is likewise read at the boundary, never
    asserted from the stop sequence's earlier state, and a FAILED final
    query degrades that wording to 'unknown' instead of suppressing the
    verified clear result and the re-enrollment guidance: past the point
    of no return, reporting must complete - fail-closed exits belong to
    decision queries, fail-soft wording to report-only ones (SPEC 22/23).

    The activation code is never a parameter and never appears on a command
    line (SPEC 20): it is read with a masked prompt via Read-SsmSecret, and
    only when a registration is actually about to run. It is never printed
    or logged, and the registration command line is executed by the module
    without echoing it (SPEC 43).

    The script never deregisters, deletes registration data, or consumes
    another activation on its own (SPEC 22), never runs 'aws configure',
    never performs an SSO login, and never writes under the user's .aws
    directory (SPEC 25).

.PARAMETER Region
    AWS region of the hybrid activation, for example ap-southeast-2.
    Validated immediately when supplied. Prompted for only when the Register
    action is about to run and no valid region is known yet.

.PARAMETER ActivationId
    SSM hybrid activation ID (UUID), from
    'terraform output -raw activation_id'. Validated immediately when
    supplied. Prompted for only when the Register action is about to run and
    no valid activation ID is known yet. A value typed on the command line is
    recorded in PSReadLine history in plain text, so the parameterless
    interactive run is preferred (SPEC 20).

.PARAMETER ForceReregister
    Destructive: after an explicit interactive confirmation, stops the
    AmazonSSMAgent service, clears the existing local registration, and
    leaves the service STOPPED, then exits 3. Re-enrollment is a fresh run
    of this script with a new activation; that Register run starts the
    service again.

.EXAMPLE
    .\setup.ps1

    Preferred: fully interactive. Region and activation ID are prompted for,
    the activation code is prompted for masked, and nothing entered at a
    prompt reaches the command line or PSReadLine history (SPEC 20).

.EXAMPLE
    .\setup.ps1 -Region ap-southeast-2

    Scripted use. -ActivationId exists for scripting too, but a value typed
    on the command line is recorded in PSReadLine history; prefer the prompts.
#>
param(
    [string]$Region,
    [string]$ActivationId,
    [switch]$ForceReregister
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# --- helpers ----------------------------------------------------------------

function Write-Step {
    param([string]$Message)
    Write-Host "[setup] $Message"
}

function Write-Fail {
    param([string]$Message)
    Write-Host "[setup] ERROR: $Message" -ForegroundColor Red
}

# Resolve one required input: keep the parameter when it is already valid,
# otherwise prompt (up to three attempts). Returns $null when no valid value
# was obtained, so the caller can exit with code 2.
function Resolve-SsmInput {
    param(
        [string]$Value,
        [string]$Label,
        [string]$Example,
        [scriptblock]$IsValid
    )

    if (& $IsValid $Value) {
        return $Value
    }

    if (-not [string]::IsNullOrEmpty($Value)) {
        Write-Host "The supplied $Label is not valid."
    }
    Write-Host "Enter the $Label (for example $Example)."

    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $candidate = Read-Host -Prompt $Label
        if (& $IsValid $candidate) {
            return $candidate
        }
        $remaining = 4 - $attempt
        Write-Host "Invalid $Label. Attempt(s) remaining: $remaining."
    }
    return $null
}

# Read the activation code with a masked prompt. It is only requested when
# the Register action is about to run, never for already-registered states,
# so an idempotent re-run never asks for bootstrap secrets (SPEC 20/36).
function Read-ActivationCode {
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $code = Read-SsmSecret -Prompt 'SSM activation code (input is masked)'
        if (-not [string]::IsNullOrEmpty($code)) {
            return $code
        }
        Write-Host 'The activation code must not be empty.'
    }
    return $null
}

# Parsed local registration, or $null when no registration file exists.
# Throws when the file exists but cannot be parsed.
function Get-SsmRegistration {
    $json = Get-SsmRegistrationFileJson
    if ([string]::IsNullOrEmpty($json)) {
        return $null
    }
    return ConvertFrom-SsmRegistrationJson -Json $json
}

# Registration RE-read for an action that already relies on one, or the
# ambiguous exit. Classification read and parsed this file moments ago, so
# when Get-SsmRegistration now returns $null (file deleted or emptied under
# us) or throws (file rewritten into something unreadable or unparseable,
# or its read now fails), the script's decision no longer matches the
# machine: another actor changed it between the classification and this
# read. That is exactly the ambiguity an unparseable registration earns at
# classification, so the same verdict is given here (exit 3, nothing
# modified, a human decides - SPEC 23) instead of acting on stale facts.
# Returns the parsed registration, or never returns.
function Get-SsmRegistrationOrAmbiguousExit {
    $registration = $null
    try {
        $registration = Get-SsmRegistration
    } catch {
        # Thrown means the file exists NOW but cannot be read or parsed NOW.
        $registration = $null
    }

    if ($null -ne $registration) {
        return $registration
    }

    Write-Fail 'The local registration vanished or changed since the state was classified above.'
    Write-Host 'It was readable and parseable moments ago, and now it is gone, empty, unreadable,'
    Write-Host 'or unparseable. Nothing was modified and nothing was deleted. The machine is in'
    Write-Host 'the same ambiguous state an unparseable registration earns at classification'
    Write-Host '(SPEC 23): no automatic action is taken from here.'
    Write-Host ('Inspect: the registration file under ' + $env:ProgramData + '\Amazon\SSM\InstanceData;')
    Write-Host 'Get-Service AmazonSSMAgent; the SSM Agent log. Repair the cause manually, or'
    Write-Host 're-run with -ForceReregister to discard the local registration and enroll'
    Write-Host 'afresh (destructive; consumes a new activation).'
    exit 3
}

# Service facts, or fail closed. Get-SsmServiceInfo never throws for a
# MISSING service (it reports Exists = $false) but DOES throw for a FAILED
# query, because a failed query must never be readable as the service being
# absent - notably in the Reregister path, where that would let the clear
# proceed against an agent that may still be running. Every call site after
# the initial classification (which has its own try/catch) goes through this
# wrapper, so a mid-script query failure stops the script with exit 1.
function Get-ServiceInfoOrFail {
    try {
        return Get-SsmServiceInfo
    } catch {
        Write-Fail ("Could not query the AmazonSSMAgent service: " + $_.Exception.Message)
        Write-Host 'A failed service query must not be read as the service being absent.'
        Write-Host 'Nothing further was changed. Inspect the error and re-run.'
        exit 1
    }
}

# Shared service repair for every healthy-verdict branch (SPEC 22/23):
# drives AmazonSSMAgent to Running AND Automatic through ONE sequence, so
# the branches cannot drift apart in ordering again. They had: the
# NoOperation copy started the service BEFORE restoring the startup type,
# and a Disabled service cannot be started at all (Start-Service fails on
# it), so a service Group Policy had flipped to Stopped+Disabled aborted
# the branch with a raw terminating error before Automatic was ever
# restored - despite the branch existing to repair exactly that drift.
#
# ORDERING RULE (the class rule for repairs): a repair sequence must be
# ordered so every step is executable given the state the previous steps
# produced. The dependencies here:
#   - EXISTENCE before configuration: Set-Service/Start-Service
#     presuppose the service; one that vanished since classification
#     fails closed below instead of surfacing as a raw terminating error.
#   - STARTUP TYPE before START: a Disabled service cannot be started,
#     so the type is restored first and the start that follows is
#     executable whatever the pre-repair start type was.
#   - RE-VERIFY after every mutation: each step re-queries through the
#     fail-closed wrapper, and the start type is repaired once more after
#     the start (Group Policy can flip it back between the Set-Service
#     and the re-query; bounded at one re-repair) before the final
#     verdict requires BOTH facts - or the run fails closed.
# Returns a PSCustomObject with Service (the final facts, for the report
# to print), Started and StartupRestored (what this run changed, for the
# truthful summary and drift clauses), or never returns: a failed query
# exits 1 inside Get-ServiceInfoOrFail, and every other failure exits 1
# here after the calling branch's own guidance lines.
function Repair-SsmServiceForHealth {
    param([string[]]$FailureGuidance)

    $started = $false
    $startupRestored = $false

    $currentService = Get-ServiceInfoOrFail
    if (-not $currentService.Exists) {
        Write-Fail 'The AmazonSSMAgent service no longer exists at the repair read.'
        Write-Host 'It existed when this run last verified it, so the repair plan is void. Inspect'
        Write-Host 'the agent installation and the SSM Agent log, then re-run.'
        foreach ($line in $FailureGuidance) {
            Write-Host $line
        }
        exit 1
    }

    if ($currentService.StartType -ne 'Automatic') {
        Write-Step ("Restoring AmazonSSMAgent startup type to Automatic (was '" + $currentService.StartType + "').")
        Set-Service -Name 'AmazonSSMAgent' -StartupType Automatic
        $startupRestored = $true
        $currentService = Get-ServiceInfoOrFail
    }
    if ($currentService.Status -ne 'Running') {
        Write-Step 'AmazonSSMAgent is not running; starting it.'
        Start-Service -Name 'AmazonSSMAgent'
        $started = $true
        $currentService = Get-ServiceInfoOrFail
    }
    if ($currentService.StartType -ne 'Automatic') {
        Write-Step ("Restoring AmazonSSMAgent startup type to Automatic again (was '" + $currentService.StartType + "'); it flipped back during the repairs.")
        Set-Service -Name 'AmazonSSMAgent' -StartupType Automatic
        $startupRestored = $true
        $currentService = Get-ServiceInfoOrFail
    }
    if (($currentService.Status -ne 'Running') -or ($currentService.StartType -ne 'Automatic')) {
        Write-Fail ("AmazonSSMAgent is not Running/Automatic after the repairs (status '" + $currentService.Status + "', startup '" + $currentService.StartType + "').")
        foreach ($line in $FailureGuidance) {
            Write-Host $line
        }
        exit 1
    }

    return [PSCustomObject]@{
        Service         = $currentService
        Started         = $started
        StartupRestored = $startupRestored
    }
}

# Race report shared by BOTH last-moment registration guards (SPEC 22/23):
# the script-side pre-enrollment revalidation (Assert-SsmRegistrationStillAbsent
# below) and the enrollment runner's own post-verification refusal
# (Invoke-SsmEnrollment's RegistrationAppeared outcome, handled in the
# Register branch) end in the same verdict - a competing process completed a
# registration inside this run's check-then-act window - so they share ONE
# report and can never drift apart in what they tell the operator. The abort
# is the already-registered handling, not a failure: report and re-run
# guidance, exit 3; nothing was changed, nothing was deleted, and no
# activation was consumed. Never returns.
function Write-SsmRegistrationRaceAndExit {
    param([string]$StalePlan)

    Write-Fail 'Another process completed a registration while this run was waiting.'
    Write-Host $StalePlan
    Write-Host 'A registration file is present NOW, so that plan is stale: enrolling would silently'
    Write-Host 'replace the newly created identity and consume another activation (SPEC 22/23).'
    Write-Host 'Nothing was changed, nothing was deleted, and no activation was consumed. Inspect the'
    Write-Host ('registration that appeared (the file under ' + $env:ProgramData + '\Amazon\SSM\InstanceData) and')
    Write-Host 'Get-Service AmazonSSMAgent, then re-run this script: it will classify the now-registered'
    Write-Host 'machine and take the appropriate action.'
    exit 3
}

# Registration-ABSENCE re-validation for the Register action: the mirror
# image of Get-SsmRegistrationOrAmbiguousExit above. That guard serves the
# actions that RELY on a registration; this one serves the action that
# relies on there being NONE. The Register branch spends unbounded
# wall-clock time between the classification reads and the enrollment
# invocation (three interactive prompts, then the setup-CLI URL build), and
# another setup process can complete a whole registration inside that
# window; the locally selected Register action is then stale, and running
# ssm-setup-cli anyway would silently replace the newly created identity
# and consume another activation (SPEC 22/23). So the machine is re-read
# and re-CLASSIFIED here through the same inputs classification itself
# used, and the full Get-SsmNodeState verdict - not a bare file-existence
# probe - decides: a registration file present in ANY form (parseable,
# unparseable, or unreadable) classifies as something other than the two
# registration-less states, and the Register plan is stale. The service
# facts are re-read only because classification consumed them too; a
# service appearing WITHOUT a registration does not abort here (Absent and
# InstalledUnregistered both map to Register - that drift was the
# classified state's own business, and the re-classification mirrors the
# original inputs faithfully). Returns normally only when the machine
# still classifies registration-less, or never returns. This guard is the
# FREE refusal - it runs before any download, command execution, or
# activation consumption - and covers the window the interactive prompts
# opened; the slow steps that follow (the setup-CLI download and its
# signature verification) run INSIDE Invoke-SsmEnrollment, past what any
# script-side check can see, so the runner revalidates the registration
# absence itself immediately before the native launch and reports a
# refusal as a distinct outcome the Register branch maps to the same
# shared race report.
function Assert-SsmRegistrationStillAbsent {
    param([string]$ClassifiedState)

    # Service first, through the same fail-closed wrapper every
    # post-classification service query uses: the re-classification below
    # needs the fact, and a query that fails must exit 1, never be read as
    # any particular service shape.
    $currentService = Get-ServiceInfoOrFail

    # Registration re-read, mirroring the classification read's own failure
    # verdict: a read that fails NOW can no longer prove the absence the
    # Register plan depends on (the file may have appeared and be locked
    # mid-write by the competing enrollment), so it earns classification's
    # exit 3, not a pass.
    $currentRegistrationJson = $null
    try {
        $currentRegistrationJson = Get-SsmRegistrationFileJson
    } catch {
        Write-Fail ("Could not re-read the local SSM registration file before enrolling. Nothing was changed and no activation was consumed. Inspect the error: " + $_.Exception.Message)
        Write-Host 'Registration may be partially complete or appearing right now. Resolve the read'
        Write-Host 'problem manually, then re-run this script: it classifies the machine afresh.'
        exit 3
    }

    $currentState = Get-SsmNodeState -RegistrationJson $currentRegistrationJson -ServiceExists $currentService.Exists -ServiceStatus $currentService.Status -ServiceStartType $currentService.StartType
    if (($currentState -eq 'Absent') -or ($currentState -eq 'InstalledUnregistered')) {
        return
    }

    Write-SsmRegistrationRaceAndExit -StalePlan ("This run classified the machine as '" + $ClassifiedState +
        "' (no registration file) and planned Register from that fact.")
}

# Registration revalidation at the SUCCESS BOUNDARY (SPEC 22/23): the last
# read before any branch prints a healthy verdict or exits 0. The branches
# that report success all verify the registration EARLY and then run slow,
# mutating repair steps before their summary: NoOperation and StartService
# hold a registration read from before Set-Service/Start-Service can run,
# and Register holds one from before the post-enrollment startup repair.
# Another actor can clear or replace the registration inside that window,
# and a report built from the early read would print a managed node ID the
# machine no longer holds - a healthy verdict over stale facts. The class
# rule is that a validation sits adjacent to what it certifies, so this
# guard runs AFTER the calling branch's last mutation, with nothing but
# reads and console output between it and the summary, and the branch may
# print its ID and exit 0 only when the record is STILL present, STILL
# parseable (a read or parse that fails here is drift, not a pass - the
# fail-closed, present-but-unparseable-is-ambiguous discipline of
# Get-SsmRegistrationOrAmbiguousExit above), and STILL the same registration:
# the same managed node ID the branch verified earlier.
#
# Disposition - exit 3, the manual-intervention/race family, not exit 1:
# exit 1 is for an action this run attempted failing its own postcondition
# (a service that will not start, an enrollment that produced no
# registration file). Here every action this run attempted succeeded; what
# broke is the machine's coherence with the plan this run was executing,
# and the way forward - accept a replacement identity, or re-enroll with a
# NEW activation - is a decision this script never makes on its own (SPEC
# 22), the same human-decides verdict as the other registration
# ambiguities. Unlike those guards, the calling branch may already have
# changed the SERVICE by the time this runs (that is the window being
# closed), so $ChangesSoFar names what this run already did and the report
# below states it plainly rather than claiming nothing changed.
# Returns the last-moment registration for the branch to print, or never
# returns.
function Get-SsmRegistrationForSuccessReport {
    param(
        [object]$Registration,
        [string]$ChangesSoFar
    )

    $lastMomentRegistration = $null
    try {
        $lastMomentRegistration = Get-SsmRegistration
    } catch {
        # Read or parse failed NOW, after the repairs: the record this
        # branch verified may have been replaced mid-write or locked; the
        # failure is drift, not a pass (fail closed).
        $lastMomentRegistration = $null
    }

    if (($null -ne $lastMomentRegistration) -and
        ($lastMomentRegistration.ManagedInstanceId -eq $Registration.ManagedInstanceId)) {
        return $lastMomentRegistration
    }

    Write-Fail 'The local registration changed or vanished while this run was finishing.'
    Write-Host ('What this run already did before this read: ' + $ChangesSoFar + '.')
    Write-Host 'What the machine holds NOW is not the registration this run verified: the record'
    Write-Host 'is gone, empty, unreadable, unparseable, or carries a different managed node ID,'
    Write-Host 'so the managed node ID this run was about to print no longer describes this'
    Write-Host 'machine, and the healthy verdict is withheld with it (SPEC 22/23). This run never'
    Write-Host 'deletes or rewrites the registration record, so the change came from another actor.'
    Write-Host ('Inspect: the registration file under ' + $env:ProgramData + '\Amazon\SSM\InstanceData;')
    Write-Host 'Get-Service AmazonSSMAgent; the SSM Agent log. Then re-run this script: it'
    Write-Host 'classifies the machine afresh and takes the appropriate action (a fresh enrollment'
    Write-Host 'needs a NEW activation; -ForceReregister discards the local registration first -'
    Write-Host 'destructive).'
    exit 3
}

# Registration revalidation before the DESTRUCTIVE STEPS of the Reregister
# action (SPEC 22/23) - called TWICE, immediately before each side-effectful
# mutation, because in a destructive sequence every mutation is damage-if-
# stale, not mere preparation for the one after it: once before the service
# STOP (a stale run must not take a replacement identity's agent offline
# and leave the newly enrolled node dark until repaired) and once
# immediately before amazon-ssm-agent -register -clear. The registration
# that CLASSIFIED this branch was read at the top of the run, and the
# Reregister flow spends unbounded wall-clock after that - an interactive
# confirmation a human can sit on, then the stop - long enough for another
# setup process to replace the registration entirely. Acting blind at
# either point destroys - or takes offline - an identity the operator
# never inspected and never confirmed; the confirmation covered the record
# AS IT STOOD when the machine was classified, and only that record may be
# acted on. The guard is pure (reads and comparisons only), so calling it
# twice is idempotent.
#
# Proceed/abort matrix (the classification shape decides what 'still the
# confirmed record' means; 'unusable' = empty or unparseable). The
# comparison basis is the FINEST AVAILABLE for each state class - the
# parsed identity where the record parsed, the RAW content where it did
# not - so every classified state can detect replacement:
#   classified PARSEABLE (an identity the operator saw named):
#     - re-reads as the SAME managed node ID                -> proceed
#       (same ID with different auxiliary fields is the same
#        confirmed identity; the identity is the confirmed unit)
#     - parses to a DIFFERENT ID                            -> abort
#     - gone, emptied, unreadable, or unparseable NOW       -> abort
#   classified UNUSABLE (empty or unparseable, cleared sight-unseen by
#   design - no parsed identity to compare, so the raw record itself is):
#     - raw content IDENTICAL to the classification read     -> proceed
#       (the exact bytes the confirmation covered, in whatever
#        unusable shape they were confirmed in)
#     - raw content DIFFERS                                 -> abort
#       (rewritten inside the window - for example a competing
#        enrollment part-way through writing its own record - and
#        the confirmation never covered the new content)
#     - parses to a real registration NOW                   -> abort
#       (an identity appeared that the confirmation never covered)
#     - the file is gone NOW                                -> abort
#       (nothing left to act on; the machine changed anyway)
# A re-read that itself fails aborts for every entry (fail closed).
#
# Disposition - exit 3, the manual-intervention/race family: the operator
# must decide again against the new state, exactly like every other
# registration ambiguity this script refuses to resolve alone. By the
# second call site the run may already have STOPPED the service, so
# $ChangesSoFar names what the run already did and the report says what
# did not run rather than claiming nothing changed.
# Returns normally only when the record is still the confirmed one, or
# never returns.
function Assert-SsmRegistrationBeforeClear {
    param(
        [string]$ClassifiedRegistrationJson,
        [string]$ChangesSoFar
    )

    # What classification saw: the parsed identity when the record parsed
    # then; $null when it was already the unusable shape. The script-level
    # classification read is passed in verbatim, so this derives from the
    # same text the classification verdict derived from.
    $classifiedRegistration = $null
    if (-not [string]::IsNullOrEmpty($ClassifiedRegistrationJson)) {
        try {
            $classifiedRegistration = ConvertFrom-SsmRegistrationJson -Json $ClassifiedRegistrationJson
        } catch {
            $classifiedRegistration = $null
        }
    }

    # Last-moment re-read, immediately before the clear: $null means the
    # file is gone, '' means it exists but is empty, text means content.
    $drift = $null
    $currentJson = $null
    try {
        $currentJson = Get-SsmRegistrationFileJson
    } catch {
        $drift = 'The registration file is present but could not be re-read NOW (locked, or its permissions changed mid-run).'
    }

    if ($null -eq $drift) {
        $currentRegistration = $null
        if (-not [string]::IsNullOrEmpty($currentJson)) {
            try {
                $currentRegistration = ConvertFrom-SsmRegistrationJson -Json $currentJson
            } catch {
                $currentRegistration = $null
            }
        }

        if ($null -ne $classifiedRegistration) {
            if ($null -ne $currentRegistration) {
                if ($currentRegistration.ManagedInstanceId -ne $classifiedRegistration.ManagedInstanceId) {
                    $drift = 'The record parses to a DIFFERENT managed node ID than the one the confirmation covered: another enrollment replaced the identity inside the window.'
                }
            } elseif ([string]::IsNullOrEmpty($currentJson)) {
                $drift = 'The registration file is gone or empty NOW; the record this run was confirmed to clear no longer exists.'
            } else {
                $drift = 'The record parsed when this run classified it, but cannot be parsed NOW; it was rewritten inside the window.'
            }
        } else {
            if ($null -ne $currentRegistration) {
                $drift = 'The record was unusable (empty or unparseable) when this run classified it, but parses to a real registration NOW: another enrollment completed inside the window, and the confirmation never covered that identity.'
            } elseif ($null -eq $currentJson) {
                $drift = 'The registration file is gone NOW; there is nothing left to clear, and the machine changed inside the window.'
            } elseif ($currentJson -cne $ClassifiedRegistrationJson) {
                # Finest available basis for the unusable class: the raw
                # record itself. Still-unparseable content that DIFFERS
                # from the classification read is a replacement (for
                # example a competing enrollment part-way through writing
                # its own record), not the bytes the confirmation covered.
                $drift = 'The record is still unusable, but its CONTENT differs from what classification read: it was rewritten inside the window, and the confirmation never covered the new content.'
            }
            # What remains is an unusable record byte-identical to the
            # classification read - the exact bytes the confirmation
            # covered - so the act it confirmed proceeds.
        }
    }

    if ($null -eq $drift) {
        return
    }

    Write-Fail 'The registration is not the one this run was confirmed to clear.'
    Write-Host $drift
    Write-Host ('What this run already did before this read: ' + $ChangesSoFar + '.')
    Write-Host 'The clear did NOT run and nothing was deleted by this run. The confirmation'
    Write-Host 'covered the record as it stood when the machine was classified, and another'
    Write-Host 'actor changed the machine inside the window since (SPEC 22/23).'
    Write-Host ('Inspect: the registration file under ' + $env:ProgramData + '\Amazon\SSM\InstanceData;')
    Write-Host 'Get-Service AmazonSSMAgent; the SSM Agent log. Then re-run this script: it'
    Write-Host 'classifies the machine afresh and asks for the confirmation again against'
    Write-Host 'whatever it holds then. What this run already did (above) is not undone.'
    exit 3
}

# Registration-ABSENCE revalidation immediately AFTER the destructive clear
# (SPEC 22/23) - the postcondition-adjacency member of the class invariant:
# R47 bound the launch to a pre-check, dd8c0b4 bound every success report
# to a boundary re-read, Assert-SsmRegistrationBeforeClear above bound the
# clear itself to a pre-clear re-read; this binds the clear's OWN
# postcondition to the report that claims it. A captured native exit code
# 0 is the agent's CLAIM that the registration left the disk - not proof
# (a concurrent enrollment can also write a whole new registration between
# the command and any later read) - and the operator is about to be told
# to run a fresh Register flow on the strength of that claim. So
# 'Local registration cleared.' prints only after the raw record re-reads
# as gone, immediately after the native command, with nothing but this
# check between the mutation and the message: a file still present in ANY
# form - parseable, empty (an empty leftover file still classifies
# Ambiguous, not registration-less), or unreadable - is drift, and so is
# a re-read that fails (fail closed: an unreadable post-clear file is not
# 'cleared').
#
# REMAINED vs REAPPEARED, one branch by design: after a captured exit
# code 0, a still-present record means either the clear did not do what
# its exit code claims or another enrollment wrote a record after it -
# and this script cannot actually distinguish those from inside one run.
# Both leave the machine possibly registered with an identity this run
# never inspected, and both get the same operator disposition (report
# drift, exit 3, no automatic retry), so one branch covers both rather
# than pretending to a distinction the evidence cannot support.
#
# Disposition - exit 3, the race/manual-intervention family, consistent
# with every other Reregister outcome: the service is already stopped and
# that is not undone; the operator decides against the machine's actual
# state. $ChangesSoFar names what the run already did, including that the
# clear command itself reported success.
# Returns normally only when the record re-reads as gone, or never
# returns.
function Assert-SsmRegistrationCleared {
    param([string]$ChangesSoFar)

    $currentJson = $null
    $readFailed = $false
    try {
        $currentJson = Get-SsmRegistrationFileJson
    } catch {
        $readFailed = $true
    }

    if ((-not $readFailed) -and ($null -eq $currentJson)) {
        return
    }

    Write-Fail 'The registration record is still present after a clear that reported success.'
    Write-Host ('What this run already did before this read: ' + $ChangesSoFar + '.')
    Write-Host 'The native clear returned exit code 0, but the raw registration record reads as'
    Write-Host "present NOW - parseable, empty, or unreadable - so the postcondition the"
    Write-Host "'Local registration cleared.' message would claim does not hold. Either the"
    Write-Host 'clear did not do what its exit code claims, or another enrollment wrote a'
    Write-Host 'registration after it; this script cannot distinguish those from inside one'
    Write-Host 'run, and neither is retried automatically (SPEC 22/23). The machine may be'
    Write-Host 'registered with an identity this run never inspected.'
    Write-Host ('Inspect: the registration file under ' + $env:ProgramData + '\Amazon\SSM\InstanceData;')
    Write-Host 'Get-Service AmazonSSMAgent (this run stopped it; verify its current state); the'
    Write-Host 'SSM Agent log. Then re-run this script: it classifies whatever the machine'
    Write-Host 'holds now and takes the appropriate action (a registered machine is reported,'
    Write-Host 'not re-enrolled).'
    exit 3
}

# --- 1. elevation (SPEC 21 step 1) ------------------------------------------

$windowsPrincipal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList ([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $windowsPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Fail 'This script must run in an elevated PowerShell session.'
    Write-Host 'Inspect/action: reopen PowerShell with "Run as administrator" and run the'
    Write-Host 'script again. Nothing was changed.'
    exit 1
}

# --- 2. module --------------------------------------------------------------

$modulePath = Join-Path -Path $PSScriptRoot -ChildPath 'SSMHybrid.psm1'
if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
    Write-Fail "Required module not found next to this script: $modulePath"
    exit 1
}
Import-Module -Name $modulePath -Force

# --- 3. supplied inputs (SPEC 20) -------------------------------------------
# A parameter actually supplied on the command line is validated NOW, so a bad
# supplied value fails fast with exit 2 before anything is inspected or
# classified. Values NOT supplied are deliberately NOT prompted for here:
# region and activation ID are only consumed by the Register action, so they
# are resolved inside that branch below. NoOperation, StartService,
# ManualIntervention, and Reregister therefore run to completion on a
# parameterless invocation without ever asking for activation values (SPEC
# 20/22/36).

if (-not [string]::IsNullOrEmpty($Region)) {
    $Region = Resolve-SsmInput -Value $Region -Label 'AWS region' -Example 'ap-southeast-2' -IsValid { param($Value) Test-SsmRegion -Region $Value }
    if ([string]::IsNullOrEmpty($Region)) {
        Write-Fail 'No valid AWS region was provided.'
        exit 2
    }
}

if (-not [string]::IsNullOrEmpty($ActivationId)) {
    $ActivationId = Resolve-SsmInput -Value $ActivationId -Label 'SSM activation ID' -Example 'a UUID, from: terraform output -raw activation_id' -IsValid { param($Value) Test-SsmActivationId -ActivationId $Value }
    if ([string]::IsNullOrEmpty($ActivationId)) {
        Write-Fail 'No valid SSM activation ID was provided.'
        exit 2
    }
}

# --- 4. local state (SPEC 21 steps 3-5, SPEC 23) ----------------------------

Write-Step 'Inspecting the local SSM Agent installation and registration...'

$serviceInfo = $null
try {
    $serviceInfo = Get-SsmServiceInfo
} catch {
    Write-Fail ("Could not query the AmazonSSMAgent service. Nothing was changed. Inspect the error: " + $_.Exception.Message)
    exit 1
}

$registrationJson = $null
try {
    $registrationJson = Get-SsmRegistrationFileJson
} catch {
    Write-Fail ("Could not read the local SSM registration file. Nothing was changed and nothing was deleted. Inspect the error: " + $_.Exception.Message)
    Write-Host 'Registration may be partially complete; resolve the read problem manually.'
    exit 3
}

$nodeState = Get-SsmNodeState -RegistrationJson $registrationJson -ServiceExists $serviceInfo.Exists -ServiceStatus $serviceInfo.Status -ServiceStartType $serviceInfo.StartType
$action = Get-SsmSetupAction -State $nodeState -ForceReregister:$ForceReregister
Write-Step ("State: " + $nodeState + ". Planned action: " + $action + ".")

# --- 5. actions -------------------------------------------------------------

if ($action -eq 'NoOperation') {
    $registration = Get-SsmRegistrationOrAmbiguousExit

    # Re-verify the service before declaring health (SPEC 22). The health
    # verdict requires AmazonSSMAgent to be BOTH Running AND Automatic at
    # re-query time - not merely as classified above. Drift that appeared
    # in between, for example the service stopping or Group Policy flipping
    # the startup type to Manual/Disabled, is repaired by the same shared,
    # dependency-ordered sequence every healthy-verdict branch uses (see
    # Repair-SsmServiceForHealth: startup type restored BEFORE the start,
    # because a Disabled service cannot be started at all), and the
    # invariant is then re-queried and must hold, or the run fails closed.
    $repair = Repair-SsmServiceForHealth -FailureGuidance @(
        'Another actor may be re-applying a service configuration, for example Group'
        'Policy. Inspect: Get-Service AmazonSSMAgent and the SSM Agent log under'
        ($env:ProgramData + '\Amazon\SSM\Logs. The existing registration was NOT modified.')
    )
    $currentService = $repair.Service
    $serviceStarted = $repair.Started
    $startupRestored = $repair.StartupRestored

    # Success-report adjacency (the class rule applied to the REPORT side):
    # the registration this branch holds was read BEFORE the repairs above,
    # and Start-Service/Set-Service are mutating steps another actor can
    # clear or replace a registration inside - a summary built from that
    # read would print a cached managed node ID. The guard re-reads and
    # re-validates the registration here, after the last mutation and
    # immediately before the summary, and withholds success when the record
    # is gone, changed, or unreadable. It runs on the clean path too: the
    # read is cheap, and every success report in this script is built the
    # same way - only facts read at the last possible moment, nothing but
    # reads and console output after them.
    $changesMade = 'nothing at all'
    if ($serviceStarted -and $startupRestored) {
        $changesMade = 'started AmazonSSMAgent and restored its Automatic startup type'
    } elseif ($serviceStarted) {
        $changesMade = 'started AmazonSSMAgent'
    } elseif ($startupRestored) {
        $changesMade = 'restored the AmazonSSMAgent Automatic startup type'
    }
    $registration = Get-SsmRegistrationForSuccessReport -Registration $registration -ChangesSoFar $changesMade

    Write-Host ''
    Write-Host ('Managed node ID : ' + $registration.ManagedInstanceId)
    # The region shown here comes from the local registration record, not from
    # an operator-supplied value: this path never asks for one, so the line is
    # simply omitted when the record carries no Region.
    if (-not [string]::IsNullOrEmpty($registration.Region)) {
        Write-Host ('Region          : ' + $registration.Region)
    }
    Write-Host ('Service         : AmazonSSMAgent ' + $currentService.Status + ' / startup ' + $currentService.StartType)
    if ($serviceStarted -or $startupRestored) {
        Write-Step 'Drift found at the re-check was repaired; the existing registration was untouched and no activation was consumed (SPEC 22/36).'
    } else {
        Write-Step 'Already registered and healthy. No changes made; no activation consumed (SPEC 22/36).'
    }
    exit 0
}

if ($action -eq 'StartService') {
    $registration = Get-SsmRegistrationOrAmbiguousExit
    Write-Step 'Registration exists and AmazonSSMAgent is stopped; starting the existing service (SPEC 23).'

    # Repairs run through the same shared, dependency-ordered sequence every
    # healthy-verdict branch uses (see Repair-SsmServiceForHealth): the
    # startup type is restored BEFORE the start - a Manual/Disabled start
    # type would leave the node offline again after the next reboot even
    # though it is Running now, and a Disabled service cannot be started at
    # all - and the start type is re-verified after the start, because the
    # restore can be undone between the Set-Service and the re-query. The
    # start itself is conditional on the re-read status, so the flags (and
    # the truthful summary below) reflect what this run actually did even
    # when another actor already started the service inside the window.
    $repair = Repair-SsmServiceForHealth -FailureGuidance @(
        'Another actor may be re-applying a service configuration, for example Group'
        'Policy. Inspect: Get-Service AmazonSSMAgent and the SSM Agent log. The existing'
        'registration was NOT modified and no activation was consumed.'
    )
    $currentService = $repair.Service
    $startupRestored = $repair.StartupRestored

    # Success-report adjacency, the same ordering as NoOperation above: the
    # registration this branch holds was read before Set-Service/Start-
    # Service ran, so the summary below may print its managed node ID only
    # after re-reading and re-validating the registration past those
    # mutations - gone, changed, or unreadable at this moment is reported
    # as drift, never a cached ID with exit 0.
    $changesMade = 'nothing at all'
    if ($repair.Started -and $startupRestored) {
        $changesMade = 'started AmazonSSMAgent and restored its Automatic startup type'
    } elseif ($repair.Started) {
        $changesMade = 'started AmazonSSMAgent'
    } elseif ($startupRestored) {
        $changesMade = 'restored the AmazonSSMAgent Automatic startup type'
    }
    $registration = Get-SsmRegistrationForSuccessReport -Registration $registration -ChangesSoFar $changesMade

    Write-Host ''
    Write-Host ('Managed node ID : ' + $registration.ManagedInstanceId)
    Write-Host ('Service         : AmazonSSMAgent ' + $currentService.Status + ' / startup ' + $currentService.StartType)
    if ($repair.Started -and $startupRestored) {
        Write-Step 'Service started and Automatic startup restored; existing registration preserved.'
    } elseif ($repair.Started) {
        Write-Step 'Service started; existing registration preserved.'
    } elseif ($startupRestored) {
        Write-Step 'Automatic startup restored; the service was already running again; existing registration preserved.'
    } else {
        Write-Step 'The service was already running again; existing registration preserved.'
    }
    exit 0
}

if ($action -eq 'Register') {
    Write-Host 'This machine is not registered as an SSM managed node yet.'
    Write-Host 'The AWS ssm-setup-cli will be downloaded over HTTPS, its Authenticode'
    Write-Host 'signature verified (Amazon.com Services LLC), and only then executed.'

    # Activation values are resolved HERE, only once a registration is actually
    # about to run (SPEC 20): values already supplied as parameters were
    # validated up front and pass straight through; missing ones are prompted
    # for now, and the code is always read masked. Every other action above
    # completed without asking for any of these.
    $Region = Resolve-SsmInput -Value $Region -Label 'AWS region' -Example 'ap-southeast-2' -IsValid { param($Value) Test-SsmRegion -Region $Value }
    if ([string]::IsNullOrEmpty($Region)) {
        Write-Fail 'No valid AWS region was provided.'
        exit 2
    }

    $ActivationId = Resolve-SsmInput -Value $ActivationId -Label 'SSM activation ID' -Example 'a UUID, from: terraform output -raw activation_id' -IsValid { param($Value) Test-SsmActivationId -ActivationId $Value }
    if ([string]::IsNullOrEmpty($ActivationId)) {
        Write-Fail 'No valid SSM activation ID was provided.'
        exit 2
    }

    # The trailing marker is the audit's documented exemption for a
    # label-shape collision (see the audit.sh header): the lowercased,
    # separator-wildcarded activation-code detector correctly cannot tell
    # this assignment from a leak, and must not be narrowed to miss one, so
    # this known-safe line - the value is a function invocation, not a
    # credential - carries the marker instead.
    $activationCode = Read-ActivationCode # audit-allow:synthetic
    if ([string]::IsNullOrEmpty($activationCode)) {
        Write-Fail 'No activation code was provided.'
        exit 2
    }

    $setupCliUrl = Get-SsmSetupCliUrl -Region $Region
    Write-Step ("Downloading and verifying the AWS setup CLI for region " + $Region + ".")
    Write-Step ("URL: " + $setupCliUrl)

    # Final pre-enrollment revalidation (SPEC 22/23): the Register plan was
    # chosen from a registration-less classification, but the interactive
    # prompts above sit between that classification and this point, and each
    # can wait on a human indefinitely - long enough for another setup
    # process to complete a whole registration on this machine. The guard
    # re-reads and re-classifies, and refuses while refusal is still free
    # (before any download, command execution, or activation consumption).
    # RACE WINDOW, stated plainly: this script-side guard covers everything
    # up to the enrollment invocation, but the SLOW steps - the setup-CLI
    # download and its signature verification - run INSIDE
    # Invoke-SsmEnrollment, past what any script-side check can see. The
    # class rule is that a state revalidation sits adjacent to the side
    # effect it guards, so the last check lives in the runner: it re-reads
    # the registration record after verification and immediately before the
    # native launch, and reports a refusal as a distinct outcome
    # (RegistrationAppeared) that this script maps, right after the call
    # below, to the same already-registered handling this guard's own
    # refusal uses. What remains is check-then-act at irreducible scale: the
    # statements between that re-read and the native command itself.
    Assert-SsmRegistrationStillAbsent -ClassifiedState $nodeState

    try {
        # Invoke-SsmEnrollment (SSMHybrid.psm1) performs SPEC 21 steps 6-9:
        # forces TLS 1.2 where needed, downloads ssm-setup-cli to a temp file,
        # REFUSES to run any binary whose Authenticode signature is not Valid
        # and signed by Amazon.com Services LLC, REFUSES likewise to launch
        # at all when its pre-launch re-read finds a local registration
        # present in any form (SPEC 22/23 - reported as RegistrationAppeared
        # on the result and handled right after this call), runs the
        # registration without ever echoing or logging the command line
        # (SPEC 43), and removes the temp download directory afterwards
        # (SPEC 21 step 16) with bounded retries. A leftover after a
        # successful enrollment is NOT a failure: the module warns naming
        # the path and reports it on this result, so the summary at the end
        # can stay truthful.
        $enrollmentResult = Invoke-SsmEnrollment -Region $Region -ActivationId $ActivationId -ActivationCode $activationCode
    } catch {
        Write-Fail ('Registration did not complete: ' + $_.Exception.Message)
        Write-Host 'Activation values were not logged. Registration may have partially'
        Write-Host 'completed: inspect the local registration file, the AmazonSSMAgent'
        Write-Host 'service, and the SSM Agent log before re-running. Nothing was deleted.'
        exit 1
    } finally {
        # Clear bootstrap secrets from memory as soon as possible (SPEC 21 step 17).
        $activationCode = $null
        Remove-Variable -Name activationCode -ErrorAction SilentlyContinue
    }

    # Last-moment race outcome from the enrollment runner (SPEC 22/23): the
    # download and signature verification ran inside Invoke-SsmEnrollment
    # AFTER the script-side guard above, and the runner found a local
    # registration present (or unreadable) when it re-read the record
    # immediately before launching ssm-setup-cli - so it refused to launch,
    # cleaned up its temp download, and reported the refusal here. This is
    # the already-registered handling, not the failure dump in the catch
    # above: nothing was enrolled, the executable never ran, and no
    # activation was consumed - the shared race report says the rest.
    if ($enrollmentResult.RegistrationAppeared) {
        Write-SsmRegistrationRaceAndExit -StalePlan ('This run passed the revalidation above, but the setup-CLI download and' +
            ' signature verification that followed gave another process time to complete a registration' +
            ' first; the enrollment runner refused to launch, so the download was never executed.')
    }

    Write-Step 'Registration command finished. Verifying the local result...'

    $registrationAfter = $null
    try {
        $registrationAfter = Get-SsmRegistration
    } catch {
        Write-Fail 'The local registration file is present but could not be parsed.'
        Write-Host 'Registration may have partially completed. Inspect: the registration file'
        Write-Host 'under ProgramData\Amazon\SSM, Get-Service AmazonSSMAgent, and the SSM Agent'
        Write-Host 'log. Nothing was deleted; do not re-run with -ForceReregister blindly.'
        exit 1
    }
    if ($null -eq $registrationAfter) {
        Write-Fail 'No local registration file was found after registration.'
        Write-Host 'The registration may have partially completed or failed silently.'
        Write-Host 'Inspect: the SSM Agent log and the AmazonSSMAgent service. Nothing was deleted.'
        exit 1
    }

    $serviceAfter = Get-ServiceInfoOrFail
    if (-not $serviceAfter.Exists) {
        Write-Fail 'The AmazonSSMAgent service does not exist after registration.'
        Write-Host 'Inspect: installed services and the SSM Agent installation log. The'
        Write-Host 'registration data was NOT deleted.'
        exit 1
    }
    # Post-enrollment repairs run through the same shared, dependency-
    # ordered sequence every healthy-verdict branch uses (see
    # Repair-SsmServiceForHealth); the exists check above stays here so a
    # missing agent right after enrollment is reported in this branch's own
    # terms before any repair is attempted.
    $repair = Repair-SsmServiceForHealth -FailureGuidance @(
        'Registration data was NOT deleted. Inspect: Get-Service AmazonSSMAgent and the'
        'SSM Agent log; the node may still be completing its first connection.'
    )
    $serviceAfter = $repair.Service
    $startupSetAfter = $repair.StartupRestored
    $serviceStartedAfter = $repair.Started

    Remove-Variable -Name ActivationId -ErrorAction SilentlyContinue

    # Success-report adjacency, the same ordering as NoOperation and
    # StartService above: the registration this branch verified was read
    # BEFORE the startup repairs, so the summary below may print its
    # managed node ID only after re-reading and re-validating the
    # registration past those mutations. Drift here is reported, never
    # retried: the enrollment already consumed the activation, and whether
    # to accept a replacement identity or enroll afresh is the operator's
    # decision, so the guard's report names the consumed activation too.
    $changesMade = 'completed the enrollment (one activation was consumed)'
    if ($startupSetAfter -and $serviceStartedAfter) {
        $changesMade = 'completed the enrollment (one activation was consumed), set the AmazonSSMAgent startup type to Automatic, and started AmazonSSMAgent'
    } elseif ($startupSetAfter) {
        $changesMade = 'completed the enrollment (one activation was consumed) and set the AmazonSSMAgent startup type to Automatic'
    } elseif ($serviceStartedAfter) {
        $changesMade = 'completed the enrollment (one activation was consumed) and started AmazonSSMAgent'
    }
    $registrationAfter = Get-SsmRegistrationForSuccessReport -Registration $registrationAfter -ChangesSoFar $changesMade

    Write-Host ''
    Write-Host 'Registration complete.'
    Write-Host ('Managed node ID : ' + $registrationAfter.ManagedInstanceId)
    Write-Host ('Region          : ' + $registrationAfter.Region)
    Write-Host ('Service         : AmazonSSMAgent ' + $serviceAfter.Status + ' / startup ' + $serviceAfter.StartType)
    Write-Host 'It can take a few minutes before the node reports Online in AWS Systems Manager.'
    if ($enrollmentResult.TempDownloadRemoved) {
        Write-Step 'Temporary download removed; activation values cleared from memory.'
    } else {
        # The module already warned when its removal retries ran out (SPEC 21
        # step 16 is a postcondition, but a leftover is not a failed
        # enrollment). The summary must not repeat the unconditional removal
        # claim while the download is still on disk: nothing secret is in it -
        # it is the AWS ssm-setup-cli executable - but the operator's mental
        # model must match the filesystem, so name the path and the fix.
        Write-Host ('WARNING: the temporary download could not be removed and is still on disk:') -ForegroundColor Yellow
        Write-Host ('  ' + $enrollmentResult.TempDownloadPath)
        Write-Host 'Nothing secret is in it (the AWS ssm-setup-cli executable); delete it manually'
        Write-Host 'once any antivirus scan has released the lock, for example:'
        Write-Host ("  Remove-Item -LiteralPath '" + $enrollmentResult.TempDownloadPath + "' -Recurse -Force")
        Write-Step 'Activation values cleared from memory.'
    }
    exit 0
}

if ($action -eq 'ManualIntervention') {
    Write-Fail ("This machine is in the '" + $nodeState + "' state; nothing was changed automatically (SPEC 23).")
    if ($nodeState -eq 'RegisteredUnhealthy') {
        Write-Host 'A local registration record parses, but the AmazonSSMAgent service is missing,'
        Write-Host 'not Running, or not configured for Automatic startup.'
        Write-Host 'Inspect: Get-Service AmazonSSMAgent;'
        Write-Host ('          Get-CimInstance Win32_Service -Filter "Name=''AmazonSSMAgent''" (State, StartMode);')
        Write-Host ('          the SSM Agent log under ' + $env:ProgramData + '\Amazon\SSM\Logs.')
    } else {
        Write-Host 'A local registration file exists but cannot be parsed, so its contents cannot'
        Write-Host 'be trusted for an automatic decision (SPEC 23).'
        Write-Host ('Inspect: the registration file under ' + $env:ProgramData + '\Amazon\SSM\InstanceData;')
        Write-Host '          Get-Service AmazonSSMAgent; the SSM Agent log.'
    }
    Write-Host 'Registration may be partially complete. Nothing was deleted or deregistered.'
    Write-Host 'Repair the cause manually, or re-run with -ForceReregister to discard the local'
    Write-Host 'registration and enroll afresh (destructive; consumes a new activation).'
    exit 3
}

if ($action -eq 'Reregister') {
    Write-Host 'Reregistration was requested with -ForceReregister. This is DESTRUCTIVE:'
    Write-Host '  - AmazonSSMAgent is stopped first and left STOPPED after the clear;'
    Write-Host '  - the local SSM registration will be cleared (amazon-ssm-agent -register -clear);'
    Write-Host '  - the current managed node ID stops being used by this machine;'
    Write-Host '  - the node remains registered in AWS until separately deregistered there;'
    Write-Host '  - re-enrollment consumes a NEW activation and yields a NEW managed node ID.'

    $confirmation = Read-Host -Prompt 'Type yes to clear the local registration'
    if ($confirmation -cne 'yes') {
        Write-Host 'Not confirmed. Nothing was changed.'
        exit 3
    }

    $agentExe = Join-Path -Path $env:ProgramFiles -ChildPath 'Amazon\SSM\amazon-ssm-agent.exe'
    if (-not (Test-Path -LiteralPath $agentExe -PathType Leaf)) {
        Write-Fail ("amazon-ssm-agent.exe was not found at " + $agentExe + ".")
        Write-Host 'Nothing was changed. Clear the registration manually once the agent exists:'
        Write-Host ("  Stop-Service AmazonSSMAgent")
        Write-Host ("  & '" + $agentExe + "' -register -clear")
        exit 3
    }

    # Stop the agent BEFORE the clear, the same sequence the README's manual
    # reset documents: a running agent can hold or rewrite its registration
    # data while -register -clear runs. Already-stopped and service-missing
    # are both tolerated; the clear only proceeds once the service is verified
    # stopped. The service is deliberately NOT started again in this run: with
    # no registration left it has nothing to run with, and the fresh Register
    # run (a new activation) brings it back. $stopNote records what this run
    # actually did here, for the second guard call's drift report below.

    # Revalidation before the FIRST service mutation, not only before the
    # clear: the stop is itself damage-if-stale. If another setup replaced
    # the registration while this run waited on the confirmation prompt,
    # stopping now would take the REPLACEMENT identity's agent offline -
    # the pre-clear revalidation would still abort the clear, but the
    # newly enrolled node would sit dark until something repaired it. The
    # same guard runs here, before any mutation has happened, so drift is
    # refused while refusal is still free. Between this guard and the
    # Stop-Service below there is no statement other than the branch
    # decision (a read taken just above it).
    $stopNote = 'nothing at all'
    $serviceBeforeClear = Get-ServiceInfoOrFail
    Assert-SsmRegistrationBeforeClear -ClassifiedRegistrationJson $registrationJson -ChangesSoFar $stopNote
    if (-not $serviceBeforeClear.Exists) {
        Write-Step 'AmazonSSMAgent service not found; nothing to stop before the clear.'
        $stopNote = 'the AmazonSSMAgent service was not found, so nothing was stopped'
    } elseif ($serviceBeforeClear.Status -eq 'Stopped') {
        Write-Step 'AmazonSSMAgent is already stopped.'
        $stopNote = 'nothing at all - AmazonSSMAgent was already stopped'
    } else {
        Write-Step ("Stopping AmazonSSMAgent before the clear (was '" + $serviceBeforeClear.Status + "').")
        try {
            Stop-Service -Name 'AmazonSSMAgent'
        } catch {
            Write-Fail ("Stopping AmazonSSMAgent failed: " + $_.Exception.Message)
            Write-Host 'Nothing was changed and the registration was NOT cleared. Inspect:'
            Write-Host 'Get-Service AmazonSSMAgent and the SSM Agent log, then re-run.'
            exit 3
        }
        $stopNote = 'stopped AmazonSSMAgent'
    }

    $serviceAtClear = Get-ServiceInfoOrFail
    if ($serviceAtClear.Exists -and ($serviceAtClear.Status -ne 'Stopped')) {
        Write-Fail ("AmazonSSMAgent did not stop (status '" + $serviceAtClear.Status + "'); the registration was NOT cleared.")
        Write-Host 'Inspect: Get-Service AmazonSSMAgent and the SSM Agent log, then re-run.'
        exit 3
    }

    # Destructive-act adjacency, the second call of the same guard (see
    # Assert-SsmRegistrationBeforeClear above): the registration that
    # classified this branch was read before an interactive confirmation a
    # human can sit on and before the service stop, so the clear runs only
    # after the record is re-read immediately beforehand and is still
    # exactly what the confirmation covered. Between this guard and the
    # native clear below there is no mutation and no slow step - only the
    # stopped re-verification directly below (a read) and the
    # error-preference juggling the native call itself needs.
    Assert-SsmRegistrationBeforeClear -ClassifiedRegistrationJson $registrationJson -ChangesSoFar $stopNote

    # The clear is justified by TWO facts, so both are read at its
    # boundary: the registration identity (revalidated just above) and the
    # service being stopped - verified after the stop, several statements
    # ago. A service another actor restarted in between is exactly what
    # the documented stop-before-clear sequence exists to prevent: a
    # running agent can hold or rewrite its registration data while
    # -register -clear runs, turning the clear into a partial one the
    # post-clear guard could only REPORT, not prevent. So the stopped fact
    # is re-read here, immediately before the mutation, like every other
    # justifying fact; a running service aborts, and deliberately without
    # re-stopping: an actor actively restarting the agent mid-sequence is
    # the operator's fight, not this run's (bounded, like every repair
    # here).
    $serviceAtClearBoundary = Get-ServiceInfoOrFail
    if ($serviceAtClearBoundary.Exists -and ($serviceAtClearBoundary.Status -ne 'Stopped')) {
        Write-Fail ("AmazonSSMAgent is running again at the clear boundary (status '" + $serviceAtClearBoundary.Status + "'); the clear was NOT run.")
        Write-Host 'The documented clear sequence requires the agent stopped (a running agent can'
        Write-Host 'hold or rewrite its registration data mid-clear). Another actor restarted it'
        Write-Host 'after this run stopped it, so the registration was NOT cleared and the stop is'
        Write-Host 'not re-fought against that actor. Inspect: Get-Service AmazonSSMAgent and the'
        Write-Host 'SSM Agent log, then re-run (the confirmation is asked for again).'
        exit 3
    }

    Write-Step 'Clearing the local registration (amazon-ssm-agent -register -clear).'
    # Native-call discipline, mirroring Invoke-SsmEnrollment in
    # SSMHybrid.psm1: under this script's $ErrorActionPreference = 'Stop',
    # redirected stderr from a native command can surface on Windows
    # PowerShell 5.1 as a terminating NativeCommandError, which would bypass
    # the $LASTEXITCODE branch below entirely - and a clear that succeeded
    # while merely writing a warning to stderr would be misreported as a
    # failure. So: relax ErrorActionPreference around the call, discard BOTH
    # streams (the agent's text never reaches the console), restore the
    # preference in finally, and judge the outcome by $LASTEXITCODE alone -
    # but only once $LASTEXITCODE has proved the agent actually launched: a
    # launch that never happened (the executable quarantined or deleted
    # between the existence check above and the invocation) leaves it
    # holding whatever an earlier native call in this session left there -
    # commonly 0 - which the exit-code branch would read as a successful
    # clear. The sentinel closes that hole: $LASTEXITCODE is reset to $null
    # before the call, and a still-$null value after it is a hard failure
    # of the clear. Only a genuinely captured exit code 0 may reach the
    # post-clear verification below, and only that verification may print
    # the success message.
    $previousEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $clearExitCode = $null
    try {
        $global:LASTEXITCODE = $null
        & $agentExe -register -clear 2>&1 | Out-Null
        $clearExitCode = $LASTEXITCODE
    } catch {
        # The launch failure itself (nonexistent or non-runnable image). It
        # can surface as a terminating error even under 'Continue'; it is
        # absorbed here so the sentinel branch below reports the failure in
        # this block's own terms (nothing on this command line is secret).
        $clearExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousEap
    }
    if ($null -eq $clearExitCode) {
        Write-Fail ("Clearing the local registration failed: " + $agentExe + " could not be launched, so the clear never ran.")
        Write-Host 'Nothing was cleared. The agent executable passed the existence check above but could'
        Write-Host 'not be started (for example quarantined while the service was being stopped). Inspect'
        Write-Host 'the agent installation and re-run.'
        exit 3
    }
    if ($clearExitCode -ne 0) {
        Write-Fail ("Clearing the local registration failed with exit code " + $clearExitCode + ".")
        Write-Host 'The registration may be partially cleared. Inspect the registration file and'
        Write-Host 'the SSM Agent log before re-running.'
        exit 3
    }

    # Postcondition adjacency (see Assert-SsmRegistrationCleared above): a
    # captured exit code 0 is the agent's claim, not proof the record left
    # the disk, and the completion message below claims the clear's own
    # postcondition - so the record is re-verified gone immediately after
    # the native command, with nothing but this check between the mutation
    # and the message.
    Assert-SsmRegistrationCleared -ChangesSoFar ($stopNote + '; ran the clear, which reported success (exit code 0)')

    # Report adjacency for the completion message: the STOPPED claim is a
    # machine-state fact like any other reported fact, so it is read here,
    # at the boundary, instead of being asserted from the stop sequence's
    # earlier state - another actor can restart the service inside the
    # clear window, and the message must match the machine.
    #
    # Failure handling is PROPORTIONAL TO THE QUERY'S ROLE: the point of
    # no return has passed (the clear completed and its postcondition was
    # verified by the guard above), and this read feeds ONLY the wording
    # below - nothing follows it but console output - so it is a
    # REPORT-only query and must fail SOFT. The fail-closed wrapper
    # belongs to DECISION queries, where acting on unknown state is
    # dangerous; exiting here instead would misreport a COMPLETED
    # destructive operation over a transient query failure, burying the
    # verified clear result and the fresh-activation guidance under an
    # unrelated error report. A failed read degrades the wording to
    # 'unknown' - which is not a claim of any state - and reporting
    # completes.
    $serviceAtReport = $null
    $serviceReadFailed = $false
    try {
        $serviceAtReport = Get-SsmServiceInfo
    } catch {
        $serviceReadFailed = $true
    }

    Write-Step 'Local registration cleared.'
    if ($serviceReadFailed) {
        Write-Host 'The AmazonSSMAgent service status could not be queried at the final read; its'
        Write-Host 'current status is unknown (unknown is not a claim of stopped or running).'
        Write-Host ('What this run did to the service: ' + $stopNote + '. Check: Get-Service AmazonSSMAgent.')
    } elseif (-not $serviceAtReport.Exists) {
        Write-Host 'The AmazonSSMAgent service no longer exists at the final read (the agent'
        Write-Host 'installation changed under this run).'
    } elseif ($serviceAtReport.Status -eq 'Stopped') {
        Write-Host 'AmazonSSMAgent has deliberately been left STOPPED: without a registration it'
        Write-Host 'has nothing to run with.'
    } else {
        Write-Host ("AmazonSSMAgent was left stopped by this run, but another actor has started it again (status '" + $serviceAtReport.Status + "').")
    }
    Write-Host 'Re-enroll by running this script again WITHOUT -ForceReregister, providing a'
    Write-Host 'fresh activation (the previous one is consumed); that Register run starts'
    Write-Host 'AmazonSSMAgent again with the new identity.'
    exit 3
}

Write-Fail ("Unexpected action '" + $action + "' for state '" + $nodeState + "'. Nothing was changed.")
exit 1
