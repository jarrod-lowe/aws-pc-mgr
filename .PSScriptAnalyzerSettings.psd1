# PSScriptAnalyzer settings (plan Task T8).
# Only PSUseCompatibleSyntax runs: the Windows module and entry scripts must
# parse under Windows PowerShell 5.1 (the on-machine shell) and PowerShell 7
# (the CI container).
# IncludeRules is required to actually isolate the rule: a settings file with a
# Rules block alone still runs PSScriptAnalyzer's full default ruleset, which
# floods these console scripts with PSAvoidUsingWriteHost warnings.
@{
    IncludeRules = @('PSUseCompatibleSyntax')
    Rules         = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.0')
        }
    }
}
