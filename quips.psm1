# -------------------------------------------------------------------------------------------------------------------
# quips 0.5   |   https://github.com/noalt/quips
# -------------------------------------------------------------------------------------------------------------------
Set-StrictMode -Version 'Latest'

$local:ScriptsDirectory = "$PSScriptRoot"
$local:ModulesDirectory = "$PSScriptRoot"

# -------------------------------------------------------------------------------------------------------------------

<#
.SYNOPSIS
Build a PowerShell module using the latest versions, or if -AllScripts is specified all, of the PowerShell scripts in the $ScriptsDirectory.
#>
function Build-QuipsModule {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter()]
        [ValidateScript({ -not $_.ToLowerInvariant().Contains('quips.psm1') }, ErrorMessage = 'Cannot contain "quips.psm1".')]
        [String]$Name,

        [Parameter()]
        [switch]$AllScripts
    )
    begin {
        if ([String]::IsNullOrEmpty($Name)) {
            $directory = Get-Item -Path "$PSScriptRoot"
            if ($directory.Name -eq 'quips') {
                $Name = 'quips-scripts.psm1'
            }
            else {
                $Name = '{0}.psm1' -f $directory.Name
            }
            $PSBoundParameters.TryAdd('Name', $Name) | Out-Null
        }
    }
    process {
        $scriptRepository = Initialize-ScriptRepository -Path "$ScriptsDirectory"
        $moduleFile = Get-ModuleFileContent -ScriptRepository $scriptRepository -Name $Name -AllScripts:$AllScripts
        if ($moduleFile) {
            $moduleFile | Out-File -FilePath (Join-Path -Path "$ModulesDirectory" -ChildPath "$Name") -Encoding 'utf8BOM'
        }
        else {
            $message = 'No custom scripts found in "{0}", no module file to write.' -f $ScriptsDirectory
            Write-Error -Message "$message" -ErrorAction 'Stop'
        }
    }
    end {
    }
}

<#
.SYNOPSIS
Invokes the PSScriptAnalyzer for all PowerShell scripts and modules in the $ScriptsDirectory and $ModulesDirectory.
#>
function Invoke-QuipsScriptAnalyzer {
    [CmdletBinding(PositionalBinding = $false)]
    param (
    )
    begin {
        if (-not (Get-Module -ListAvailable -Name 'PSScriptAnalyzer')) {
            $message = 'PowerShell Module "PSScriptAnalyzer" is not installed, please install using "Install-Module -Name ''PSScriptAnalyzer''".'
            Write-Error -Message "$message" -ErrorAction 'Stop'
        }
    }
    process {
        Invoke-ScriptAnalyzer -Path "$ScriptsDirectory" -IncludeDefaultRules
        if ($ModulesDirectory -ne $ScriptsDirectory) {
            Invoke-ScriptAnalyzer -Path "$ModulesDirectory" -IncludeDefaultRules
        }
    }
    end {
    }
}

<#
.SYNOPSIS
Creates a new PowerShell script with optional Pester test file and a set of other optional sections.
#>
function New-QuipsScript {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory)]
        [ValidatePattern('([A-Za-z0-9_-]+)\-([A-Za-z0-9_-]+)', ErrorMessage = 'Must match pattern "Verb-SomeAction".')]
        [ValidateScript( { $name = $_; (Get-Verb | ForEach-Object { $name.StartsWith(('{0}-') -f $_.Verb) }) -contains $true }, ErrorMessage = 'Must start with an approved PowerShell verb.')]
        [String]$Name,

        [ValidateSet('ScriptProcess', 'StrictMode')]
        [String[]]$Options,

        [switch]$ExcludeTests
    )
    begin {
        $nameWithVersion = '{0}_01' -f $Name

        $scriptCodeFile = Join-Path -Path "$ScriptsDirectory" -ChildPath "$nameWithVersion.ps1"
        $checkCodeFileExists = Test-Path -Path "$scriptCodeFile" -PathType 'Any'
        if ($checkCodeFileExists) {
            $message = 'Script Code File "{0}.ps1" already exists in directory "{1}".' -f $nameWithVersion, $ScriptsDirectory
            Write-Error -Message "$message" -ErrorAction 'Stop'
        }
        $scriptTestFile = Join-Path -Path "$ScriptsDirectory" -ChildPath "$nameWithVersion.Tests.ps1"
        $checkTestFileExists = Test-Path -Path "$scriptTestFile" -PathType 'Any'
        if ($checkTestFileExists) {
            $message = 'Script Test File "{0}.Tests.ps1" already exists in directory "{1}".' -f $nameWithVersion, $ScriptsDirectory
            Write-Error -Message "$message" -ErrorAction 'Stop'
        }
        $pesterModule = Get-Module -ListAvailable -Name 'Pester' -Verbose:$false
        if (-not $ExcludeTests -and -not $pesterModule) {
            $message = 'PowerShell Module "Pester" is not installed but is required for running unit and integration tests, please install using "Install-Module -Name ''Pester''".'
            Write-Warning -Message "$message" -WarningAction 'Continue'
        }
        if (-not $ExcludeTests -and $pesterModule.Version -notlike '5.*') {
            $message = 'PowerShell Module "Pester" is version "{0}" but must be at least version 5, please follow instructions on https://pester.dev/docs/introduction/installation#removing-the-built-in-version-of-pester to uninstall the built-in version on Windows.' -f $pesterModule.Version
            Write-Warning -Message "$message" -WarningAction 'Continue'
        }
    }
    process {
        if ($Options) {
            $functionOptions = @{
                ScriptProcess = $Options.Contains('ScriptProcess')
                StrictMode = $Options.Contains('StrictMode')
            }
        }
        else {
            # Set default options for Code Template:
            $functionOptions = @{
                ScriptProcess = $true
                StrictMode = $true
            }
        }
        $scriptCodeFileContent = Get-ScriptCodeContent -FunctionName $nameWithVersion -FunctionOptions $functionOptions
        Set-Content -Path $scriptCodeFile -Value $scriptCodeFileContent -Encoding 'utf8BOM'
        if (-not $ExcludeTests) {
            $scriptTestFileContent = Get-ScriptTestContent -FunctionName $nameWithVersion -FunctionOptions $functionOptions
            Set-Content -Path $scriptTestFile -Value $scriptTestFileContent -Encoding 'utf8BOM'
        }
    }
    end {
    }
}

# -------------------------------------------------------------------------------------------------------------------

function Initialize-Module {
    # Ensure $ScriptsDirectory is a valid directory:
    if (-not (Test-Path -Path "$ScriptsDirectory" -PathType 'Container')) {
        $message = '$ScriptsDirectory = "{0}" is not a valid directory.' -f $ScriptsDirectory
        Write-Error -Message "$message" -ErrorAction 'Stop'
    }
    # Ensure $ModulesDirectory is a valid directory:
    if (-not (Test-Path -Path "$ModulesDirectory" -PathType 'Container')) {
        $message = '$ModulesDirectory = "{0}" is not a valid directory.' -f $ModulesDirectory
        Write-Error -Message "$message" -ErrorAction 'Stop'
    }
    # Create (or update) files for all built-in quips functions:
    foreach($functionName in $functions.Keys) {
        $path = Join-Path -Path "$ScriptsDirectory" -ChildPath "$functionName.ps1"
        Set-Content -Path "$path" -Value $functions[$functionName] -Encoding 'utf8BOM' -Force
    }
}

function Initialize-ScriptRepository([String]$Path) {
    $out = [ScriptRepository]::new()
    $scriptFiles = Get-ChildItem -Path "$Path" -Filter '*.ps1'
    foreach ($file in $scriptFiles) {
        if ($file.Name -match '(?<Verb>\w+)-(?<Action>\w+)_(?<Version>[0-9][0-9]).ps1') {
            # Normal script with version:
            $name = '{0}-{1}_{2}' -f $matches['Verb'], $matches['Action'], $matches['Version']
            $script = [Script]::new($file, $name, $matches['Verb'], $matches['Action'], [int]$matches['Version'])
            $out.Add($script)
        }
        elseif ($file.Name -match '(?<Verb>\w+)-(?<Action>\w+)_(?<Variant>\w+).ps1') {
            # Normal script with variant:
            $name = '{0}-{1}_{2}' -f $matches['Verb'], $matches['Action'], $matches['Variant']
            $script = [Script]::new($file, $name, $matches['Verb'], $matches['Action'], $matches['Variant'])
            $out.Add($script)
        }
        elseif ($file.Name -match '(?<Verb>\w+)-(?<Action>\w+).ps1') {
            # Built-in function, internal, will not be exposed in built PowerShell modules:
            $name = '{0}-{1}' -f $matches['Verb'], $matches['Action']
            $script = [Script]::new($file, $name, $matches['Verb'], $matches['Action'])
            $out.Add($script)
        }
        elseif ($file.Name -match '(?<Verb>\w+)-(?<Action>\w+)_(?<VersionOrVariant>\w+).Tests.ps1') {
            # Pester Test Script, don't include in ScriptRepository.
        }
        else {
            Write-Warning ('Script File "{0}" does not match any known patterns.' -f $file.FullName)
        }
    }
    $out
}

function Get-Function([ScriptRepository]$ScriptRepository, [Script]$Script, [switch]$AllScripts) {
    $indent = '    '
    if ($AllScripts) {
        $isAlias = ($null -ne $Script.Version -and $ScriptRepository.GetLatestVersions().Contains($Script))
        $out = @("function $($Script.Name) {")
    }
    else {
        if($Script.Variant) {
            $isAlias = $false
            $out = @("function $($Script.Verb)-$($Script.Action)_$($Script.Variant) {")
        }
        else {
            $isAlias = $true
            $out = @("function $($Script.Verb)-$($Script.Action) {")
        }
    }

    $functions = $ScriptRepository.GetAllFunctions()
    foreach ($line in $Script.Content) {
        # Indent all lines one level:
        $line = "{0}{1}" -f $indent, $line
        if ($AllScripts) {
            # Add Alias attribute to the latest version of the script found:
            if ($line.Trim().StartsWith('[CmdletBinding') -and $isAlias) {
                $out += '{0}[Alias("{1}")]' -f $indent, $Script.Alias
            }
        }
        if ($line -match "& .\\(?<Verb>\w+)-(?<Action>\w+)_(?<Version>[0-9][0-9]).ps1") {
            # Replace "& .\Verb-Action_##.ps1" with calls to "Verb-Action":
            $cmdlet = "{0}-{1}_{2}" -f $matches["Verb"], $matches["Action"], $matches["Version"]
            if (-not $functions.Contains("$cmdlet")) {
                $message = "{0}.ps1 » Referenced cmdlet `"{1}.ps1`" cannot be found in directory `"{2}`"." -f $Script.Name, $cmdlet, $ScriptsDirectory
                Write-Error -Message $message -ErrorAction Stop
            }
            if ($AllScripts) {
                $line = $line.Replace("& .\$cmdlet.ps1", "$cmdlet")
            }
            else {
                $line = $line.Replace("& .\$cmdlet.ps1", "$($matches["Verb"])-$($matches["Action"])")
            }
        }
        elseif ($line -match "& .\\(?<Verb>\w+)-(?<Action>\w+)_(?<Variant>\w+).ps1") {
            # Replace "& .\Verb-Action_Variant.ps1" with calls to "Verb-Action_Variant":
            $cmdlet = "{0}-{1}_{2}" -f $matches["Verb"], $matches["Action"], $matches["Variant"]
            if (-not $functions.Contains("$cmdlet")) {
                $message = "{0}.ps1 » Referenced cmdlet `"{1}.ps1`" cannot be found in directory `"{2}`"." -f $Script.Name, $cmdlet, $ScriptsDirectory
                Write-Error -Message $message -ErrorAction Stop
            }
            $line = $line.Replace("& .\$cmdlet.ps1", "$cmdlet")
        }
        elseif ($line -match "& .\\(?<Verb>\w+)-(?<Action>\w+).ps1") {
            # Replace "& .\Verb-Action.ps1" with calls to "Verb-Action":
            $cmdlet = "{0}-{1}" -f $matches["Verb"], $matches["Action"]
            if (-not $functions.Contains("$cmdlet")) {
                $message = "{0}.ps1 » Referenced cmdlet `"{1}.ps1`" cannot be found in directory `"{2}`"." -f $Script.Name, $cmdlet, $ScriptsDirectory
                Write-Error -Message $message -ErrorAction Stop
            }
            $line = $line.Replace("& .\$cmdlet.ps1", "$cmdlet")
        }
        elseif ($line -match ".\\(?<Verb>\w+)-(?<Action>\w+)_(?<Version>[0-9][0-9]).ps1") {
            if ($AllScripts) {
                # Replace ".\Verb-Action_##.ps1" in Documentation Examples with calls to "Verb-Action_##":
                $line = $line.Replace(".\$($Script.Name).ps1", "$($Script.Name)")
            }
            else {
                # Replace ".\Verb-Action_##.ps1" in Documentation Examples with calls to "Verb-Action":
                $line = $line.Replace(".\$($Script.Name).ps1", "$($Script.Verb)-$($Script.Action)")
            }
        }
        elseif ($line -match ".\\(?<Verb>\w+)-(?<Action>\w+)_(?<Variant>\w+).ps1") {
            # Replace ".\Verb-Action_Variant.ps1" in Documentation Examples with calls to "Verb-Action_Variant":
            $line = $line.Replace(".\$($Script.Name).ps1", "$($Script.Verb)-$($Script.Action)_$($Script.Variant)")
        }
        if ($line.Trim().StartsWith('# -----') -or $line.Trim().StartsWith('# quips ')) {
            # Don't include headers of built-in quips functions.
        }
        else {
            if ($line -eq $indent) {
                # Don't add lines with all whitespace:
                $out += ''
            }
            else {
                $out += $line
            }
        }
    }
    $out += "}`n"
    $out
}

function Get-ScriptCodeContent([String]$FunctionName, [PSCustomObject]$FunctionOptions) {
    $out = @()
    $out += '<#'
    $out += '.SYNOPSIS'
    $out += '...'
    $out += '#>'
    $out += '[CmdletBinding(PositionalBinding = $false)]'
    $out += 'param ('
    $out += '    [Parameter(Mandatory)]'
    $out += '    [String]$MandatoryParameter,'
    $out += ''
    $out += '    [Parameter()]'
    $out += '    [String]$OptionalParameter = ''World'''
    $out += ')'
    $out += 'begin {'
    if ($FunctionOptions.StrictMode) {
        $out += '    Set-StrictMode -Version ''Latest'''
    }
    $out += '    $PSBoundParameters.TryAdd(''OptionalParameter'', ''World'') | Out-Null'
    $out += '}'
    $out += 'process {'
    if ($FunctionOptions.ScriptProcess) {
        $out += '    & .\Write-ScriptProcess.ps1 -Invocation $MyInvocation'
        $out += ''
    }
    $out += '    $out = ''{0} {1}'' -f $MandatoryParameter, $OptionalParameter'
    $out += '    $out'
    $out += '}'
    $out += 'end {'
    $out += '}'
    $out
}

function Get-ScriptTestContent([String]$FunctionName, [PSCustomObject]$FunctionOptions) {
    $out = @()
    $out += 'BeforeDiscovery {'
    $out += '}'
    $out += 'BeforeAll {'
    $out += '}'
    $out += "Describe '$FunctionName' {"
    $out += '    BeforeEach {'
    $out += '    }'
    $out += '    It ''Given "World", Should Return "Hello World"'' {'
    $out += '        $result = & .\{0}.ps1 -MandatoryParameter ''Hello''' -f $FunctionName
    $out += '        $result | Should -Be ''Hello World'''
    $out += '    }'
    $out += '    It ''Given "Hello" and "PowerShell", Should Return "Hello PowerShell"'' {'
    $out += '        $result = & .\{0}.ps1 -MandatoryParameter ''Hello'' -OptionalParameter ''PowerShell''' -f $FunctionName
    $out += '        $result | Should -Be ''Hello PowerShell'''
    $out += '    }'
    $out += '    AfterEach {'
    $out += '    }'
    $out += '}'
    $out += 'AfterAll {'
    $out += '}'
    $out
}

function Get-ModuleFileContent([ScriptRepository]$ScriptRepository, [String]$Name, [switch]$AllScripts) {
    $out = @()
    if ($AllScripts) {
        $scriptsToLoad = $ScriptRepository.GetLatestVersions()
    }
    else {
        $scriptsToLoad = $ScriptRepository.GetAllScripts()
    }
    foreach ($script in $scriptsToLoad) {
        $out += Get-Function -ScriptRepository $ScriptRepository -Script $script -AllScripts:$AllScripts
    }
    if ($ScriptRepository.GetExposedFunctions()) {
        if ($AllScripts) {
            $exposeAliases = $ScriptRepository.GetAliases() -join "', '"
            $exposeFunctions = $ScriptRepository.GetExposedFunctions() -join "', '"
            $out += "Export-ModuleMember ```n    -Alias '{0}' ```n    -Function '{1}'" -f $exposeAliases, $exposeFunctions
        }
        else {
            $exposeFunctions = (@($ScriptRepository.GetAliases() + $ScriptRepository.GetVariants()) | Sort-Object) -join "', '"
            $out += "Export-ModuleMember ```n    -Function '{0}'" -f $exposeFunctions
        }
        $out
    }
    else {
        $out = $null
    }
}

# -------------------------------------------------------------------------------------------------------------------

class Script {
    [Boolean]$IsExposed
    [System.IO.FileSystemInfo]$File
    [String]$Name
    [String]$Alias
    [String]$Verb
    [String]$Action
    [Nullable[int]]$Version
    [String]$Variant
    [String[]]$Content

    Script([System.IO.FileSystemInfo]$file, [string]$name, [string]$verb, [string]$action, [int]$version) {
        $this.IsExposed = $true
        $this.File = $file
        $this.Name = $name
        $this.Alias = "$verb-$action"
        $this.Verb = $verb
        $this.Action = $action
        $this.Version = $version
        $this.Content = Get-Content -Path $file
    }

    Script([System.IO.FileSystemInfo]$file, [string]$name, [string]$verb, [string]$action, [string]$variant) {
        $this.IsExposed = $true
        $this.File = $file
        $this.Name = $name
        $this.Alias = $name
        $this.Verb = $verb
        $this.Action = $action
        $this.Variant = $variant
        $this.Content = Get-Content -Path $file
    }

    Script([System.IO.FileSystemInfo]$file, [string]$name, [string]$verb, [string]$action) {
        $this.IsExposed = $false
        $this.File = $file
        $this.Name = $name
        $this.Alias = $name
        $this.Verb = $verb
        $this.Action = $action
        $this.Content = Get-Content -Path $file
    }
}

class ScriptRepository {
    hidden [ordered]$_files = @{}

    Add([Script]$script) {
        $this._files.Add($script.File, $script)
    }

    [Script[]] GetAllScripts() {
        return $this._files.Values | Sort-Object -Property Name
    }

    [Script[]] GetLatestVersions() {
        return $this._files.Values | Where-Object { $_.IsExposed } | Sort-Object -Property Version -Descending | Sort-Object -Property Alias -Unique
    }

    [String[]] GetAliases() {
        return $this.GetLatestVersions() | Where-Object { $null -ne $_.Version } | Select-Object -ExpandProperty Alias
    }

    [String[]] GetVariants() {
        return $this._files.Values | Where-Object { $null -ne $_.Variant } | Select-Object -ExpandProperty Name
    }

    [String[]] GetAllFunctions() {
        return $this._files.Values | Sort-Object -Property Name | Select-Object -ExpandProperty Name
    }

    [String[]] GetExposedFunctions() {
        return $this._files.Values | Where-Object { $_.IsExposed } | Sort-Object -Property Name | Select-Object -ExpandProperty Name
    }
}

# -------------------------------------------------------------------------------------------------------------------

$functions = @{
    'Write-ScriptProcess' = @'
# -------------------------------------------------------------------------------------------------------------------
# quips » Write-ScriptProcess   |   https://github.com/noalt/quips                    AUTOGENERATED   |   DO NOT EDIT
# -------------------------------------------------------------------------------------------------------------------
[CmdletBinding(PositionalBinding = $false)]
param (
    [Parameter(Mandatory)]
    $Invocation
)
if ($Invocation.MyCommand.Module) {
    $functionName = $Invocation.MyCommand.Name
    $functionCall = $Invocation.MyCommand.Name
}
else {
    $functionName = $Invocation.MyCommand.Name.Replace('.ps1', '')
    $functionCall = '& .\{0} ' -f $Invocation.MyCommand.Name
}

$commonParameters = @{
    Confirm             = $null
    Debug               = $null
    ErrorAction         = $null
    ErrorVariable       = $null
    Force               = $null
    InformationAction   = $null
    InformationVariable = $null
    OutBuffer           = $null
    OutVariable         = $null
    PipelineVariable    = $null
    Verbose             = $null
    WarningAction       = $null
    WarningVariable     = $null
    WhatIf              = $null
}

$normalParameters = @()
foreach ($key in $Invocation.BoundParameters.Keys) {
    $value = $Invocation.BoundParameters[$key]
    if ($commonParameters.ContainsKey($key)) {
        if ($value -is [System.Management.Automation.SwitchParameter]) {
            $commonParameters[$key] = "-$key "
        }
        elseif ($value -is [Int32]) {
            $commonParameters[$key] = "-$key $value "
        }
        else {
            $commonParameters[$key] = "-$key '$value' "
        }
    }
    else {
        if ($value -is [String]) {
            $normalParameters += "$key = '$value'"
        }
        elseif ($value -is [Array]) {
            $normalParameters += "$key = @( '$($value -join '', '')' )"
        }
        elseif ($value -is [System.Management.Automation.SwitchParameter]) {
            $normalParameters += "$key = `$$value"
        }
        else {
            $normalParameters += "$key = $value"
        }
    }
}

$commonOutput = @()
foreach ($key in $commonParameters.Keys | Sort-Object) {
    $commonOutput += $commonParameters[$key]
}

$indent = '         '
if ($normalParameters.Length -gt 0) {
    $functionSplat = "$($functionName.Replace('-','').Replace('_',''))Splat"
    $normalSplat = "`$$functionSplat = @{`n$indent  $($normalParameters -join "`n  $indent")`n$indent}`n$indent"
    $functionSplatVariable = " @$functionSplat"
}
else {
    $normalSplat = ''
    $functionSplatVariable = ''
}
if (@($commonOutput | Where-Object { $_ -ne $null }).Count -gt 0) {
    Write-Verbose -Message ("{0}{1}{2} {3}" -f $normalSplat, $functionCall, $functionSplatVariable, ($commonOutput -join ''))
}
else {
    Write-Verbose -Message ("{0}{1}{2}" -f $normalSplat, $functionCall, $functionSplatVariable)
}
'@
}

# -------------------------------------------------------------------------------------------------------------------

Export-ModuleMember -Function 'Build-QuipsModule', 'Invoke-QuipsScriptAnalyzer', 'New-QuipsScript'

Initialize-Module
