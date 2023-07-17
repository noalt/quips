# -------------------------------------------------------------------------------------------------------------------
# quips 0.2   |   https://github.com/noalt/quips
# -------------------------------------------------------------------------------------------------------------------
Set-StrictMode -Version Latest

class Script {
    [System.IO.FileSystemInfo]$File
    [string]$Name
    [string]$Alias
    [string]$Verb
    [string]$Action
    [Nullable[int]]$Version
    [string]$Variant
    [string[]]$Content

    Script([System.IO.FileSystemInfo]$file, [string]$name, [string]$verb, [string]$action, [int]$version) {
        $this.File = $file
        $this.Name = $name
        $this.Alias = "$verb-$action"
        $this.Verb = $verb
        $this.Action = $action
        $this.Version = $version
        $this.Content = Get-Content -Path $file
    }

    Script([System.IO.FileSystemInfo]$file, [string]$name, [string]$verb, [string]$action, [string]$variant) {
        $this.File = $file
        $this.Name = $name
        $this.Alias = $name
        $this.Verb = $verb
        $this.Action = $action
        $this.Variant = $variant
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
        return $this._files.Values | Sort-Object -Property Version -Descending | Sort-Object -Property Alias -Unique
    }

    [string[]] GetAliases() {
        return $this.GetLatestVersions() | Where-Object { $null -ne $_.Version } | Select-Object -ExpandProperty Alias
    }

    [string[]] GetFunctions() {
        return $this._files.Values | Sort-Object -Property Name | Select-Object -ExpandProperty Name
    }
}

function Build-QuipsModule {
    <#
    .SYNOPSIS

    .DESCRIPTION

    .EXAMPLE

    .NOTES

    #>
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -Path $_ -PathType Container }, ErrorMessage = 'ScriptsPath is not a valid directory.')]
        [string]$ScriptsPath,

        [ValidateScript({ $_.ToLowerInvariant() -ne 'quips.psm1' }, ErrorMessage = '"quips.psm1" is not a valid name.')]
        [string]$Name,

        [switch]$StrictMode
    )
    begin {
        if ([String]::IsNullOrEmpty($Name)) {
            $PSBoundParameters.Add("Name", 'quips-scripts.psm1')
            $Name = 'quips-scripts.psm1'
        }
    }
    process {
        $scriptRepository = InitializeScriptRepository -Path "$ScriptsPath"
        WriteModuleFile -ScriptRepository $scriptRepository
    }
    end {
    }
}

function InitializeScriptRepository([string]$Path) {
    $output = [ScriptRepository]::new()
    $scriptFiles = Get-ChildItem -Path "$Path" -Filter '*.ps1'
    foreach ($file in $scriptFiles) {
        if ($file.Name -match "(?<Verb>\w+)-(?<Action>\w+)_(?<Version>[0-9][0-9]).ps1") {
            $name = "{0}-{1}_{2}" -f $matches["Verb"], $matches["Action"], $matches["Version"]
            $script = [Script]::new($file, $name, $matches["Verb"], $matches["Action"], [int]$matches["Version"])
            $output.Add($script)
        }
        elseif ($file.Name -match "(?<Verb>\w+)-(?<Action>\w+)_(?<Variant>\w+).ps1") {
            $name = "{0}-{1}_{2}" -f $matches["Verb"], $matches["Action"], $matches["Variant"]
            $script = [Script]::new($file, $name, $matches["Verb"], $matches["Action"], $matches["Variant"])
            $output.Add($script)
        }
        else {
            Write-Warning ("Script File `"{0}`" does not match any known patterns." -f $file.FullName)
        }
    }
    $output
}

function GetFunction([ScriptRepository]$ScriptRepository, [Script]$Script) {
    $latestVersions = $ScriptRepository.GetLatestVersions()
    $functions = $ScriptRepository.GetFunctions()

    $output = @()
    $function = $Script.Name
    $output += ("function $function {")
    foreach ($line in $Script.Content) {
        # Add Alias attribute to the latest version of the script found:
        if ($line.Trim().StartsWith('[CmdletBinding')) {
            if ($null -ne $Script.Version -and $latestVersions.Contains($Script)) {
                $output += "    [Alias('{0}')]" -f $Script.Alias
            }
        }
        # Replace "& .\Verb-Action.ps1" with calls to "Verb-Action":
        if ($line -match "& .\\(?<Verb>\w+)-(?<Action>\w+)_(?<Version>[0-9][0-9]).ps1") {
            $cmdlet = "{0}-{1}_{2}" -f $matches["Verb"], $matches["Action"], $matches["Version"]
            if (-not $functions.Contains("$cmdlet")) {
                $message = "{0}.ps1 » Referenced cmdlet `"{1}.ps1`" cannot be found in directory `"{2}`"." -f $Script.Name, $cmdlet, $ScriptsPath
                Write-Error -Message $message -ErrorAction Stop
            }
            $line = $line.Replace("& .\$cmdlet.ps1", "$cmdlet")
        }
        elseif ($line -match "& .\\(?<Verb>\w+)-(?<Action>\w+)_(?<Variant>\w+).ps1") {
            $cmdlet = "{0}-{1}_{2}" -f $matches["Verb"], $matches["Action"], $matches["Variant"]
            if (-not $functions.Contains("$cmdlet")) {
                $message = "{0}.ps1 » Referenced cmdlet `"{1}.ps1`" cannot be found in directory `"{2}`"." -f $Script.Name, $cmdlet, $ScriptsPath
                Write-Error -Message $message -ErrorAction Stop
            }
            $line = $line.Replace("& .\$cmdlet.ps1", "$cmdlet")
        }
        # Add calls to Write-QuipsBegin/Process and optionally Set-StrictMode:
        if ($line.Trim() -eq 'begin {') {
            $output += "    $line"
            if ($StrictMode) {
                $output += "        Set-StrictMode -Version Latest"
            }
            $output += "        Write-QuipsBegin -Function '$function'"
        }
        elseif ($line.Trim() -eq 'process {') {
            $output += "    $line"
            $output += "        Write-QuipsProcess -Function '$function' -Parameters `$PSBoundParameters"
        }
        elseif ($line.Trim() -eq '') {
            $output += ''
        }
        else {
            $output += "    $line"
        }
    }
    $output += "}`n"
    $output
}

function WriteModuleFile([ScriptRepository]$ScriptRepository) {
    $output = @()
    foreach ($script in $ScriptRepository.GetAllScripts()) {
        $function = GetFunction -ScriptRepository $ScriptRepository -Script $script
        $output += $function
    }
    $output += "$WriteQuipsBegin`n"
    $output += "$WriteQuipsProcess`n"
    $exposeAliases = $ScriptRepository.GetAliases() -join "', '"
    $exposeFunctions = $ScriptRepository.GetFunctions() -join "', '"
    $output += "Export-ModuleMember ```n    -Alias '$exposeAliases' ```n    -Function '$exposeFunctions'"
    $output | Out-File -FilePath (Join-Path -Path "$PSScriptRoot" -ChildPath "$Name") -Encoding utf8BOM
}

$WriteQuipsBegin = @'
function Write-QuipsBegin {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory)]
        [string]$Function
    )
    Write-Verbose -Message "quips » $Function"
}
'@

$WriteQuipsProcess = @'
function Write-QuipsProcess {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory)]
        [ValidatePattern('\w-\w')]
        [string]$Function,

        [Parameter(Mandatory)]
        [hashtable]$Parameters
    )
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
    foreach ($key in $Parameters.Keys) {
        $value = $Parameters[$key]
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

    $indent = '           '
    if ($normalParameters.Length -gt 0) {
        $functionSplat = "$($Function.Replace('-','').Replace('_',''))Splat"
        $normalSplat = "`$$functionSplat = @{`n  $indent$($normalParameters -join "`n  $indent")`n$indent}`n$indent"
        $functionSplatVariable = " @$functionSplat"
    }
    else {
        $normalSplat = ''
        $functionSplatVariable = ''
    }
    if (@($commonOutput | Where-Object { $_ -ne $null }).Count -gt 0) {
        Write-Verbose -Message ("  {0}{1}{2} ```n  $indent{3}" -f $normalSplat, $Function, $functionSplatVariable, ($commonOutput -join ''))
    }
    else {
        Write-Verbose -Message ("  {0}{1}{2}" -f $normalSplat, $Function, $functionSplatVariable)
    }
}
'@

Export-ModuleMember -Function 'Build-QuipsModule'
