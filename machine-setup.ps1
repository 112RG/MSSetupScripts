[cmdletbinding()]
param(
    [Parameter(Position=0)]
    [bool]$runscript = $true
)

function New-ObjectFromProperties{
    [cmdletbinding()]
    param(
        [Parameter(Position=0)]
        [System.Collections.IDictionary]$properties
    )
    process{
        if($properties -ne $null){
            # create and return the object
            New-Object -TypeName psobject -Property $properties
        }
    }
}
set-alias -Name newobj -Value New-ObjectFromProperties   

$global:machinesetupconfig = @{
    MachineSetupConfigFolder = (Join-Path $env:temp 'MachineSetup')
    MachineSetupAppsFolder = (Join-Path $env:temp 'MachineSetup\apps')
    BaseChocoPackages = @(
        'git.install',
        'googlechrome',
        'firefox',
        'notepadplusplus.install',
        'microsoft-windows-terminal'
        '7zip.install'
    )
<#     BaseRepos = @(
        (newobj @{
                SSH = 'git@github.com:sayedihashimi/sayed-tools.git'
                HTTPS = 'https://github.com/sayedihashimi/sayed-tools.git' })

        (newobj @{
                SSH = 'git@github.com:sayedihashimi/pshelpers.git'
                HTTPS = 'https://github.com/sayedihashimi/pshelpers.git' }),

        (newobj @{
                SSH = 'git@github.com:dahlbyk/posh-git.git'
                HTTPS = 'git@github.com:dahlbyk/posh-git.git' })
    ) #>
    SecondaryChocoPackages = @(
        'fiddler',
        'discord-canary',
        'steam-client',
        'vscode-insiders',
        'greenshot',
        'vlc',
        'zoom',
        'winscp',
        'openjdk11',
        'bitwarden',
        'foobar2000',
        'qbittorrent-enhanced',
        'windirstat',
        'obsidian'
        'everything'
    )
    ApplicationList = @(
	    "Microsoft.BingFinance"
	    "Microsoft.3DBuilder"
	    "Microsoft.BingFinance"
	    "Microsoft.BingNews"
	    "Microsoft.BingSports"
	    "Microsoft.BingWeather"
	    "Microsoft.CommsPhone"
	    "Microsoft.Getstarted"
	    "Microsoft.WindowsMaps"
	    "*MarchofEmpires*"
	    "Microsoft.GetHelp"
	    "Microsoft.Messaging"
	    "*Minecraft*"
	    "Microsoft.MicrosoftOfficeHub"
	    "Microsoft.OneConnect"
	    "Microsoft.WindowsPhone"
	    "Microsoft.WindowsSoundRecorder"
	    "*Solitaire*"
	    "Microsoft.MicrosoftStickyNotes"
	    "Microsoft.Office.Sway"
	    "Microsoft.XboxApp"
	    "Microsoft.XboxIdentityProvider"
	    "Microsoft.ZuneMusic"
	    "Microsoft.ZuneVideo"
	    "Microsoft.NetworkSpeedTest"
	    "Microsoft.FreshPaint"
	    "Microsoft.Print3D"
	    "*Autodesk*"
	    "*BubbleWitch*"
        "king.com*"
        "G5*"
	    "*Dell*"
	    "*Facebook*"
	    "*Keeper*"
	    "*Netflix*"
	    "*Twitter*"
	    "*Plex*"
	    "*.Duolingo-LearnLanguagesforFree"
	    "*.EclipseManager"
	    "ActiproSoftwareLLC.562882FEEB491" # Code Writer
	    "*.AdobePhotoshopExpress"
    )
    #WallpaperUrl = 'https://raw.githubusercontent.com/sayedihashimi/sayed-tools/master/powershell/checking-out-the-view.jpg'
}

function InstallPrompt{
    PowerShellGet\Install-Module -Name PSReadLine -AllowPrerelease -Scope CurrentUser -Force -SkipPublisherCheck
    PowerShellGet\Install-Module posh-git -Scope CurrentUser -AllowPrerelease -Force
    PowerShellGet\Install-Module posh-git -Scope CurrentUser
    PowerShellGet\Install-Module oh-my-posh -Scope CurrentUser
}

#// 'https://dl.dropboxusercontent.com/u/40134810/wallpaper/checking-out-the-view.jpg'
function InternalGet-ScriptDirectory{
    split-path (((Get-Variable MyInvocation -Scope 1).Value).MyCommand.Path)
}

$scriptDir = ((InternalGet-ScriptDirectory) + "\")

<#
.SYNOPSIS
    Can be used to convert a relative path (i.e. .\project.proj) to a full path.
#>
function Get-Fullpath{
    [cmdletbinding()]
    param(
        [Parameter(
            Mandatory=$true,
            ValueFromPipeline = $true)]
        $path,

        $workingDir = ($pwd)
    )
    process{
        $fullPath = $path
        $oldPwd = $pwd

        Push-Location
        Set-Location $workingDir
        [Environment]::CurrentDirectory = $pwd
        $fullPath = ([System.IO.Path]::GetFullPath($path))
        
        Pop-Location
        [Environment]::CurrentDirectory = $oldPwd

        return $fullPath
    }
}

if([string]::IsNullOrWhiteSpace($Global:dropboxhome)){
    if(-not ([string]::IsNullOrWhiteSpace($env:dropboxhome))){
        $Global:dropboxhome = $env:dropboxhome
    }

    if([string]::IsNullOrWhiteSpace($Global:dropboxhome)){
        $Global:dropboxhome = 'c:\data\dropbox'
    }
}


function Add-Path{
    [cmdletbinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [string[]]$pathToAdd,

        [System.EnvironmentVariableTarget]$envTarget = [System.EnvironmentVariableTarget]::Process,

        [bool]$alsoAddToProcess = $true
    )
    process{
        [string]$existingPath = ([System.Environment]::GetEnvironmentVariable('path',$envTarget))
        
        [string]$existingPathLower = $existingPath.ToLowerInvariant()
        
        foreach($path in $pathToAdd){
            if(-not ([string]::IsNullOrWhiteSpace($path))){
                [string]$fullpath = (Get-Fullpath -path $path)
                if(test-path -path $fullpath){
                    $trimmed = $fullpath.TrimEnd('\')
                    
                    # don't add if it's already included
                    if(-not ($existingPathLower.Contains($trimmed.ToLowerInvariant()))){
                        $newPath = ('{0};{1}' -f $existingPath,$trimmed)
                        [System.Environment]::SetEnvironmentVariable('path',$newPath,$envTarget)
                    }

                    if( ($alsoAddToProcess -eq $true) -and ($envTarget -ne [System.EnvironmentVariableTarget]::Process) ){
                        [string]$oldprocesspath = [System.Environment]::GetEnvironmentVariable('path',[System.EnvironmentVariableTarget]::Process)
                        $oldprocesspathlower = $oldprocesspath.ToLowerInvariant()
                        if(-not $oldprocesspathlower.Contains($trimmed.ToLowerInvariant())){
                            $newprocesspath = ('{0};{1}' -f $existingPath,$trimmed)
                            [System.Environment]::SetEnvironmentVariable('path',$newprocesspath,[System.EnvironmentVariableTarget]::Process)
                        }
                    }
                }
                else{
                    'Not adding to path because the path was not found [{0}], fullpath=[{1}]' -f $path,$fullpath | Write-Warning
                }
            }
        }
    }
}

function Get7ZipPath{
    [cmdletbinding()]
    param()
    process{
        (join-path $env:ProgramFiles '7-Zip\7z.exe')
    }
}

function EnsureFolderExists{
    [cmdletbinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [string[]]$path
    )
    process{
        foreach($p in $path){
            if(-not [string]::IsNullOrWhiteSpace($p) -and (-not (Test-Path $p))){
                New-Item -Path $p -ItemType Directory
            }
        }
    }
}

function IsCommandAvailable{
    [cmdletbinding()]
    param(
        [Parameter(Position=0)]
        $command
    )
    process{
        $foundcmd = (get-command choco.exe -ErrorAction SilentlyContinue)
        [bool]$isinstalled = ($foundcmd -ne $null)

        # return the value
        $isinstalled
    }
}

function GetCommandFullpath{
    [cmdletbinding()]
    param(
        [Parameter(Position=0)]
        [string]$command
    )
    process{
        (get-command $command).Source
    }
}

function InstallChoclatey{
    [cmdletbinding()]
    param()
    process{
        iwr https://chocolatey.org/install.ps1 -UseBasicParsing | iex
        # restart the console to get the changes
        RestartThisScript
    }
}

function RestartThisScript{
    [cmdletbinding()]
    param()
    process{
        @'
************************************
Restarting the script
************************************
'@ | Write-Output

        powershell.exe -NoExit -ExecutionPolicy RemoteSigned -File $($MyInvocation.ScriptName)
        break
    }
}

function InstallWithChoco{
    [cmdletbinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [array]$packages
    )
    process{
        foreach($pkg in $packages){
            choco install $pkg -y
        }
    }
}

function RemoveApps{
    [cmdletbinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [array]$apps
    )
    process{
        foreach($app in $apps){
            Write-Output "Trying to remove $app"
	        Get-AppxPackage $app -AllUsers | Remove-AppxPackage
	        Get-AppXProvisionedPackage -Online | Where DisplayName -like $app | Remove-AppxProvisionedPackage -Online
        }
    }
}

function InstallBaseApps{
    [cmdletbinding()]
    param()
    process{
        [string]$pkgsbefore = ((choco list --local-only) -join ';')
        $Global:machinesetupconfig.BaseChocoPackages | InstallWithChoco
        [string]$pkgsafter = ((choco list --local-only) -join ';')
        
        if(-not ([string]::Equals($pkgsbefore,$pkgsafter,[System.StringComparison]::OrdinalIgnoreCase)) ){
            Add-Path -pathToAdd "$env:ProgramFiles\Git\bin" -envTarget User
            RestartThisScript
        }
    }
}

function InstallSecondaryApps{
    [cmdletbinding()]
    param()
    process{
        $Global:machinesetupconfig.SecondaryChocoPackages | InstallWithChoco

        EnsureFolderExists ($global:machinesetupconfig.MachineSetupAppsFolder)
        EnsureInstalled-MarkdownPad

        # TODO: Need to find a more generic way of doing this.
        $pathPartsToAdd = @(
            "$env:ProgramFiles\Git\bin"
            "${env:ProgramFiles(x86)}\Perforce"
            (Join-Path $Global:machinesetupconfig.MachineSetupAppsFolder 'markdownpad2-portable')
        )
        
        $pathPartsToAdd | %{
            $current = $_
            if(Test-Path $current){
                add-path -pathToAdd $current -envTarget User
            }
        }
    }
}

function ConfigureApps{
    [cmdletbinding()]
    param()
    process{
        ConfigureFirefox
    }
}


function IsRunningAsAdmin{
    [cmdletbinding()]
    param()
    process{
        [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
    }
}

function GetLocalFileFor{
    [cmdletbinding()]
    param(
        [Parameter(Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$downloadUrl,

        [Parameter(Position=1,Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$filename,

        [Parmeter(Postion=2)]
        [string]$downloadRootDir = $global:machinesetupconfig.MachineSetupConfigFolder
    )
    process{
        $expectedPath = (Join-Path $downloadRootDir $filename)
        
        if(-not (test-path $expectedPath)){
            # download the file
            EnsureFolderExists -path ([System.IO.Path]::GetDirectoryName($expectedPath)) | out-null            
            Invoke-WebRequest -Uri $downloadUrl -OutFile $expectedPath | out-null
        }

        if(-not (test-path $expectedPath)){
            throw ('Unable to download file from [{0}] to [{1}]' -f $downloadUrl, $expectedPath)
        }

        $expectedPath
    }
}

function ExtractRemoteZip{
    [cmdletbinding()]
    param(
        [Parameter(Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$downloadUrl,

        [Parameter(Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$filename,

        [Parmeter(Postion=2)]
        [string]$downloadRootDir = $global:machinesetupconfig.MachineSetupConfigFolder
    )
    process{
        $zippath = GetLocalFileFor -downloadUrl $downloadUrl -filename $filename
        $expectedFolderpath = (join-path -Path $downloadRootDir ('apps\{0}\' -f $filename))

        if(-not (test-path $expectedFolderpath)){
            EnsureFolderExists -path $expectedFolderpath | Write-Verbose
            # extract the folder to the directory
            & (Get7ZipPath) x -y "-o$expectedFolderpath" "$zippath" | Write-Verbose
        }        

        # return the path to the folder
        $expectedFolderpath
    }
}

function ExtractLocalZip{
    [cmdletbinding()]
    param(
        [Parameter(Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$filepath
    )
    process{
        $filename = [System.IO.Path]::GetFilename($filepath)
        #$zippath = GetLocalFileFor -downloadUrl $downloadUrl -filename $filename
        $expectedFolderpath = (join-path -Path ($global:machinesetupconfig.MachineSetupConfigFolder) ('apps\{0}\' -f $filename))

        if(-not (test-path $expectedFolderpath)){
            EnsureFolderExists -path $expectedFolderpath | Write-Verbose
            # extract the folder to the directory
            & (Get7ZipPath) x -y "-o$expectedFolderpath" "$filepath" | Write-Verbose
        }        

        # return the path to the folder
        $expectedFolderpath
    }
}

function CreateDummyFile{
    [cmdletbinding()]
    param(
        [string[]]$filepath
    )
    process{
        foreach($path in $filepath){            
            if( (-not ([string]::IsNullOrWhiteSpace($path)) ) -and (-not (Test-Path -Path $path)) ){
                EnsureFolderExists -path ([System.IO.Path]::GetDirectoryName($path));
                Set-Content -Value 'empty file' -Path $path
            }
        }
    }
}

function GetPinToTaskbarTool{
    [cmdletbinding()]
    param(
        [Parameter(Position=0)]
        [string]$downloadUrl = 'https://github.com/sayedihashimi/sayed-tools/raw/master/contrib/PinTo10v2.exe'
    )
    process{
        # see if the file has already been downloaded
        [string]$expectedPath = (join-path $global:machinesetupconfig.MachineSetupConfigFolder 'PinTo10v2.exe')
        if(-not (test-path $expectedPath)){
            'Downloading PinToTaskbar from [{0}] to [{1}]' -f $downloadUrl,$expectedPath | Write-Verbose
            # make sure the directory exists
            EnsureFolderExists -path ([System.IO.Path]::GetDirectoryName($expectedPath)) | write-verbose
            # download the file
            Invoke-WebRequest -Uri $downloadUrl -OutFile $expectedPath | write-verbose
        }

        if(-not (test-path $expectedPath)){
            $msg = 'Unable to download PinToTaskbar from [{0}] to [{1}]' -f $downloadUrl,$expectedPath
            throw $msg 
        }

        $expectedPath
    }
}

# https://connect.microsoft.com/PowerShell/feedback/details/1609288/pin-to-taskbar-no-longer-working-in-windows-10
function PinToTaskbar{
    [cmdletbinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [string[]]$pathtopin,

        [Parameter(Position=0)]
        [string]$pinTov2 = (GetPinToTaskbarTool)
    )
    process{        
        if(-not (Test-Path $pinTov2)){
            'PinTo10v2.exe not found at [{0}]' -f $pinTov2 | Write-Error
            break
        }

        foreach($path in $pathtopin){
            'Pin to taskbar with command: [{0} /pinsm {1}]' -f $pinTov2,$path | Write-Verbose
            & $pinTov2 /pintb $path
        }
    }
}

function ConfigureTaskBar{
    [cmdletbinding()]
    param(
        [Parameter(Position=0)]
        [string]$configuretaskbarhasrunpath = (Join-Path $global:machinesetupconfig.MachineSetupConfigFolder 'configtaskbar.hasrun')
    )
    process{
        if(-not (Test-Path $configuretaskbarhasrunpath)){
            $itemstopin = @(
                "$env:ProgramFiles\Mozilla Firefox\firefox.exe"
                "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
                "$env:ProgramFiles\ConEmu\ConEmu64.exe"
            )

            foreach($pi in $itemstopin){
                if (test-path $pi) {
                    PinToTaskbar -pathtopin $pi
                }
            }

            CreateDummyFile -filepath $configuretaskbarhasrunpath
        }
    }
}

function ConfigureWindows{
    [cmdletbinding()]
    param()
    process{
        RunTask @(
            #{Enable-RemoteDesktop},
            # Show hidden files, Show protected OS files, Show file extensions
            {Set-WindowsExplorerOptions -EnableShowHiddenFilesFoldersDrives -EnableShowProtectedOSFiles -EnableShowFileExtensions},
            #--- File Explorer Settings ---
            #{$Global:machinesetupconfig.ApplicationList | RemoveApps},
            # will expand explorer to the actual folder you're in
            {Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneExpandToCurrentFolder -Value 1},
            #adds things back in your left pane like recycle bin
            {Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneShowAllFolders -Value 1},
            #opens PC to This PC, not quick access
            {Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Value 1},
            {powercfg.exe -SETACTIVE 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c},
            {powercfg.exe /Change monitor-timeout-ac 5},
            {powercfg.exe /Change standby-timeout-dc 0}
            #{AddFonts},
            #{DisableScreenSaver},
            #{
            #    $wppath = (GetLocalFileFor -downloadUrl $global:machinesetupconfig.WallpaperUrl -filename 'wp-view.jpg')
            #    Update-wallpaper -path $wppath -Style 'Fit'
           # },

            #{InstallPaintDotNet}   
        )

        # TODO: update mouse pointer speed

        # TODO: update mouse pointer to show when CTRL is clicked
    }
}

# http://www.getpaint.net/doc/latest/UnattendedInstallation.html


function RunTask{
    [cmdletbinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [ScriptBlock[]]$task
    )
    process{
        foreach($t in $task){
            if($t -eq $null){
                continue
            }

            try{
                . $t
            }
            catch{
                'Error in task execution of [{0}]' -f $t | Write-Warning
            }
        }
    }
}

function ConfigureMachine{
    [cmdletbinding()]
    param(
        [Parameter(Position=0)]
        $codehome = $Global:codehome
    )
    process{
        # check to see that Choclatey is installed

        if(-not (IsCommandAvailable -command choco.exe)){
            InstallChoclatey
            #"`r`nERROR: Choclatey is not installed, install and rerun this script" | Write-Error
            #throw
        }

        EnsureFolderExists $codehome
        EnsureFolderExists ($global:machinesetupconfig.MachineSetupAppsFolder)
        ConfigureWindows
       # InstallBaseApps
        
        RunTask @(
            #{EnsurePhotoViewerRegkeyAdded},
            #{ConfigureTaskBar},

            #{ConfigureConsole},
            #{ConfigureGit},
            #{ConfigurePowershell},

            #{EnsureBaseReposCloned},
            #{LoadModules},
            #{InstallSecondaryApps}

            {ConfigureWindows}
            #{ConfigureVisualStudio},
            #{ConfigureApps}            
        )
    }
}


#########################################
# Begin script
#########################################
if($runscript -and (-not (IsRunningAsAdmin))) {
    'This script needs to be run as an administrator' | Write-Error
    throw
}

Push-Location
try{
    Set-Location $scriptDir
    if($runscript -eq $true){
        ConfigureMachine
    }
}
finally{
    Pop-Location
}

# TODO:
# Remove dependency on boxstarter
# Update firefox to not check default browser
# Update firefox to set google as default search
