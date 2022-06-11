[CmdletBinding()]
param (
    [System.IO.FileInfo]$ConfigFile
) 

Function Start-ElevatedSession {
    param (
        $wdir
    )
    If (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) 
    {
         If ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) 
         {
              Start-Process -FilePath PowerShell.exe -Verb Runas -WorkingDirectory $wdir -ArgumentList @('-file',"$PSCommandPath","-SelfElevated","-Configfile $Configfile")
         }
    }
}

Function Move-DVDDrives {
    param (
    )
    ol -t 6 -m "Reassigning driveletters for DVD Drives"
    # Only psychopaths have more than 8 DVD Drives. I mean, really!
    $DrivesArray = @('Z:','Y:','X:','W:','V:','U:','T:','S:')
    $Count = -1

    # Get all DVD Drives
    $DVDDrives = Get-WmiObject win32_volume | 
    Where-Object { 
        $_.DriveType -eq 5 
    }
    ol -t 6 -m "Found $($DVDDrives.Count) DVD Drives"
    
    # Loop and reassign
    $DVDDrives.Foreach({
        $Count++
        $NewDriveLetter = $DrivesArray[$Count]
        ol -t 6 -m "Reassigning DVD Drive # $($Count): $($_.DriveLetter) ==> $NewDriveLetter"
        Try {
            $_.DriveLetter = "$NewDriveLetter"
            $_.put()
            ol -t 6 -m "Successfully reassigned DVD Drive. New DriveLetter is $NewDriveLetter"
        }
        Catch {
            $PSCmdlet.ThrowTerminatingError($_)
        }
        
    })
}


Function Is-Admin {
    [CmdletBinding()]   
    param ()
    (New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

Function Out-Log {
    [CmdletBinding()]
    [Alias("ol")]
    param (
        [Alias("m")]
        [Parameter(Mandatory,Position=0)]
        [AllowEmptyString()]
        [string]$Message,

        [Alias("t")]
        [Parameter(Position=1)]
        [int]$Type = 6,

        [Alias("cs")]
        [Parameter(HelpMessage="Normally 1, the calling function. However, If message is converted by a proxy function, raise by 1")]
        [int]$Callstacklevel = 1

    )

    Try {
        # Get the calling cmdlet, script and line number
        $Caller = (Get-PSCallStack)[$callstacklevel]
        [string]$location = ($Caller.location).Replace(' line ','')
        [string]$LocationString = "[$Location $(get-date -Format HH:mm:ss)]"
    
        Switch ($Type) {
            1 {
                Write-Warning -Message "WARNING: $Message [$LocationString]"
            }
            2 {
                Write-Output -InputObject "ERROR:   $Message [$LocationString]"
                Write-Error -Message "ERROR:   $Message" -ErrorAction Stop
            }
            Default {
                Write-Output -InputObject "INFO:    $Message [$LocationString]"
            }
        }
    }
    Catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }  
} 


# check if running as member of 'Administrators' or not
If (Is-Admin) {
    ol -m " Running script as Administrator - Continues."
}
Else {
    Write-Error "Not Administrator - re-run in elevated session" -ErrorAction Stop
}

# Set global values, so that -Verbose and -Debug works down the stack 
$GLOBAL:VerbosePreference = $PSCmdlet.GetVariableValue('VerbosePreference')
$GLOBAL:DebugPreference = $PSCmdlet.GetVariableValue('DebugPreference')
$GLOBAL:ErrorActionPreference = 'Stop'

# -Debug sets $DebugPreference = 'Inquire' - we want it to 'Continue'. 
# Since this script is already running, and it has already inherited the 
# GLOBAL scope at start of script, we need to set it for the SCRIPT
# scope as well
If ($GLOBAL:DebugPreference -eq 'Inquire') { 
    $GLOBAL:DebugPreference = 'Continue' 
    $SCRIPT:DebugPreference = 'Continue'
}

# Get the condiguration
$Config = Get-Content $Configfile -Raw -ErrorAction Stop | 
ConvertFrom-Json -ErrorAction 'Stop'

Try {
    ol -m "............................................."
    ol -m "..  Start running 'ConfigLast.ps1'   .."
    ol -m "............................................."

    # Unless instructed NOT to reassign DVD Drives, I will do it
    If (-not ($Config.no_dvddrive_reassign -eq $True)) {
        ol -m "You did not specify `$Config.no_dvddrive_reassign, so I will reassign drive letters of DVD Drives"
        Move-DVDDrives
    }
    Else {
        ol -m "You specified `$Config.no_dvddrive_reassign, so I will NOT reassign drive letters of DVD Drives"
    }
}
Catch {
    ol -m "............................................."
    ol -m "..  Failed running 'ConfigLast.ps1'  .."
    ol -m "............................................."
    $Failed = $True
    $PSCmdlet.ThrowTerminatingError($_)
}
Finally {
    If (-not $Failed) {
        ol -m "............................................."
        ol -m "..  Finshed running 'ConfigLast.ps1' .."
        ol -m "............................................."
    }
}

