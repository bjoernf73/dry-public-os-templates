[CmdletBinding()]
param (
    [System.IO.FileInfo]$ConfigFile
) 

# Functions
Function Get-RandomHex {
    [CmdletBinding()]   
    param ([int]$Length)

    $Hex = '0123456789ABCDEF'
    [string]$Return = $null
    For ($i=1;$i -le $length;$i++)     {
        $Return += $Hex.Substring((Get-Random -Minimum 0 -Maximum 16),1)
    }
    Return $Return
}

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
    ol -m "..  Start running 'ConfigPostReboot.ps1'   .."
    ol -m "............................................."
    # configure SSH daemon (sshd)
    If ($Config.adm_interfaces.sshd.enable -eq $True) {
        
        ol -m "Instructed to enable OpenSSH Server for remote management"
        # make sure OpenSSH Server is installed
        Remove-Variable -Name OnlineCapability -ErrorAction SilentlyContinue
        $OnlineCapability = Get-WindowsCapability -Name "OpenSSH.Server*" -Online -ErrorAction Stop
       
        If ($OnlineCapability.State -ne 'Installed') {
            ol -m "Capbility OpenSSH Server found, but it's not installed. Trying to install"
            Try {
                $OnlineCapability | Add-WindowsCapability -Online -ErrorAction Stop
                ol -m "Successfully installed OpenSSH Server"
            }
            Catch {
                ol -t 2 -m "Failed to install OpenSSH Server"
            }
            
        }
        ElseIf ($OnlineCapability.State -eq 'Installed') {
            ol -m "OpenSSH Server is already installed."
        }
        Else {
            ol -t 2 -m "Unknown state for OpenSSH Server: '$($OnlineCapability.State)'"
        }
        
        
        Start-Sleep -Seconds 5
        # Start Service
        ol -m "Trying to start OpenSSH Server service (sshd)"
        Try {
            ol -m "Trying to start OpenSSH Server"
            Start-Service sshd -ErrorAction Stop
            ol -m "Successfully started SSHd"
        }
        Catch {
            ol -t 2 -m "Failed to start SSHd"
        }
        
        Start-Sleep -Seconds 5
        # configure the server
        ol -m "Testing key 'OpenSSH'"
        If (-not (Test-Path -Path "HKLM:\SOFTWARE\OpenSSH" -ErrorAction SilentlyContinue )) 
        {
            ol -m "Key 'OpenSSH' did not exist, creating it"
            Try {
                New-Item -Path "HKLM:\SOFTWARE" -Name "OpenSSH"
                ol -m "Successfully created key 'OpenSSH'"
            }
            Catch {
                ol -t 2 -m "Failed creating key 'OpenSSH'"
            }
        }
        Try {
            ol -m "Trying to set DefaultShell for OpenSSH"
            New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force

            ol -m "Trying to set Startup type for OpenSSH"
            Set-Service -Name sshd -StartupType Automatic -ErrorAction Stop -Confirm:$false

            ol -m "OpenSSH Successfully configured"

            $SSHD = Get-Service sshd
            If ($SSHD.Status -eq 'Running') {
                ol -m "Success - OpenSSH Service is up'n'running"
            }
            Else {
                ol -t 2 -m "OpenSSH Service NOT running :("
            }
        }
        Catch {
            ol -t 2 -m "Failed some configurations of OpenSSH service"
        }
        
    }
}
Catch {
    ol -m "............................................."
    ol -m "..  Failed running 'ConfigPostReboot.ps1'  .."
    ol -m "............................................."
    $Failed = $True
    $PSCmdlet.ThrowTerminatingError($_)
}
Finally {
    If (-not $Failed) {
        ol -m "............................................."
        ol -m "..  Finshed running 'ConfigPostReboot.ps1' .."
        ol -m "............................................."
    }
}

