# VMware Tools must for some reason be reinstalled in the context of the local logged on user at first boot
# or does it?  Testing without
# New-ItemProperty -Force -Path Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce -Name "ReinstallVMTools" -Value "msiexec.exe /f ""{01767101-A688-4A95-9C83-6DED9EB6735D}"" reboot=r" -PropertyType ExpandString

Function Out-Log {
    [CmdletBinding()]
    [Alias("ol")]
    Param (
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



Try {
    ol -m "............................................."
    ol -m "..  Start running 'ConfigRunOnce.ps1'  .."
    ol -m "............................................."

    # Configuring winrm over https at first boot
    $NewItemPropParams = @{
        'Path'='Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        'Name'='WinRMoverHTTPS'
        'Value'='powershell.exe -ExecutionPolicy bypass -File C:\Temp\ConfigureWinRM-https.ps1'
        'PropertyType'='ExpandString'
        'Force'=$True
        'ErrorAction'='Stop'
    } 
    New-ItemProperty @NewItemPropParams

}
Catch {
    ol -m "............................................."
    ol -m "..  Failed running 'ConfigRunOnce.ps1'  .."
    ol -m "............................................."
    $Failed = $True
    $PSCmdlet.ThrowTerminatingError($_)
}
Finally {
    If (-not $Failed) {
        ol -m "............................................."
        ol -m "..  Finshed running 'ConfigRunOnce.ps1' .."
        ol -m "............................................."
    }
}
