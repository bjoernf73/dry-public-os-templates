[CmdletBinding()]
param (
    [string]$Configfile
)

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


    Function Install-WindowsUpdates {
        [CmdletBinding()]
        param(
            [array]$UpdateClassifications
        )

        $Session = New-Object -ComObject 'Microsoft.Update.Session'
        $Session.ClientApplicationID = 'Windows Update Installer'
        $UpdateSearcher = $Session.CreateUpdateSearcher()
        Write-Output "Searching for Windows updates ..."
        $SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
        $Updates = $SearchResult.Updates
        Write-Output "Found $($Updates.count) updates in search."
        $UpdatesToDownload = New-Object -ComObject 'Microsoft.Update.UpdateColl'

        if ($Updates.Count -gt 0) {
            $i = $Updates.Count - 1
            while ($i -ge 0) {
                $Update = $Updates.Item($i)
                $UpdateClassification = ($Update.Categories | Where-Object { $_.Type -eq 'UpdateClassification' }).Name
                if ($Null -eq $UpdateClassification) {
                    Write-Output "WARNING: Found no UpdateClassification for update '$($Update.Title)'"
                } else {
                    Write-Output "Update '$($Update.Title)' is of classification: '$UpdateClassification'"
                }
                if (($UpdateClassification -in $UpdateClassifications) -or ('all' -in $UpdateClassifications)) {
                    Write-Output "Adding update '$($Update.Title)' of classification '$UpdateClassification' to list"
                    if (!($Update.EulaAccepted)) {
                        $Update.AcceptEula()
                    }
                    $UpdatesToDownload.Add($Update) | Out-Null
                    # break
                }
                else {
                    Write-Output "Update '$($Update.Title)' of classification '$UpdateClassification' is not in specified classifications list"
                }
                Remove-Variable -name UpdateClassification -ErrorAction SilentlyContinue
                $i--
            }
        }
    
        If ($UpdatesToDownload.Count -eq 0) {
            Write-Output "No Windows updates of specified classifications found."
        } 
        Else {
            Write-Output "Downloading $($UpdatesToDownload.Count) Windows updates ..."
            $Downloader = $Session.CreateUpdateDownloader()
            $Downloader.Updates = $UpdatesToDownload
            $Downloader.Download()

            Write-Output "Installing Windows updates ..."
            $Installer = $Session.CreateUpdateInstaller()
            $Installer.Updates = $UpdatesToDownload
            $InstallationResult = $Installer.Install()

            Write-Output "Installation Result: $($InstallationResult.ResultCode)"
            Write-Output "Reboot Required: $($InstallationResult.RebootRequired)"
        }
    }

    Try {
        ol -m "............................................."
        ol -m "..  Start running 'ConfigUpdates.ps1'  .."
        ol -m "............................................."

        # Get the condiguration
        $Config = Get-Content $Configfile -Raw -ErrorAction Stop | 
        ConvertFrom-Json -ErrorAction 'Stop'

        if ($config.windows_update_classifications) {
            Install-WindowsUpdates -UpdateClassifications $config.windows_update_classifications
        }
    }
    Catch {
        ol -m "............................................."
        ol -m "..  Failed running 'ConfigUpdates.ps1'  .."
        ol -m "............................................."
        $Failed = $True
        $PSCmdlet.ThrowTerminatingError($_)
    }
    Finally {
        If (-not $Failed) {
            ol -m "............................................."
            ol -m "..  Finshed running 'ConfigUpdates.ps1' .."
            ol -m "............................................."
        }
    }