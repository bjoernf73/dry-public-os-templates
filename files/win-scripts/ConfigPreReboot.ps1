[CmdletBinding()]
Param (
    [System.IO.FileInfo]$ConfigFile
) 
# Set-ExecutionPolicy -executionpolicy RemoteSigned -Scope LocalMachine -Confirm:$False -Force

# Functions
Function Get-RandomHex {
    [CmdletBinding()]   
    Param ([int]$Length)

    $Hex = '0123456789ABCDEF'
    [string]$Return = $null
    For ($i=1;$i -le $length;$i++)     {
        $Return += $Hex.Substring((Get-Random -Minimum 0 -Maximum 16),1)
    }
    Return $Return
}

Function Start-ElevatedSession {
    [CmdletBinding()]
    Param (
        $wdir
    )
    If (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
         If ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
              Start-Process -FilePath PowerShell.exe -Verb Runas -WorkingDirectory $wdir -ArgumentList @('-file',"$PSCommandPath","-SelfElevated","-Configfile $Configfile")
         }
    }
}

Function Invoke-GitCheckout { 
    [CmdLetBinding()]
    Param( 
        $URL, 
        $ref,
        $Path,
        $GitPath = 'C:\Program Files\Git\cmd\Git.exe'
    )

    ol -m "Invoke-GitCheckout: Path is '$Path'. "
    ol -m "Invoke-GitCheckout: URL is '$URL'. "
    ol -m "Invoke-GitCheckout: ref is '$ref'. "
   
    $CheckOut = $null
    
    If ((Test-Path $Path) -and (-not (Test-Path $($Path + '\.git'))) ) {
        throw "Invoke-GitCheckout: The target path '$Path' exists, but is not a git repo!"
    }
    ElseIf (Test-Path $Path) {
        ol -m "Invoke-GitCheckout: Target clone folder '$Path' exist already"
        $Origin = (Invoke-Process "$GitPath" -Arguments "-C $Path config --get remote.origin.url").StdOut.Trim()
        If ($Origin -ne $URL) {
            ol -t 2 -m "Invoke-GitCheckout: Folder exists. Invalid origin for folder $Path. Expected '$URL' got '$Origin'"
        }
        $PrevCheckedOutVersion = (Invoke-Process "$GitPath" -Arguments "-C $Path show --format='%h' --no-patch").StdOut.Replace("'", "").Trim()
        $pull = Invoke-Process "$GitPath" -Arguments "-C $Path pull"
        ol -m "Pull is: '$Pull'"
        $CheckOut = Invoke-Process "$GitPath" -Arguments "-C $Path checkout $ref -f"
        ol -m "Checkout is: '$checkout'"
        $CheckedOutVersion = (Invoke-Process "$GitPath" -Arguments "-C $Path show --format='%h' --no-patch").StdOut.Replace("'", "").Trim()
        If ($CheckedOutVersion -ne $PrevCheckedOutVersion) {
            ol -m "Invoke-GitCheckout: Repo $URL. Changes found! Previous version was $PrevCheckedOutVersion, currently at $CheckedOutVersion"
        } 
        Else {
            ol -m "Invoke-GitCheckout: Repo $URL. No changes found! Checked out at $CheckedOutVersion"
        }
    } 
    Else {
        ol -m "Invoke-GitCheckout: Folder '$Path' did not exist. Create and check out."
        New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
        $CheckOut = Invoke-Process "$GitPath" -Arguments "-C $(Split-Path -Parent $Path) clone $URL $(Split-Path -Leaf $Path) -b $ref"
        ol -m "Checkout is: '$Checkout'"
    }
    
    If ($CheckOut.ExitCode -ne 0) {
        Throw "Invoke-GitCheckout: An error occured during checkout. Output: $($CheckOut.StdErr)"
    }
    Else {
        Return [pscustomobject]@{
            URL = "$URL"
            Ref = "$ref"
            Path = "$Path"
        }
    }
    Return $CheckOut
}

Function Invoke-Process {
    [CmdLetBinding()]
    Param (
        $Command, 
        $Arguments
    )
    
    ol -m "Invoke-Process: `$Command: '$Command'"
    ol -m "Invoke-Process: `$Arguments: '$Arguments'"

    Try {
        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = $Command
        $pinfo.RedirectStandardError = $true
        $pinfo.RedirectStandardOutput = $true
        $pinfo.UseShellExecute = $false
        $pinfo.CreateNoWindow = $true
        $pinfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
        $pinfo.Arguments = $Arguments

        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $pinfo
        $p.Start() #| Out-Null

        $StdOutStr = ""
        $StdErrStr = ""

        While(!($p.StandardError.EndOfStream)) {
            $StdErrStr = $StdErrStr + $p.StandardError.ReadLine()
        }

        While(!($p.StandardOutput.EndOfStream)) {
            $StdOutStr = $StdOutStr + $p.StandardOutput.ReadLine()
        }

        $RetObj = [pscustomobject]@{
            Command = $Command
            Arguments = $Arguments
            StdOut = $StdOutStr
            StdErr = $StdErrStr
            ExitCode = $p.ExitCode  
        }
        $p.WaitForExit()
        Return $RetObj
    }
    Catch {
        $p.Dispose()
        Throw $_
    }
}

Function Remove-AppxPackages {
    Param(
        [array]$Apps
    )
    ForEach ($App in $Apps) {
        # Current User
        ol -m ('Removing Package {0} for current user' -f $App)
        Remove-Variable -Name AppxPackage -ErrorAction Ignore
        $AppxPackage = Get-AppxPackage -Name $App -ErrorAction Ignore 
        If ($AppxPackage) {
            ol -m ('Package {0} found, removing it' -f $App)
            $AppxPackage | Remove-AppxPackage -ErrorAction Ignore
        }
        Else {
            ol -m ('Package {0} not found, skipping' -f $App)
        }
        Remove-Variable -Name AppxPackage -ErrorAction Ignore

        # All Users
        ol -m ('Removing Package {0} for all users' -f $App)
        $AppxPackage = Get-AppxPackage -Name $App -AllUsers -ErrorAction Ignore
        If ($AppxPackage) {
            ol -m ('Package {0} found, removing it' -f $App)
            # Remove-AppxPackage actually ignores the -ErrorAction, it thows an error in 
            # the exact same way with Ignore, Continue and SilentlyContinue. The only 
            # way to silence it is to try-catch-it
            Try {
                $AppxPackage | Remove-AppxPackage -AllUsers -ErrorAction Ignore
            }
            Catch {
                # do nothing
            }
            
        }
        Else {
            ol -m ('Package {0} not found, skipping' -f $App)
        }
        Remove-Variable -Name AppxPackage -ErrorAction Ignore

        # Provisioned packages
        ol -m ('Removing Provisioned Package {0}' -f $App)
        $AppxPackage = Get-AppxProvisionedPackage -Online -ErrorAction Ignore | 
        Where-Object DisplayName -eq $App 
        If ($AppxPackage) {
            ol -m ('Provisioned Package {0} found, removing it' -f $App)
            $AppxPackage | Remove-AppxProvisionedPackage -Online -ErrorAction Continue
        }
        Else {
            ol -m ('Provisioned Package {0} not found, skipping' -f $App)
        }
        Remove-Variable -Name AppxPackage -ErrorAction Ignore   
    }
   
}

Function Set-Cortana {
    [CmdletBinding()]
    Param(
        [switch]$disable, 

        [switch]$enable
    )
    If ($disable) {
        ol -m "Trying to disable Cortana"
        $Cortana1 = "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
        $Cortana2 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
        $Cortana3 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
        If (!(Test-Path $Cortana1)) {
            New-Item $Cortana1
        }
        Set-ItemProperty $Cortana1 AcceptedPrivacyPolicy -Value 0 
        If (!(Test-Path $Cortana2)) {
            New-Item $Cortana2
        }
        Set-ItemProperty $Cortana2 RestrictImplicitTextCollection -Value 1 
        Set-ItemProperty $Cortana2 RestrictImplicitInkCollection -Value 1 
        If (!(Test-Path $Cortana3)) {
            New-Item $Cortana3
        }
        Set-ItemProperty $Cortana3 HarvestContacts -Value 0

    } 
    Else {
        $Cortana1 = "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
        $Cortana2 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
        $Cortana3 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
        
        If (!(Test-Path $Cortana1)) {
            New-Item $Cortana1
        }
        Set-ItemProperty $Cortana1 AcceptedPrivacyPolicy -Value 1 
        
        If (!(Test-Path $Cortana2)) {
            New-Item $Cortana2
        }
        Set-ItemProperty $Cortana2 RestrictImplicitTextCollection -Value 0 
        Set-ItemProperty $Cortana2 RestrictImplicitInkCollection -Value 0 
        
        If (!(Test-Path $Cortana3)) {
            New-Item $Cortana3
        }
        Set-ItemProperty $Cortana3 HarvestContacts -Value 1 
    }

}

Function Is-Admin {
    [CmdletBinding()]   
    Param ()
    (New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

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

Function Get-GitConfig {
    [CmdletBinding()]

    Param (
        $GitConfigPath = 'f:\win-scripts\git.json'
    )

    Try {
        # If the floppy contains a git.json, pick it up and return its as an object
        If (Test-Path -Path $GitConfigPath -ErrorAction Ignore) {
            [PSObject]$GitConfig = Get-Content -Path $GitConfigPath -ErrorAction Stop | 
            ConvertFrom-Json -ErrorAction Stop
        }
    }
    Catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
    
    # Return it
    $GitConfig
}

Try {
    ol -m "............................................."
    ol -m "...  Start running 'ConfigPreReboot.ps1'  ..."
    ol -m "............................................."

    # check if running as member of 'Administrators' or not
    If (Is-Admin) {
        ol -m "Running script as Administrator - Continues." 
    }
    Else {
        ol -t 2 -m "Not Administrator - re-run in elevated session"
        Throw "Not Administrator - re-run in elevated session"
    }

    # Set global values, so that -Verbose and -Debug works down the stack 
    $GLOBAL:VerbosePreference = $PSCmdlet.GetVariableValue('VerbosePreference')
    $GLOBAL:DebugPreference = $PSCmdlet.GetVariableValue('DebugPreference')
    $GLOBAL:ErrorActionPreference = 'Stop'

    # -Debug sets $DebugPreference = 'Inquire' - we want it to 'Continue'. 
    # Since this script is already running, and it has already inherited the 
    # GLOBAL scope at start of script, we need to set it for the SCRIPT
    # scope as well
    If ($GLOBAL:DebugPreference -eq 'Inquire'){ 
        $GLOBAL:DebugPreference = 'Continue' 
        $SCRIPT:DebugPreference = 'Continue'
    }

    # Get the condiguration
    $Config = Get-Content -Path $Configfile -Raw -ErrorAction Stop | 
    ConvertFrom-Json -ErrorAction 'Stop'

    # Get Git-configuration
    $GitConfigFile = Join-Path -Path $PSScriptRoot -ChildPath 'git.json'
    If (Test-Path -Path $GitConfigFile -ErrorAction Ignore) {
        ol -m "Git config json ($PSScriptRoot\git.json) found"
        $GitConfigObject = Get-Content -Path $GitConfigFile -Raw -ErrorAction Stop | 
        ConvertFrom-Json -ErrorAction Stop
    }
    Else {
        ol -m "Not found: Git config json (f:\Scripts\git.json)"
    }

    # windowsfeatures
    If ($Config.windows_features) {
        $FeatureLogFile = "$($Config.logdirectory)\Features.log"
        ForEach ($Feature in $Config.windows_features) {
            $OnlineFeature = Get-WindowsFeature -Name $Feature.Name -ErrorAction Continue
            Switch ($Feature.InstallState) {
                "Available" {
                    If ($OnlineFeature.InstallState -ne "Available") {
                        Try {
                            $OnlineFeature | Uninstall-WindowsFeature -LogPath $FeatureLogFile -ErrorAction Stop
                        }
                        Catch {
                            throw $_
                        }
                    } 
                }
                "Installed" {
                    #! Should not check but just install - since -IncludeAllSubfeature and -IncludeManagementTools may be specified
                    If ($OnlineFeature.InstallState -ne "Installed") {
                        Try {
                            $FeatureHash = $null; $FeatureHash = @{}
                            $Feature.psobject.properties | Foreach-Object {
                                if ($_.Name -ne 'InstallState') {
                                    $FeatureHash[$_.Name] = $_.Value 
                                }
                            }
                            ol -m "Installing Feature '$($Feature.Name)'..."
                            Install-WindowsFeature @FeatureHash -LogPath $FeatureLogFile -ErrorAction Stop
                        }
                        Catch {
                            throw $_
                        }
                    } 
                }
                Default {
                    throw "Unknown 'InstallState' on $($Feature.Name): '$($Feature.InstallState)'" 
                }
            }
        }
    }

    # Create directories recursively - specify only leaf
    If ($Config.directories -and $($Config.directories).count -gt 0)  {
        ol -m "Directories specified in config"
        ForEach ($Dir in $Config.directories) {
            ol -m "Creating directory: $Dir"
            New-Item -ItemType Directory -Path "$Dir" -Confirm:$false -Force
        } 
    } 
    Else {
        ol -m "No directories specified in config"
    }

    # Install Chocolatey
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) -ErrorAction 'stop'

    # Install all chocos 
    If ($Config.chocos -and $($Config.chocos).count -gt 0) {
        # Chocos for git and curl are mandatory, because they are used in later tasks
        $GitApp = New-Object -TypeName PSObject -Property @{
            'Name'='Git'
        }
        $CurlApp = New-Object -TypeName PSObject -Property @{
            'Name'='Curl'
        }
        @($GitApp,$CurlApp) | ForEach-Object { 
            If ((@($Config.chocos).Name) -notcontains $_.Name) 
            { 
                $Config.chocos += $_
            }
        }
        
        # Install all chocos
        ForEach ($Choco in $Config.chocos) {
            $ChocoName = $Choco.Name
            
            If ($Choco.Param) {
                $ChocoParam = $Choco.Param
                ol -m "Installing or upgrading Choco '$ChocoName' --params=$ChocoParam"
                & choco upgrade --no-progress --ignore-checksums $ChocoName --params="$ChocoParam" -y 
            }
            Else {
                ol -m "Installing or upgrading Choco '$ChocoName'"
                & choco upgrade --no-progress --ignore-checksums $ChocoName -y 
            }

            If ($LASTEXITCODE -notin @(0,3010)) {
                ol e "Unable to install Choco '$ChocoName'. LastExitCode: $LASTEXITCODE"
            }

            if ($Choco.PostCmd) {
                & cmd.exe /c $($Choco.PostCmd)
            }
            
            if ($Choco.PostPowershell) {
                & powershell.exe -noprofile -command {$($Choco.PostPowershell)}
            }
        }
    }

    If ($GitConfigObject) {
        If ($GitConfigObject.ssh_generate_key) {
            # Git should now be installed, create ssh key in the current user profile
            ol -m "Generating SSH key"
    
            If (-not (Test-Path -Path "$($env:userprofile)\.ssh" -ErrorAction Ignore)) {
                # Create .ssh and make hidden
                & mkdir "$($env:userprofile)\.ssh"
                & attrib.exe +h "$($env:userprofile)\.ssh"
            }
           
            & "$($env:programfiles)\Git\usr\bin\ssh-keygen.exe" -f "$($env:userprofile)\.ssh\id_rsa" --% -t RSA -b 4096 -N ""


            # Since shh-keygen was run, we may want to do other git/ssh-related stuff
            # Create the known_hosts file and populate it 
            If ($GitConfigObject.git_known_hosts) {
                ol -m "Generating known_hosts"
                
                If (-not (Test-Path -Path "$($env:userprofile)\.ssh\known_hosts" -ErrorAction Ignore)) {
                    New-Item -ItemType File -Path "$($env:userprofile)\.ssh\" -Name "known_hosts" -Confirm:$false
                }
                
                ForEach ($Gitlab in $GitConfigObject.git_known_hosts) {
                    ol -m "Generating known_hosts entry for '$($Gitlab.url)'"
                    "$($Gitlab.hoststring)`n" | 
                    Out-File -FilePath "$($env:userprofile)\.ssh\known_hosts" -Append -Confirm:$false -Encoding ascii
                }
            } 
            Else {
                ol -m "Not generating known_hosts"
            }

            # Copy the ssh-configuration to Windows Default user profile so each new user will inherit it
            If ($GitConfigObject.copy_ssh_folder_to_default) {
                ol -m "Copying .shh folder to Default-profile"
                Copy-Item -Container -Recurse -Path "$($env:userprofile)\.ssh" -Destination "$($env:SystemDrive)\Users\Default\" -ErrorAction 'Stop' -Confirm:$false  
            }
            Else {
                ol -m "Not copying .shh folder to Default-profile"
            }

            # Upload the Public Key to git_known_hosts that have "upload_ssh_public_key": true
            If ($GitConfigObject.git_known_hosts) {
                # Get the public key
                $PKey = Get-Content "$($env:userprofile)\.ssh\id_rsa.pub"
               
                # The Gitlab SSH key has a 'Title' which distinguishes it, somewhat. I add a randomized 4 letter HEX
                # to that title to minimize the chance of getting multiple identical titled keys
                # $Title = ($Pkey.Split(" ")[2]) + " - " + (Get-RandomHex -Length 4)
                $Title = ("$($Config.name) - " + (Get-RandomHex -Length 4))
                
                ForEach ($Gitlab in $GitConfigObject.git_known_hosts) {
                    If ($Gitlab.upload_ssh_public_key -eq $True) {
                        
                        ol -m "Uploading public key to gitlab: Gitlab: $($Gitlab.URL)"
                        # Distribute the new ssh key to gitlab.com. In return we get a json of the created 
                        # object. Checking for it's title will validate that the operation succeeded
                        # ol -m "Running: curl.exe --insecure -X POST -F `"private_token=$($Gitlab.accesstoken)`" -F `"title=$Title`" -F `"key=$Pkey`" `"https://$($Gitlab.url)/api/v4/user/keys`")"
                        $ret = ( & curl.exe --insecure -X POST -F "private_token=$($Gitlab.accesstoken)" -F "title=$Title" -F "key=$Pkey" "https://$($Gitlab.url)/api/v4/user/keys")
                        # The command should return a json with the object
                        
                        If (($ret | ConvertFrom-Json -ErrorAction 'Stop').title -ne $Title) {
                            ol -t 2 -m "Unable to upload the ssh key to '$($Gitlab.url)'" 
                        }
                        Else {
                            ol -m "Successfully uploaded ssh public key to '$($Gitlab.url)'" 
                        }
                    }
                    Else {
                        ol -m "Not uploading public key for '$($Gitlab.url)'"
                    }
                }
            } 
            Else {
                ol -m "Not uploading public key to Gitlabs since no git_known_hosts specified"
            }

            # Create the .gitconfig
            If (
                ($GitConfigObject.git_profile.email) -and 
                ($GitConfigObject.git_profile.name)
            ) {

                ol -m "Creating .gitconfig"
        
                If (Test-Path -Path "$($env:userprofile)\.gitconfig" -ErrorAction Ignore) {
                    Remove-Item -Path "$($env:userprofile)\.gitconfig" -Confirm:$false -ErrorAction SilentlyContinue
                }
        
                $GitConfigText = @"
[user]
    email = $($GitConfigObject.git_profile.email)
    name = $($GitConfigObject.git_profile.name)
"@
                Out-File -FilePath "$($env:userprofile)\.gitconfig" -Confirm:$false -Encoding ascii -InputObject $GitConfigText


                # Copy the .gitconfig to Windows Default user profile
                If ($GitConfigObject.copy_git_config_to_default) {
                    If (Test-Path -Path "$($env:userprofile)\.gitconfig" -ErrorAction Ignore) {
                        ol -m "Copying git profile to Default Windows Profile"
                        Copy-Item -Force -Path "$($env:userprofile)\.gitconfig" -Destination "$($env:SystemDrive)\Users\Default\" -ErrorAction 'Stop' -Confirm:$false
                    }
                    Else {
                        ol -m "Skipping copying git profile to Default Windows Profile (it does not exist)"
                    }
                }
                Else {
                    ol -m "Not copying .gitconfig to Default profile"
                }
            }
            Else {
                ol -m "Not adding git-profile since I haven't got both .email and .name"
            }
        }
        Else {
            ol -m "Config specifies not to generate ssh key-pair - skipping all git-related stuff"
        }
    }
    Else {
        ol -m "No Git-config found - skipping all git-related stuff"
    }
    

    If ($GitConfigObject.git_repos_to_clone) {
        ForEach ($GitRepository in $GitConfigObject.git_repos_to_clone) {
            ol -m "Trying to clone '$($GitRepository.Name)'"
            $GitRepositoryPath = "$($GitRepository.path)" + '\\' + "$($GitRepository.name)"
            ol -m "Invoking: 'Invoke-GitCheckout -URL $($GitRepository.url) -ref $($GitRepository.ref) -Path $GitRepositoryPath'"
            Invoke-GitCheckout -URL $GitRepository.url -Ref $GitRepository.ref -Path $GitRepositoryPath 
        }
    }

    # remove all AppXPackages in $Config.appx_remove
    If ($Config.appx_remove -and $($Config.appx_remove).count -gt 0) {
        Remove-AppxPackages -apps $Config.appx_remove
    }

    # Disable Cortana, if $config.Cortana = disable
    If ($Config.Cortana -eq 'disable') {
        Set-Cortana -Disable
    }
    ElseIf ($Config.Cortana -eq 'enable'){
        Set-Cortana -Enable
    }

    # Put cmtrace in c:\windows
    [system.IO.File]::WriteAllBytes("C:\Windows\system32\cmtrace.exe",([System.Convert]::FromBase64String($(get-content "$PSScriptRoot\cmtext.txt"))))

    # Put background_image in systemroot
    If ($Config.bg.background_image) {
        $BGImagePath = $Config.bg.background_image
        ol -m "Background image source path: '$BGImagePath'"

        If (Test-Path -path $BGImagePath -ErrorAction Ignore) {
            Copy-Item -Path $BGImagePath -Destination "$($env:SystemRoot)\bg.jpg" -Confirm:$false -Force -ErrorAction Stop
        }
        Else {
            ol -t 1 -m "No background source image '$BGImagePath' found" 
        }
    }
    
    # Put bginfo config in systemroot
    If ($Config.bg.bg_config) {

        # $BGConfigPath = "$PSScriptRoot\bgconfigs\" + $Config.bg.bgconfig
        $BGConfigPath = $Config.bg.bg_config
        ol -m "Bg config source path: '$BGConfigPath'"
        If (Test-Path -path $BGConfigPath -ErrorAction Ignore) {
            Copy-Item -Path $BGConfigPath -Destination "$($env:SystemRoot)\bg.bgi" -Confirm:$false -Force -ErrorAction Stop
        }
        Else {
            ol -t 1 -m "No bginfo source configuration file '$BGConfigPath' found"
        }

        # Run the initial conf - must be done in scheduled task later, when domain joined
        # & "C:\ProgramData\chocolatey\bin\bginfo64.exe" "$($env:SystemRoot)\bg.bgi" /TIMER:0 /SILENT /NOLICPROMPT
    }
    
    
    # Add Firewall rules according to $Config.firewall.add_local_rules. 
    $RulesToKeep = @()
    If ($Config.firewall.add_local_rules) {

        ForEach ($Rule in $Config.firewall.add_local_rules) {
            $RulesToKeep += $Rule.DisplayName
            # build a hash to splat to New-NetFirewallRule
            Remove-Variable -Name NewNetFirewallRuleSplat -ErrorAction Ignore
            [hashtable]$NewNetFirewallRuleSplat = @{}
            $Rule | 
            Get-Member -MemberType Properties | 
            ForEach-Object { 
                    $NewNetFirewallRuleSplat.Add($_.Name,$Rule.($_.name)) 
            }
            New-NetFirewallRule @NewNetFirewallRuleSplat -Confirm:$false
        }
    }

    # Remove all firewall rules we didn't explicitly allow
    If ($Config.firewall.remove_local_rules) {
        ol -m "Removing all locally defined firewall rules"
        Get-NetFirewallRule | 
        Where-Object { 
            $_.DisplayName -notin $RulesToKeep 
        } | 
        Remove-NetFirewallRule -Confirm:$false -ErrorAction Stop
    }
    
    # Update Windows-Help. It will typically always fail at some point, 
    # therefore, do them one by one
    If ($Config.update_help) {
        
        ol -m "Update help on all powershell modules"
        $InstalledModules = @((Get-Module -ListAvailable | Select-Object -property Name).Name)
        ol -m "There are $($InstalledModules.count) modules to update"
        $UpdatedHelpCount = 0
        ForEach ($InstalledModule in $InstalledModules) {

            Try {
                Update-Help -Module $Installedmodule -Force -Confirm:$false -ErrorAction SilentlyContinue
                $UpdatedHelpCount++
            }
            Catch {
                ol -t 1 -m "Unable to update help on module '$Installedmodule'"
            }
            Finally {
                ol -m "Updated help on $UpdatedHelpCount of $($InstalledModules.count) modules."
            }
        }   
    }
    Else {
        ol -m "Skipping updating Powershell module helpfiles"
    }

    # windowsfeatures
    If ($Config.windows_features) {
        $FeatureLogFile = "$($Config.logdirectory)\Features.log"
        ForEach ($Feature in $Config.windows_features) {
            $OnlineFeature = Get-WindowsFeature -Name $Feature.Name -ErrorAction Continue
            Switch ($Feature.InstallState) {
                "Available" {
                    If ($OnlineFeature.InstallState -ne "Available") {
                        Try {
                            $OnlineFeature | Uninstall-WindowsFeature -LogPath $FeatureLogFile -ErrorAction Stop
                        }
                        Catch {
                            throw $_
                        }
                    } 
                }
                "Installed" {
                    #! Should not check but just install - since -IncludeAllSubfeature and -IncludeManagementTools may be specified
                    If ($OnlineFeature.InstallState -ne "Installed") {
                        Try {
                            $FeatureHash = $null; $FeatureHash = @{}
                            $Feature.psobject.properties | Foreach-Object {
                                if ($_.Name -ne 'InstallState') {
                                    $FeatureHash[$_.Name] = $_.Value 
                                }
                            }
                            ol -m "Installing Feature '$($OptionalFeature.Name)'..."
                            Install-WindowsFeature @FeatureHash -LogPath $FeatureLogFile -ErrorAction Stop
                        }
                        Catch {
                            throw $_
                        }
                    } 
                }
                Default {
                    throw "Unknown 'InstallState' on $($Feature.Name): '$($Feature.InstallState)'" 
                }
            }
        }
    }

    # windowsoptionalfeature
    If ($Config.windows_optional_features) {

        $OptFeatureLogFile = "$($Config.logdirectory)\OptionalFeatures.log"
        ForEach ($OptionalFeature in $Config.windows_optional_features) {

            $OnlineFeature = Get-WindowsOptionalFeature -FeatureName $OptionalFeature.FeatureName -Online -ErrorAction Continue

            # Will return $Null if feature does not exist
            If ($Null -eq $OnlineFeature) {
                ol -t 1 -m "Feature '$($OptionalFeature.FeatureName)' does not exist in this OS - skipping" 
            }
            Else {
                ol -m "Feature '$($OptionalFeature.FeatureName)' found. Current state: $($OnlineFeature.State)" 
            }
            Switch ($OptionalFeature.State) {
                "Disabled" {
                    ol -m "Disabling Windows optional feature: '$($OptionalFeature.FeatureName)'"
                    If ($OnlineFeature.State -ne "Disabled") {

                        ol -m "Feature '$($OptionalFeature.FeatureName)' is enabled, trying to disable"
                        Try {
                            $OnlineFeature | Disable-WindowsOptionalFeature -Online -LogLevel 2 -LogPath $OptFeatureLogFile -Norestart -ErrorAction Stop
                            ol -m "Successfully disabled feature '$($OptionalFeature.FeatureName)'"
                        }
                        Catch {
                            ol -t 2 -m "Failed disabling feature '$($OptionalFeature.FeatureName)'"
                        }
                    } 
                    Else {
                        ol -m "Feature '$($OptionalFeature.FeatureName)' already disabled."
                    }
                }
                "Enabled" {
                    ol -m "Enabling Windows optional feature: '$($OptionalFeature.FeatureName)'"
                    If ($OnlineFeature.State -ne "Enabled") {
                        ol -m "Feature '$($OptionalFeature.FeatureName)' is disabled, trying to enable"
                        Try {
                            $OnlineFeature | Enable-WindowsOptionalFeature -Online -All -LogLevel 2 -LogPath $OptFeatureLogFile -Norestart -ErrorAction Stop
                            ol -m "Successfylly enabled feature '$($OptionalFeature.FeatureName)'"
                        }
                        Catch {
                            ol -t 2 -m "Failed enabling feature '$($OptionalFeature.FeatureName)'"
                        }
                    } 
                    Else {
                        ol -m "Feature '$($OptionalFeature.FeatureName)' already Enabled."
                    }
                }
                Default {
                    ol -t 2 -m "Wrong 'State' on $($OptionalFeature.FeatureName): '$($OptionalFeature.State)'" 
                }
            }
        }
    }

    # Windows Capabilities
    If ($Config.windows_capabilities) {

        ForEach ($Capability in $Config.windows_capabilities) {
            
            $OnlineCapability = Get-WindowsCapability -Name $Capability.Name -Online -ErrorAction Continue
            Switch ($Capability.State) {
                
                "NotPresent" {
                    ol -m "Disabling Windows optional capability: '$($Capability.Name)'"
                    If ($OnlineCapability.State -ne "NotPresent") {

                        ol -m "Capability '$($Capability.Name)' is installed, trying to remove"
                        $OnlineCapability | Remove-WindowsCapability -Online -ErrorAction Continue
                        ol -m "Successfylly removed capability '$($Capability.Name)'"
                    } 
                    Else {
                        ol -m "Capability '$($Capability.Name)' already removed."
                    }
                }
                "Installed" {
                    ol -m "Adding Windows optional capability: '$($Capability.Name)'"

                    If ($OnlineCapability.State -ne "Installed") {

                        ol -m "Capability '$($Capability.Name)' is NotPresent, trying to Add"
                        $OnlineCapability | Add-WindowsCapability -Online -ErrorAction Continue
                        ol -m "Successfylly added capability '$($Capability.Name)'"
                    } 
                    Else {
                        ol -m "capability '$($Capability.Name)' already Installed."
                    }
                }
                Default {
                    ol -t 2 -m "Wrong 'State' on $($Capability.Name): '$($Capability.State)'"
                }
            }
        }
    }

    # configure RDP
    If ($Config.adm_interfaces.rdp.enable -eq $True) {

        ol -m "Trying to enable RDP for remote management"
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0 -ErrorAction Stop
        Switch ($Config.adm_interfaces.rdp.nla) {
            $false {
                ol -t 1 -m "Disabling pre-session authentication for RDP." 
                Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 0 -ErrorAction Stop
            }
            Default {
                ol -m "Enabling pre-session authentication for RDP."
                Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 1 -ErrorAction Stop
            }
        }
    }
    
    # Copy the psprofile folder to Default user profile
    If ($Config.copy_ps_profile_to_default) {
        # Configure the psprofile. It is checked out to C:\GITS\psprofile, 
        $ProfileFolder = "$($env:systemdrive)\Users\Default\Documents\WindowsPowerShell"

        ol -m "Profilefolder is: '$ProfileFolder'"
        If (-not (Test-Path -Path $ProfileFolder -ErrorAction SilentlyContinue) ) {
            ol -m "Running: 'New-Item -Path $ProfileFolder -ItemType Directory -Force'"
            New-Item -Path $ProfileFolder -ItemType Directory -Force
        }
        Else {
            ol -m "ProfileFolder exists already."
        }
    
        # copy it to the Default ps profile
        ol -m "Copying profile to powershell profile"
        Copy-Item -Path "C:\GITs\psprofile\Microsoft.PowerShell_profile.ps1" -Destination "$ProfileFolder\Microsoft.PowerShell_profile.ps1" -Force

        # copy it to the VS Code ps profile
        ol -m "Copying profile to vscode profile"
        Copy-Item -Path "C:\GITs\psprofile\Microsoft.PowerShell_profile.ps1" -Destination "$ProfileFolder\Microsoft.VSCode_profile.ps1" -Force 
    }

    # configure SSH daemon (sshd)
    If ($Config.adm_interfaces.sshd.enable -eq $True) {

        ol -m "Instructed to enable SSHd for remote management"
        # make sure sshd is installed
        Remove-Variable -Name OnlineCapability -ErrorAction SilentlyContinue
        $OnlineCapability = Get-WindowsCapability -Name "OpenSSH.Server*" -Online -ErrorAction Stop
       
        If ($OnlineCapability.State -ne 'Installed') {
            ol -m "SSHd wa found, not installed. Trying to install."
            Try {
                $OnlineCapability | Add-WindowsCapability -Online -ErrorAction Stop
                ol -m "Successfully installed SSHd"
            }

            Catch {
                ol -t 2 -m "Failed to install SSHd"
            }  
        }
        ElseIf ($OnlineCapability.State -eq 'Installed') {
            ol -m "SSHd is already installed."
        }
        Else {
            ol -t 2 -m "Unknown state SSHd (OpenSSH Server): '$($OnlineCapability.State)'"
        } 
    }
}

Catch {
    ol -m "............................................."
    ol -m "..  Failed running 'ConfigPreReboot.ps1'   .."
    ol -m "............................................."
    $Failed = $True
    $PSCmdlet.ThrowTerminatingError($_)
}
Finally {
    If (-not $Failed) {
        ol -m "............................................."
        ol -m "..  Finshed running 'ConfigPreReboot.ps1'  .."
        ol -m "............................................."
    }
}

