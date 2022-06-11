# platform vars
variable "vcenter_server" {
  default = {}
}

variable "vcenter_cluster" {
  default = {}
}

variable "vcenter_big_datastore" {
  default = {}
}

variable "vcenter_fast_datastore" {
  default = {}
}

variable "vcenter_templates_folder" {
  default = {}
}

variable "vcenter_network" {
  default = {}
}

# users and passwords
variable "vcenter_password" {
  default = {}
}

variable "vcenter_username" {
  default = {}
}

variable "winrm_password" {
  default = {}
}

variable "winrm_username" {
  default = {}
}

# paths vars
variable "vcenter_iso_w11" {
  default = {}
}

variable "vcenter_iso_vmwaretools" {
  default = {} 
}

variable "win_scripts" {
  default = {}
}

variable "resource_name" {
  default = {}
}

variable "vcenter_template" {
  default = {}
}

variable "product_key" {
  default = {}
}

source "vsphere-iso" "w11-enterprise" {
  CPUs                 = 4
  NestedHV             = true
  vTPM                 = true
  RAM                  = 8192
  RAM_reserve_all      = true
  boot_command         = ["<enter>"]
  boot_wait            = "2s"
  cd_files             = ["./*","${var.win_scripts}"]
  cluster              = "${var.vcenter_cluster}"
  communicator         = "winrm"
  convert_to_template  = true
  cpu_cores            = 4
  datastore            = "${var.vcenter_big_datastore}"
  disk_controller_type = ["lsilogic-sas"]
  firmware             = "efi-secure"
  folder               = "${var.vcenter_templates_folder}"
  guest_os_type        = "windows9_64Guest"
  insecure_connection  = true
  iso_paths            = ["${var.vcenter_iso_w11}", "${var.vcenter_iso_vmwaretools}"]
  network_adapters {
    network      = "${var.vcenter_network}"
    network_card = "vmxnet3"
  }
  password     = "${var.vcenter_password}"
  remove_cdrom = true
  storage {
    disk_controller_index = 0
    disk_size             = 102400
    disk_thin_provisioned = true
  }
  username       = "${var.vcenter_username}"
  vcenter_server = "${var.vcenter_server}"
  vm_name        = "${var.vcenter_template}"
  vm_version     = 19
  winrm_password = "${var.winrm_password}"
  winrm_username = "${var.winrm_username}"
}

build {
  sources = ["source.vsphere-iso.w11-enterprise"]

  provisioner "powershell" {
    elevated_password = "${var.winrm_password}"
    elevated_user     = "${var.winrm_username}"
    inline            = [
      "Write-Host '### Upgrade Nuget Provider (minimum 2.8.5.201)' ###",
      "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12", 
      "Set-PackageSource -Name PSGallery -Trusted", 
      "Install-PackageProvider -Name Nuget -MinimumVersion 2.8.5.201 -Scope AllUsers -Confirm:$false -Force"]
    max_retries       = "3"
    pause_before      = "2m0s"
  }

  provisioner "windows-restart" {
    restart_check_command = "powershell -command \"& {Write-Output '### Restart Succeeded'}\""
    timeout           = "1h0m0s"
    max_retries       = "50"
  }

  provisioner "powershell" {
    elevated_password = "${var.winrm_password}"
    elevated_user     = "${var.winrm_username}"
    inline            = [
      "Write-Host '### Upgrade PackageManagement module (minimum 1.4.6)' ###",
      "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12", 
      "Install-Module -Name PackageManagement -MinimumVersion 1.4.6 -Scope AllUsers -AllowClobber -Repository PSGallery -Confirm:$false -Force"]
    max_retries       = "3"
    pause_before      = "2s"
  }

  provisioner "windows-restart" {
    restart_check_command = "powershell -command \"& {Write-Output '### Restart Succeeded'}\""
    timeout           = "1h0m0s"
    max_retries       = "50"
  }

  provisioner "powershell" {
    elevated_password = "${var.winrm_password}"
    elevated_user     = "${var.winrm_username}"
    max_retries       = "3"
    pause_before      = "2s"
    inline            = [
      "Write-Host '### Upgrade PowerShellGet module (minimum 2.2.5)' ###",
      "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12", 
      "Install-Module -Name PowerShellGet -MinimumVersion 2.2.5 -Scope AllUsers -AllowClobber -Repository PSGallery -Confirm:$false -Force -WarningAction Continue", 
      "Remove-Module -Name PowerShellGet -ErrorAction Ignore", 
      "Remove-Module -Name PackageManagement -ErrorAction Ignore", 
      "$ModulesToDelete = @(Get-Module -Name PowerShellGet -ListAvailable | Where-Object Version -lt 2.2.5)", 
      "foreach ($m in $ModulesToDelete) { Remove-Item -Path (Split-Path -Path $m.Path) -Recurse -Force }"
    ]
    
  }

  provisioner "windows-restart" {
    restart_check_command = "powershell -command \"& {Write-Output '### Restart Succeeded'}\""
    timeout           = "1h0m0s"
    max_retries       = "50"
  }

  provisioner "powershell" {
    elevated_password = "${var.winrm_password}"
    elevated_user     = "${var.winrm_username}"
    inline            = ["f:\\win-scripts\\ConfigUpdates.ps1 -Configfile f:\\w11-enterprise-OSConfig.json"]
    max_retries       = "1"
    timeout           = "2h0m0s"
  }

  provisioner "windows-restart" {
    restart_check_command = "powershell -command \"& {Write-Output '### Restart Succeeded'}\""
    timeout           = "2h0m0s"
    max_retries       = "50"
  }

  provisioner "powershell" {
    elevated_password = "${var.winrm_password}"
    elevated_user     = "${var.winrm_username}"
    inline            = ["f:\\win-scripts\\ConfigUpdates.ps1 -Configfile f:\\w11-enterprise-OSConfig.json"]
    max_retries       = "1"
    timeout           = "2h0m0s"
  }

  provisioner "windows-restart" {
    restart_check_command = "powershell -command \"& {Write-Output '### Restart Succeeded'}\""
    timeout           = "1h0m0s"
    max_retries       = "50"
  }

  provisioner "powershell" {
    elevated_password = "${var.winrm_password}"
    elevated_user     = "${var.winrm_username}"
    inline            = ["f:\\win-scripts\\ConfigUpdates.ps1 -Configfile f:\\w11-enterprise-OSConfig.json"]
    max_retries       = "1"
    timeout           = "2h0m0s"
  }

  provisioner "windows-restart" {
    restart_check_command = "powershell -command \"& {Write-Output '### Restart Succeeded'}\""
    timeout           = "1h0m0s"
    max_retries       = "50"
  }

  provisioner "powershell" {
    elevated_password = "${var.winrm_password}"
    elevated_user     = "${var.winrm_username}"
    inline            = ["f:\\win-scripts\\ConfigPreReboot.ps1 -Configfile f:\\w11-enterprise-OSConfig.json"]
    max_retries       = "1"
    pause_before      = "2s"
  }

  provisioner "windows-restart" {
    restart_check_command = "powershell -command \"& {Write-Output '### Restart Succeeded'}\""
    timeout           = "1h0m0s"
    max_retries       = "50"
  }

  provisioner "powershell" {
    elevated_password = "${var.winrm_password}"
    elevated_user     = "${var.winrm_username}"
    inline            = ["f:\\win-scripts\\ConfigPostReboot.ps1 -Configfile f:\\w11-enterprise-OSConfig.json"]
    max_retries       = "2"
  }

  provisioner "powershell" {
    elevated_password = "${var.winrm_password}"
    elevated_user     = "${var.winrm_username}"
    inline            = ["reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\" /v DisabledComponents /t REG_DWORD /d 255 /f"]
    max_retries       = "1"
  }

  provisioner "windows-restart" {
    restart_check_command = "powershell -command \"& {Write-Output '### Restart Succeeded'}\""
    timeout           = "1h0m0s"
    max_retries       = "50"
  }

  provisioner "powershell" {
    elevated_password = "${var.winrm_password}"
    elevated_user     = "${var.winrm_username}"
    inline            = ["Try { Copy-Item -Path F:\\win-scripts\\ConfigureWinRM-https.ps1 -Destination C:\\Temp\\ -Force } Catch { Throw $_ }"]
    max_retries       = "1"
  }

  provisioner "powershell" {
    elevated_password = "${var.winrm_password}"
    elevated_user     = "${var.winrm_username}"
    max_retries       = "3"
    inline            = [
      "Write-Host '### Onedrive prevents sysprep'",
      "Remove-AppxPackage -Package Microsoft.OneDriveSync_21220.1024.5.0_neutral__8wekyb3d8bbwe",
      "Remove-AppxProvisionedPackage -Package Microsoft.OneDriveSync_21220.1024.5.0_neutral__8wekyb3d8bbwe -AllUsers -Online"
    ]
      
  }

  provisioner "powershell" {
    elevated_password = "${var.winrm_password}"
    elevated_user     = "${var.winrm_username}"
    inline            = ["f:\\win-scripts\\ConfigLast.ps1 -Configfile f:\\w11-enterprise-OSConfig.json"]
    max_retries       = "1"
  }

  provisioner "powershell" {
    elevated_password = "${var.winrm_password}"
    elevated_user     = "${var.winrm_username}"
    inline            = [
      "Write-Host '### Creating the powershell profile with oh-my-posh'",
      "$FolderPath1 = 'C:\\Users\\Administrator\\Documents\\WindowsPowerShell'",
      "$ProfilePath1 = Join-Path -Path $FolderPath1 -ChildPath 'Microsoft.PowerShell_profile.ps1'",
      "$FolderPath2 = 'C:\\Users\\Default\\Documents\\WindowsPowerShell'",
      "$ProfilePath2 = Join-Path -Path $FolderPath1 -ChildPath 'Microsoft.PowerShell_profile.ps1'",
      "$ProfileText = \u0022oh-my-posh init pwsh --config \u0022\u0022$env:POSH_THEMES_PATH\\powerlevel10k_rainbow.omp.json\u0022\u0022 | Invoke-Expression\u0022",
      "Try { New-Item -Itemtype Directory -Path $FolderPath1 -Force | Out-Null } Catch { Throw $_ }",
      "Try { New-Item -Itemtype Directory -Path $FolderPath2 -Force | Out-Null } Catch { Throw $_ }",
      "Try { $ProfileText | Out-File -FilePath $ProfilePath1 -Encoding Default -Force -Confirm:$false } Catch { Throw $_ }",
      "Try { $ProfileText | Out-File -FilePath $ProfilePath2 -Encoding Default -Force -Confirm:$false } Catch { Throw $_ }"
    ]
  }
}