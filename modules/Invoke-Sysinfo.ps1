function Invoke-Sysinfo {
<# 

.SYNOPSIS
Gathers some information about a system.

.Example
PS> . .\Invoke-Sysinfo.ps1
PS> Invoke-Sysinfo -Help

Author: (@0rbz_)

#>

[CmdletBinding()]
param (
	[Switch]$Help,
	[Switch]$List,
	[Switch]$Os,
	[Switch]$Env,
	[Switch]$Drives,
	[Switch]$Users,
	[Switch]$LocalAdmins,
	[Switch]$DomainAdmins,
	[Switch]$Privs,
	[Switch]$Hotfixes,
	[Switch]$CheckElevated,
	[Switch]$Shares,
	[Switch]$LoggedOn,
	[Switch]$Apps,
	[Switch]$procs,
	[Switch]$services,
	[Switch]$tasks,
	[Switch]$av,
	[Switch]$LangMode,
	[Switch]$PsVersion,
	[Switch]$DnsCache,
	[Switch]$PsHistory,
	[Switch]$ClipBoard,
	[Switch]$IpConfig,
	[Switch]$NetStat,
	[Switch]$DumpAll
)

	if ($Help -eq $true -or $List -eq $True) {
	
		Write @"

 ### Invoke-Sysinfo HELP ###
 ---------------------------
 
 Invoke-Sysinfo [-command]
 
 Example: Invoke-Sysinfo -os
 Example: Invoke-Sysinfo -os | Out-File C:\temp\os.txt
 Example: Invoke-Sysinfo -env
 Example: Invoke-Sysinfo -LangMode
 Example: Invoke-Sysinfo -PsHistory |Select-String "password"
 
 SYSINFO Command List:
 ---------------------
 /---------------------------------------------------------------------/
 | -Os             (Displays Basic Operating System Information)       |
 | -Env            (Displays Environment Variables Information)        |
 | -Drives         (Displays current drives)                           |
 | -Users          (Displays Users)                                    |
 | -LocalAdmins    (Displays local admins)                             |
 | -DomainAdmins   (Displays Domain Admins)                            |
 | -Privs          (Displays current user privileges)                  |
 | -HotFixes       (Displays installed hotfixes)                       |
 | -CheckElevated  (Checks if current user PS process is elevated)     |
 | -Shares         (Displays shared drives on the system)              |
 | -LoggedOn       (Displays currently interactively logged-on users)  |
 | -Apps           (Retrieves installed applications)                  |
 | -Procs          (Displays current running processes)                |
 | -Services       (Displays current running and stopped services)     |
 | -Tasks          (Displays non-Microsoft scheduled tasks)            |
 | -Av             (Retrieves installed AntiVirus software information)|
 | -LangMode       (Checks powershell current language mode)           |
 | -PsVersion      (Displays PowerShell version)                       |
 | -DnsCache       (Dumps DNS Cache)                                   |
 | -PsHistory      (Dumps PowerShell Commandline History)              |
 | -ClipBoard      (Dumps Clipboard Contents)                          |
 | -IpConfig       (Dumps Network Interface Information)               |
 | -NetStat        (Dumps Active Network Connection information)       |
 | -DumpAll        (Dumps all of the above modules information into    |
 |                  %appdata%\sysinfo.txt)                             |
 /---------------------------------------------------------------------/
 
"@
	}
	
	elseif ($Os) {
		$h = "`n### Invoke-Sysinfo(os) ###`n"
		$h
		get-wmiobject win32_operatingsystem | Select-Object Caption, Version, OSArchitecture, ServicePackMajorVersion, ServicePackMinorVersion, MUILanguages, LastBootUpTime, LocalDateTime, NumberOfUsers, SystemDirectory
		$h
	}
	elseif ($env) {
		$h = "`n### Invoke-Sysinfo(env) ###`n"
		$h
		Get-ChildItem Env: | ft Key,Value
		$h
	}
	elseif ($drives) {
		$h = "`n### Invoke-Sysinfo(drives) ###`n"
		$h
		Get-PSDrive | where {$_.Provider -like 'Microsoft.PowerShell.Core\FileSystem'}| ft Name,Root
		$h
	}
	elseif ($Users) {
		$h = "`n### Invoke-Sysinfo(Users) ###`n"
		$h
		Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True'" | select name, fullname
		$h 
	}
	elseif ($LocalAdmins) {
		$h = "`n### Invoke-Sysinfo(LocalAdmins) ###`n"
		$h
		(get-wmiobject win32_group -filter "name='Administrators'").GetRelated("win32_useraccount")
		$h
	}
	
	elseif ($DomainAdmins) {
		$h = "`n### Invoke-Sysinfo(DomainAdmins) ###`n"
		$h
		(C:\??*?\*3?\n?t.?x? group "Domain Admins" /domain)
		$h
	}
	
	elseif ($Privs) {
		$h = "`n### Invoke-Sysinfo(privs) ###`n"
		$h
		(C:\??*?\*3?\wh??m?.?x? /priv)
		$h
	}
	
	elseif ($hotfixes) {
		$h = "`n### Invoke-Sysinfo(hotfixes) ###`n"
		$h
		Get-Hotfix
		$h
	}
	
	elseif ($CheckElevated) {
		$h = "`n### Invoke-Sysinfo(CheckElevated) ###`n"
		$check = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
		if ($check -eq $true) {
			$h
			Write " [+] We're running as an elevated process."
			$h
		}
		if ($check -eq $false) {
			$h
			Write " [-] Not Elevated."
			$h
		}
	}
	
	elseif ($shares) {
		$h = "`n### Invoke-Sysinfo(shares) ###`n"
		$h
		Get-WmiObject Win32_Share
		$h
	}
	
	elseif ($LoggedOn) {
	# https://social.technet.microsoft.com/Forums/forefront/en-US/6bf4194e-36d4-4fd1-96d6-40ebb9498424/powershell-script-list-all-remote-users-connected-via-rdp-with-details-like-remote-workstation
		$h = "`n### Invoke-Sysinfo(LoggedOn) ###`n"
		$Explorer = (Get-WmiObject -Query "select * from Win32_Process where Name='explorer.exe'")
	
		if (!$Explorer) {
		$h
		Write " [-] No users currently interactively logged on."
		$h
		}
			else {
				foreach ($p in $Explorer) {
				$Username = $p.GetOwner().User
				$Domain = $p.GetOwner().Domain
				$h
				Write " User: $Domain\$Username`n Logon Time: $($p.ConvertToDateTime($p.CreationDate))"
				$h
			}
		}
	}
	
	elseif ($apps) {
		$h = "`n### Invoke-Sysinfo(apps) ###`n"
		$h
		Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | Format-Table Parent,Name,LastWriteTime
		$h
	}
	
	elseif ($procs) {
		$h = "`n### Invoke-Sysinfo(procs) ###`n"
		$h
		Get-WmiObject -Query 'Select * from Win32_Process' | where {$_.Name -notlike 'svchost*'} | Select Name, Handle, @{Label='Owner';Expression={$_.GetOwner().User}} | Format-Table -AutoSize
		$h
	}
	
	elseif ($services) {
		$h = "`n### Invoke-Sysinfo(services) ###`n"
		$h
		Get-WmiObject win32_service | Select-Object Name, DisplayName, @{Name="Path"; Expression={$_.PathName.split('"')[1]}}, State | Format-List
		$h
	}
	
	elseif ($tasks) {
		$h = "`n### Invoke-Sysinfo(tasks) ###`n"
		$h
		(Get-ChildItem C:\windows\system32\tasks |fl -Property Name,FullName)
		$h
	}
	
	elseif ($av) {
	# https://stackoverflow.com/questions/33649043/powershell-how-to-get-antivirus-product-details#37842942
	[parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
	[Alias('name')]
	$computername=$env:computername
	$AntiVirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct  -ComputerName $computername

		$ret = @()
		foreach($AntiVirusProduct in $AntiVirusProducts){
			switch ($AntiVirusProduct.productState) {
			"262144" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
			"262160" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
			"266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
			"266256" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
			"393216" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
			"393232" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
			"393488" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
			"397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
			"397328" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
			"397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
			default {$defstatus = "Unknown" ;$rtstatus = "Unknown"}
			}
			#Create hash-table for each computer
			$ht = @{}
			$ht.Computername = $computername
			$ht.Name = $AntiVirusProduct.displayName
			$ht.'Product GUID' = $AntiVirusProduct.instanceGuid
			$ht.'Product Executable' = $AntiVirusProduct.pathToSignedProductExe
			$ht.'Reporting Exe' = $AntiVirusProduct.pathToSignedReportingExe
			$ht.'Definition Status' = $defstatus
			$ht.'Real-time Protection Status' = $rtstatus

			#Create a new object for each computer
			$ret += New-Object -TypeName PSObject -Property $ht
		}
		Write "`n### Invoke-Sysinfo(av) ###"
		Return $ret
	}
	
	elseif ($LangMode) {
		$h = "`n### Invoke-Sysinfo(LangMode) ###`n"
		$h
		$ExecutionContext.SessionState.LanguageMode
		$h
	}
	
	elseif ($PsVersion) {
		$h = "`n### Invoke-Sysinfo(PsVersion) ###`n"
		$h
		Write $psversiontable
		$h
	}
	
	elseif ($DnsCache) {
		$h = "`n### Invoke-Sysinfo(DnsCache) ###`n"
		if ($PSVersionTable.PSVersion.Major -eq "2") {
			$h
			Write " [!] This function requires PowerShell version greater than 2.0."
			$h
			return
		}
		else {
			$h
			Get-DnsClientCache
			$h
		}
	}
	elseif ($PsHistory) {
	# https://twitter.com/mattifestation/status/740242366754226176
		$h = "`n### Invoke-Sysinfo(PsHistory) ###`n"
		$h
		(Get-Content "$env:appdata\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt")
		$h
	}
	elseif ($ClipBoard) {
		$h = "`n### Invoke-Sysinfo(ClipBoard) ###`n"
		$h
		Get-ClipBoard
		$h
	}
	elseif ($IpConfig) {
		(ipconfig /all)
	}
	elseif ($NetStat) {
		(netstat -an)
	}
	elseif ($DumpAll) {
		$h = "`n### Invoke-Sysinfo(DumpAll) ###`n"
		$h
		(Invoke-Sysinfo -Os | out-file $env:temp\sysinfo.txt -Append)
		(Invoke-Sysinfo -Env | out-file $env:temp\sysinfo.txt -Append)
		(Invoke-Sysinfo -Drives | out-file $env:temp\sysinfo.txt -Append)
		(Invoke-Sysinfo -Users | out-file $env:temp\sysinfo.txt -Append)
		(Invoke-Sysinfo -LocalAdmins | out-file $env:temp\sysinfo.txt -Append)
		(Invoke-Sysinfo -DomainAdmins | out-file $env:temp\sysinfo.txt -Append)
		(Invoke-Sysinfo -Privs | out-file $env:temp\sysinfo.txt -Append)
		(Invoke-Sysinfo -HotFixes | out-file $env:temp\sysinfo.txt -Append)
		(Invoke-Sysinfo -CheckElevated | out-file $env:temp\sysinfo.txt -Append)
		(Invoke-Sysinfo -Shares | out-file $env:temp\sysinfo.txt -Append)
		(Invoke-Sysinfo -LoggedOn | out-file $env:temp\sysinfo.txt -Append)
		(Invoke-Sysinfo -Apps | out-file $env:temp\sysinfo.txt -Append)
		(Invoke-Sysinfo -Procs | out-file $env:temp\sysinfo.txt -Append)
		(Invoke-Sysinfo -Services | out-file $env:temp\sysinfo.txt -Append)
		(Invoke-Sysinfo -Tasks | out-file $env:temp\sysinfo.txt -Append)
		(Invoke-Sysinfo -Av | out-file $env:temp\sysinfo.txt -Append)
		(Invoke-Sysinfo -LangMode | out-file $env:temp\sysinfo.txt -Append)
		(Invoke-Sysinfo -PsVersion | out-file $env:temp\sysinfo.txt -Append)
		(Invoke-Sysinfo -DnsCache | out-file $env:temp\sysinfo.txt -Append)
		(Invoke-Sysinfo -PsHistory | out-file $env:temp\sysinfo.txt -Append)
		(Invoke-Sysinfo -ClipBoard | out-file $env:temp\sysinfo.txt -Append)
		(Invoke-Sysinfo -IpConfig | out-file $env:temp\sysinfo.txt -Append)
		(Invoke-Sysinfo -NetStat | out-file $env:temp\sysinfo.txt -Append)
    
		Write "All modules dumped to $env:temp\sysinfo.txt"
		$h	
	}
}
