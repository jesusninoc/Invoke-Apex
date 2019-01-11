function Invoke-TimeStomp {
[CmdletBinding()]
param (
	[Parameter(ParameterSetName = 'Help', Position=1)]
	[Switch]$Help,
	
	[Parameter(ParameterSetName = 'ListCommands')]
	[switch]$List,
	
	[Parameter(ParameterSetName = 'TimeStomp')]
	[String]$File
	
	
)

$TimeSource = (Get-Item C:\windows\system32\cmd.exe).FullName

	if ($Help -eq $True) {
		Write @"
		
 ### Invoke-TimeStomp HELP ###
 -----------------------------
 /----------------------------------------------------------------------/
 | [-File] file.exe                                                     |
 | -------------------------------------------------------------------- |
 |                                                                      |
 |  [*] Description: Modifies a files' Creation Time to that of         |
 |      C:\windows\system32\cmd.exe.                                    |
 |                                                                      |
 |  [*] Usage: Invoke-TimeStomp -File C:\temp\file.exe                  |
 /----------------------------------------------------------------------/
 
"@
	}
	elseif ($List -eq $True) {
		Write @"
 
 Invoke-TimeStomp Command List:
 ------------------------------
 Invoke-TimeStomp [-File] file
 
"@
	}
	elseif ($File) {
		$LastWriteTime = (Get-Item C:\windows\system32\cmd.exe).LastWriteTime
		[IO.File]::SetCreationTime("$File", [IO.File]::GetCreationTime($TimeSource))
		[IO.File]::SetLastAccessTime("$File", [IO.File]::GetLastAccessTime($TimeSource))
		[IO.File]::SetLastWriteTIme("$File", [IO.File]::GetLastWriteTime($TimeSource))
		
		Write " `n[+] Changed Creation, Last Access, and Last Write Time for $File to $LastWriteTime (cmd.exe).`n"
	}
}
