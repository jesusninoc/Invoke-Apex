function Invoke-TCPScan {
[CmdletBinding()]
param (
	[Parameter(ParameterSetName = 'Help', Position=1)]
	[Switch]$Help,
	
	[Parameter(ParameterSetName = 'ListCommands')]
	[switch]$List,
	
	[Parameter(ParameterSetName = 'tcpscan')]
	[string]$IpAddress,
	$PortRange = (21,22,23,222,80,81,135,137,139,443,445,8080,3389,3390,1090,1080)
)

	if ($Help -eq $true) {
		Write @"

 ### Invoke-TCPScan HELP ###
 ---------------------------
 
 Invoke-TCPScan [-command] [-parameter(s)]
 
 Available Invoke-TCPScan Commands:
 ----------------------------------
 /---------------------------------------------------------------------/
 | [-IpAddress] ip_address                                             |
 | --------------------------------------------------------------------|
 |                                                                     |
 |  [*] Description: Simple TCP Port Scanner                           |
 |                                                                     |
 |  [*] Mitre ATT&CK Ref: T1423 (Network Service Scanning)             |
 |     (https://attack.mitre.org/techniques/T1423/)                    |
 |                                                                     |
 |  [*] Usage: Invoke-TCPScan -IpAddress 127.0.0.1                     |
 |                                                                     |
 /---------------------------------------------------------------------/
 
"@ 
	}
	elseif ($List -eq $True) {
		Write @"
 
 Invoke-TCPScan Command List:
 ----------------------------
 Invoke-TCPScan [-IpAddress] ip_address
 
"@
	}
	elseif ($IpAddress) {

		$ping = (Test-Connection -Quiet -Count 1 $IpAddress)
#	 	$ping = $true
		if ($Ping) {
	
			foreach ($Port in $PortRange) {
				$TcpClient = New-Object System.Net.Sockets.TcpClient
				$Connect = $TcpClient.BeginConnect($IpAddress, $Port, $Null, $Null)
				$TimeOut = $Connect.AsyncWaitHandle.WaitOne(1, $False)
			
				if (!$TimeOut) {
					$TcpClient.Close() 
					sleep 1
				}
				else {
					Write "Open: $Port"
					$TcpClient.Close()
					sleep 1
				}
			}
		}
		else {
			Write "Host Appears Offline."
		}
	}
}
