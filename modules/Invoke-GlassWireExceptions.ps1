function Invoke-GlasswireExceptions {
<# 
.SYNOPSIS
Dumps GlassWire Exceptions for allowed outbound internet connectivity.

.EXAMPLE
PS> . .\Invoke-GlasswireExceptions.ps1

Author: (@0rbz_)

# https://github.com/securemode/RTK/blob/master/PowerShell/Get-GlasswireExceptions.ps1
#>

	Write "`n"
	Write "GlassWire Exceptions List"
	Write "-------------------------"
	$RegKey = (Get-ItemProperty 'HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules')
	$RegKey.PSObject.Properties | ForEach-Object {
	  If($_.Value -like '*Active=TRUE*' -and $_.Value -like '*Allow*' -and $_.Value -like '*Dir=Out|App=*'){
		Write-Output $_.Value | ForEach-Object {$_.split("|")} | Select-String -pattern "^App"
	  }
	}
	Write "`n"
}