
<#PSScriptInfo

.VERSION 1.0
.GUID b727a4e5-4484-444f-a6ba-ab0ba244d9ec
.AUTHOR Mark Holderness
.TAGS NetStat Get-NetTCPConnection Get-UDPEndPoint Get-FirewallLog

#> 

#Requires -Module NetTCPIP
#Requires -Module Microsoft.PowerShell.Core

<#

.DESCRIPTION 
 PowerShell equivalent(ish) of NetStat via Invoke-Command
 Collects TCP Connections and UDP Endpoints via Get-NetTCPConnection and Get-NETUDPEndpoint respectively; wrapped within Invoke-Command.
 Links the OwningProcess to Services and/or Processes with the GetServiceDetails and/or GetProcessDetails parameters.
 The Windows Firewall log can be parsed via the GetFirewallLog parameter.
 Output can be focused by specifying various other parameters (such as Listen, IPv4, IPv6, TCP and UDP).  See Get-Help Detailed or Full for more information.

.SYNOPSIS
 PowerShell equivalent(ish) of NetStat via Invoke-Command
.EXAMPLE
 .\Get-NetConnection.ps1 -Listen -GetServiceDetails -WriteProgress -Verbose | Select AddressFamily, Protocol, LocalAddress, LocalPort, ServiceDisplayName | Format-Table -AutoSize -Wrap
.EXAMPLE
 .\Get-NetConnection.ps1 'ComputerA','ComputerB' -Listen -IPv4 -GetServiceDetails | Select * -ExcludeProperty Service, TcpConnection | Out-GridView
.EXAMPLE
 'ComputerA','ComputerB' | .\Get-NetConnection.ps1 -Listen -Port 445 -GetFirewallLog -GetServiceDetails | Select * -ExcludeProperty Service, TcpConnection | Out-GridView
.EXAMPLE
 Get-ADComputer -Filter {name -like 'emea-dc1-fs*'} | .\Get-NetConnection.ps1 -Port 3389 -GetServiceDetails -WriteProgress | Tee-Object -Variable RDPNetStat | Select * -ExcludeProperty FirewallLog, Process, ParentProcess, Service, TcpConnection | Out-GridView

#>
[cmdletbinding()]
Param(
	[Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)][Alias("CN","MachineName","DNSHostName")]
	$ComputerName = $Env:Computername,
	<#
		Specifies the properties to return from Get-NetTCPConnection and Get-NETUDPEndpoint.
		Portions of the script require these properties (State is required to link established TCP Connections to Listening ports).
		Parameters within the script may rely on some of these properties.  For example:
			-Listen requires State
			-IPv4 and -IPv6 require LocalAddress to calculate the AddressFamily
			-GetServiceDetails and -GetProcessDetails require OwningProcess to match against Win32_Service and Win32_Process
	#>
	[string[]]$NetProperties = @("CreationTime","LocalAddress","LocalPort","OwningProcess","State"),
	<#
		Return only TCP connections in a Listen state (and UDP endpoints).  By default, all TCP connections and UDP endpoints are returned.
	#>
	[switch]$Listen,
	<#
		Return connections where the Local Address is part of the IPv4 Address Family.
		If the IPv4 parameter is present and the IPv6 parameter is not, only IPv4 connections are returned.
		If both (or neither) of the IPv4 and IPv6 parameters are present, all connections are returned. 
	#>
	[switch]$IPv4,
	<#
		Return connections where the Local Address is part of the IPv6 Address Family.
		If the IPv6 parameter is present and the IPv4 parameter is not, only IPv6 connections are returned.
		If both (or neither) of the IPv4 and IPv6 parameters are present, all connections are returned. 
	#>
	[switch]$IPv6,
	<#
		Return TCP connections.
		If the TCP parameter is present and the UDP parameter is not, only TCP connections are returned.
		If both (or neither) of the TCP and UDP parameters are present, all TCP connections and UDP endpoints are returned. 
	#>
	[switch]$TCP,
	<#
		Return UDP endpoints.
		If the UDP parameter is present and the TCP parameter is not, only UDP endpoints are returned.
		If both (or neither) of the TCP and UDP parameters are present, all TCP connections and UDP endpoints are returned. 
	#>
	[switch]$UDP,
	<#
		Only return results where the LocalPort or RemotePort -eq Port
	#>
	[ValidateRange(1,65535)][uint16[]]$Port,
	<#
		Specifies whether to link a TCP connection or UDP endpoint to Win32_Service by the OwningProcess via Get-CimInstance (if possible, not all Processes are Services).
		Appends the ServiceDisplayName and Service properties to each connection in the output.
	#>
	[switch]$GetServiceDetails,
	[string[]]$ServiceProperties = @("Name","DisplayName","StartName","PathName","Description"),
	<#
		Specifies whether to link a TCP connection or UDP endpoint to Win32_Process by the OwningProcess via Get-CimInstance and Invoke-CimMethod (to inititiate GetOwner).
		Appends the ProcessName, Process, ParentProcessName and ParentProcess properties to each connection in the output.
	#>
	[switch]$GetProcessDetails,
	[string[]]$ProcessProperties = @("Name","Owner","CreationDate","ExecutablePath","CommandLine","Handles","ParentProcessID"),
	<#
		Specifies whether to retrieve Windows Defender firewall logs; making use of Get-NetFirewallSetting, Get-NetFirewallProfile and Get-Content.
		Appends the FirewallLog, FirewallLogAllowCount, FirewallLogAllowRemoteAddress, FirewallLogDropCount, FirewallLogDropRemoteAddress properties to each connection in the output.
	#>
	[switch]$GetFirewallLog,
	<#
		If Windows Defender has been configured to log the Domain, Private and Public profiles to separate files:
			Specifies whether to return logs from the Active Windows Defender firewall profile.  By default, firewall logs from all profiles are returned.
	#>
	[switch]$FirewallLogActiveProfileOnly,
	<#
		Specifies the number of lines to parse from the end of each log file.
			If used with the $TailTime parameter, Tail will occur first and TailTime will filter solely on those log entries.
	#>
	[int32]$FirewallLogTail,
	<#
		Similar to Tail but specifies log entries to return based on their timestamp.
		Timestamp is calculated by converting the date and time fields to [DateTime].
		The denomination used by TailTime can be adjusted with the $TailTimeDenomination parameter.  The default denomination is Minutes.
	#>
	[int32]$FirewallLogTailTime,
	<#
		The denomination referred to in FirewallLogTailTime.  Possible values are Minutes, Hours, Days, Months or Years.  Default value: Minutes.
	#>
	[ValidateSet("Minutes","Hours","Days","Months","Years")][String]$FirewallLogTailTimeDenomination = "Minutes",
	<#
		Specifies whether to call Write-Progress during script execution.
	#>
	[switch]$WriteProgress,
	<#
		Specifies the ID used by Write-Progress if the $WriteProgress parameter is used.
	#>
	[int32]$ProgressID = 1,
	<#
		Specifies how many machines to be queried in parallel.  Defines maxRunspaces when calling [runspacefactory]::CreateRunspacePool.
	#>
	[int32]$Throttle = 5,
	<#
		Specifies whether to call [System.GC]::GetTotalMemory('forceFullCollection').
	#>
	[bool]$ForceGarbageCollection = $True
)
Begin{
	
	$GetNetConnectionScriptBlock = {
		Param (
			$Computer,
			$GetNetConnectionParameters
		)
		$VerbosePreference = $GetNetConnectionParameters.VerbosePreference
		$WriteProgress = $GetNetConnectionParameters.WriteProgress
		Write-Verbose "$(Get-Date) : $Computer : Invoked GetNetConnectionScriptBlock."
		If($WriteProgress) {
			Write-Progress -Activity $Computer -Status "Invoked GetNetConnectionScriptBlock.  Building Invoke-Command parameters." -ID $GetNetConnectionParameters.ProgressID -ParentID $GetNetConnectionParameters.ProgressParentID
		}
		If(Test-NetConnection $Computer -CommonTCPPort WINRM -InformationLevel 'Quiet') {
			$InvokeCommandSplat = @{}
			$InvokeCommandSplat.ComputerName = $Computer
			$InvokeCommandSplat.ScriptBlock = {
				Param (
					$GetNetConnectionParameters
				)
				$Computer = $Env:Computername
				Function Get-SelectProperties($Object,[string[]]$PropertyOrderPreference)
				{	$SelectProperties = @()
					$ObjectProperties = $Object | ForEach-Object {$_.PSObject.Properties.Name} | Select-Object -Unique
					If($PropertyOrderPreference)
					{	ForEach($Property in $PropertyOrderPreference)
						{	If($ObjectProperties -Contains $Property)
							{	$SelectProperties += @{ "Name" = $Property; "Expression" = [scriptblock]::Create("`$`_.`"$Property`"")}
							}
						}
					}
					ForEach($Property in $ObjectProperties)
					{	If($SelectProperties.Name -Contains $Property)
						{	Write-Verbose "$(Get-Date) : $Property already processed due to PropertyOrderPreference."
						}
						Else
						{	#Write-Verbose "$(Get-Date) : $Property to be added to the SelectProperties object."
							$Hash = @{}
							$Hash.Add("Name",$Property)
							$Hash.Add("Expression",[scriptblock]::Create("`$`_.`"$Property`""))
							$SelectProperties += $Hash
						}
					}
					$SelectProperties
				}
				Function Get-FirewallLog
				{	
					[cmdletbinding()]
					Param(
						[uint16[]]$Port,
						[switch]$ActiveProfileOnly,
						[int32]$Tail,
						[DateTime]$TailTimeThreshold,
						[System.Management.Automation.ActionPreference]$VerbosePreference
					)
					$Computer = $Env:Computername
					Write-Verbose "$(Get-Date) : $Computer : Invoke-Command : Get-NetConnection : Get-FirewallLog"
					$GetNetFirewallSplat = [ordered]@{PolicyStore="ActiveStore"}
					If($ActiveProfileOnly) {
						#For($i=0;$i -lt 8;$i++) {"$i {@($([Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile]($i)))}"}
						Write-Verbose "$(Get-Date) : $Computer : Get-FirewallLog : ActiveProfileOnly parameter found.  Get-NetFirewallSetting called to find active firewall profiles."
						$NetFirewallSetting = Get-NetFirewallSetting @GetNetFirewallSplat
						switch ($NetFirewallSetting.Profile) {
							0	{$ActiveProfile = @('Any')}
							1	{$ActiveProfile = @('Domain')}
							2	{$ActiveProfile = @('Private')}
							3	{$ActiveProfile = @('Domain', 'Private')}
							4	{$ActiveProfile = @('Public')}
							5	{$ActiveProfile = @('Domain', 'Public')}
							6	{$ActiveProfile = @('Private', 'Public')}
							7	{$ActiveProfile = @('Domain', 'Private', 'Public')}
						}
					}
					Write-Verbose "$(Get-Date) : $Computer : Get-FirewallLog : Get-NetFirewallProfile called to find firewall profiles."
					$NetFirewallProfile = Get-NetFirewallProfile @GetNetFirewallSplat -All
					If($ActiveProfileOnly -And $ActiveProfile -ne 'Any') {
						Write-Verbose "$(Get-Date) : $Computer : Get-FirewallLog : Filtering NetFirewallProfile to active firewall profiles."
						$NetFirewallProfile = $NetFirewallProfile | Where-Object {$ActiveProfile -Contains $_.Name}
					}
					ForEach($LogFile in ($NetFirewallProfile.LogFileName | Select-Object -Unique)) {
						Write-Verbose "$(Get-Date) : $Computer : Get-FirewallLog : Get-Content against $Computer for $LogFile."
						$Path = "$([System.Environment]::ExpandEnvironmentVariables($LogFile))"
						Write-Verbose "$(Get-Date) : $Computer : Get-FirewallLog : LogFile expanded to $Path"
						Write-Verbose "$(Get-Date) : $Computer : Get-FirewallLog : Get-Content $Path."
						$LogContent = Get-Content $Path | Select-Object -Skip 3
						Write-Verbose "$(Get-Date) : $Computer : Get-FirewallLog : LogContent line count: $($LogContent.Count)."
						If($LogContent.Count -gt 2) {
							Write-Verbose "$(Get-Date) : $Computer : Get-FirewallLog : Retrieving Log File fields."
							$Header = $LogContent[0].Replace("#Fields: ","").Split(" ")
							If($Tail) {
								Write-Verbose "$(Get-Date) : $Computer : Get-FirewallLog : Returning the last $Tail log entries due to -Tail."
								$LogContentStart = $LogContent.Count-$Tail
							}
							Else {
								$LogContentStart = 2
							}
							$LogContentEnd = $LogContent.Count-1
							Write-Verbose "$(Get-Date) : $Computer : Get-FirewallLog : ConvertFrom-Csv running against LogContent found in $LogFile."
							$Logs = ConvertFrom-Csv -InputObject ($LogContent[$LogContentStart..$LogContentEnd]) -Delimiter " " -Header $Header
							Remove-Variable $LogContent
							If($Logs) {
								$FirstLogEntryDateTime = [DateTime]"$($Logs[0].date) $($Logs[0].Time)"
								$LastLogEntryDateTime = [DateTime]"$($Logs[-1].date) $($Logs[-1].Time)"
								Write-Verbose "$(Get-Date) : $Computer : Get-FirewallLog : $($Logs.Count) log entries found."
								Write-Verbose "$(Get-Date) : $Computer : Get-FirewallLog : First log entry: $FirstLogEntryDateTime."
								Write-Verbose "$(Get-Date) : $Computer : Get-FirewallLog : Last log entry: $LastLogEntryDateTime."
								If($TailTimeThreshold) {
									Write-Verbose "$(Get-Date) : $Computer : Get-FirewallLog : Filtering log entries based on TailTimeThreshold: $TailTimeThreshold"
									$Logs = ForEach($Log in $Logs) {
										$LogDateTime = [DateTime]"$($Log.date) $($Log.Time)"
										If($LogDateTime -gt $TailTimeThreshold) {
											Add-Member -InputObject $Log -NotePropertyName DateTime -NotePropertyValue $LogDateTime
											$Log
										}
									}
									$FirstLogEntryDateTime = [DateTime]"$($Logs[0].date) $($Logs[0].Time)"
									$LastLogEntryDateTime = [DateTime]"$($Logs[-1].date) $($Logs[-1].Time)"
									Write-Verbose "$(Get-Date) : $Computer : Get-FirewallLog : $($Logs.Count) log entries found."
									Write-Verbose "$(Get-Date) : $Computer : Get-FirewallLog : First log entry: $FirstLogEntryDateTime."
									Write-Verbose "$(Get-Date) : $Computer : Get-FirewallLog : Last log entry: $LastLogEntryDateTime."		
								}
								If($Port) {
									Write-Verbose "$(Get-Date) : $Computer : Get-FirewallLog : Filtering log entries based on Port: $($Port)"
									$Logs = ForEach($Log in $Logs) {
										If($Port -Contains [uint16]$_.'src-port' -Or $Port -Contains [uint16]$_.'dst-port') {
											$Log
										}
									}
									Write-Verbose "$(Get-Date) : $Computer : Get-FirewallLog : $($Logs.Count) log entries found."
								}
								Write-Verbose "$(Get-Date) : $Computer : Get-FirewallLog : Appending custom properties to log entries."
								$Logs | Select-Object *,
									@{n="LocalPort";e={	If($_.Path -eq "RECEIVE") {$_."dst-port"} ElseIf($_.Path -eq "SEND") {$_."src-port"} Else {"WTF"}}},
									@{n="RemotePort";e={ If($_.Path -eq "RECEIVE") {$_."src-port"} ElseIf($_.Path -eq "SEND") {$_."dst-port"} Else {"WTF"}}},
									@{n="LocalAddress";e={ If($_.Path -eq "RECEIVE") {$_."dst-ip"} ElseIf($_.Path -eq "SEND") {$_."src-ip"} Else {"WTF"}}},
									@{n="RemoteAddress";e={ If($_.Path -eq "RECEIVE") {$_."src-ip"} ElseIf($_.Path -eq "SEND") {$_."dst-ip"} Else {"WTF"}}},
									@{n="Ports";e={@($_."src-port",$_."dst-port")}},
									@{n="IPs";e={@($_."src-ip",$_."dst-ip")}},
									@{n="AddressFamily";e={@($_."src-ip",$_."dst-ip") | ForEach-Object {([IPAddress]$_).AddressFamily} | Select-Object -Unique | ForEach-Object {If($_ -eq "InterNetwork") {"IPv4"}ElseIf("InterNetworkV6") {"IPv6"}}}},
									@{n="LogSource";e={$Computer}}
							}
						}
					}
				}
				Function Get-NetConnection
				{
					[cmdletbinding()]
					Param(
						[string[]]$NetProperties,
						[switch]$Listen,
						[switch]$IPv4,
						[switch]$IPv6,
						[switch]$TCP,
						[switch]$UDP,
						[int[]]$Port,
						[switch]$GetServiceDetails,
						[string[]]$ServiceProperties,
						[switch]$GetProcessDetails,
						[string[]]$ProcessProperties,
						[switch]$GetFirewallLog,
						[switch]$FirewallLogActiveProfileOnly,
						[int32]$FirewallLogTail,
						[DateTime]$FirewallLogTailTimeThreshold,
						[switch]$WriteProgress,
						[int32]$ProgressID,
						[int32]$ProgressParentID,
						[System.Management.Automation.ActionPreference]$VerbosePreference
					)
					$Computer = $Env:Computername
					Write-Verbose "$(Get-Date) : $Computer : Invoke-Command : Get-NetConnection"
					If($WriteProgress) {
						Write-Progress -Activity $Computer -Status "Invoke-Command : Get-NetConnection" -ID $ProgressID -ParentID $ProgressParentID
					}
					Foreach($PSBoundParameter in $PSBoundParameters.GetEnumerator())
					{	Write-Verbose "$(Get-Date) : $Computer : Get-NetConnection | PSBoundParameter: $($PSBoundParameter.Key) = $($PSBoundParameter.Value)"
					}				
					If($GetServiceDetails) {
						Write-Verbose "$(Get-Date) : $Computer : Get-NetConnection : GetServiceDetails"
						If($WriteProgress) {
							Write-Progress -Activity $Computer -Status "Invoke-Command : Get-NetConnection : GetServiceDetails" -ID $ProgressID -ParentID $ProgressParentID
						}
						Write-Verbose "$(Get-Date) : $Computer : Get-NetConnection : GetServiceDetails : Get-CimInstance Win32_Service to link the owning process of connections to Process IDs of Services."
						If($ServiceProperties -notcontains "DisplayName") {$ServiceProperties += "DisplayName"}
						$Win32Service = @{}
						Get-CimInstance Win32_Service -Filter 'State="Running"' | ForEach-Object {
							$ServiceKey = $_.ProcessId
							$ServiceValue = [ordered]@{}
							ForEach($ServiceProperty in $ServiceProperties) {
								If($_."$ServiceProperty") {
									$ServiceValue."$ServiceProperty" = $_."$ServiceProperty"
								}
							}
							If($Win32Service.ContainsKey($ServiceKey)) {
							}
							Else {
								$Win32Service.Add($ServiceKey,[System.Collections.ArrayList]::new())
							}			
							[void]$Win32Service.$ServiceKey.Add([PSCustomObject]$ServiceValue)
						}
					}
					If($GetProcessDetails) {
						Write-Verbose "$(Get-Date) : $Computer : Get-NetConnection : GetProcessDetails"
						If($WriteProgress) {
							Write-Progress -Activity $Computer -Status "Invoke-Command : Get-NetConnection : GetProcessDetails" -ID $ProgressID -ParentID $ProgressParentID
						}
						Write-Verbose "$(Get-Date) : $Computer : Get-NetConnection : GetProcessDetails : Get-CimInstance Win32_Process to link the owning process of connections to Process IDs of Processes."
						If($ProcessProperties -notcontains "Name") {$ProcessProperties += "Name"}
						$Win32Process = @{}
						Get-CimInstance Win32_Process | ForEach-Object {
							$ProcessKey = $_.ProcessId
							$ProcessValue = [ordered]@{}
							$ProcessValue.Name = $_.Name
							If($ProcessProperties -Contains 'Owner') {
								$ProcessValue.Owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner | ForEach-Object{
									If($_.ReturnValue -eq 0) {
										@($_.Domain,$_.User) -Join "\"
									}
									Else {
										"Error.  ReturnValue: $($_.ReturnValue)."
									}
								}
							}
							ForEach($ProcessProperty in $ProcessProperties) {
								If($_."$ProcessProperty") {
									$ProcessValue."$ProcessProperty" = $_."$ProcessProperty"
								}
							}
							$Win32Process.Add($ProcessKey,[PSCustomObject]$ProcessValue)
						}
					}
					If($GetFirewallLog) {
						Write-Verbose "$(Get-Date) : $Computer : Get-NetConnection : GetFirewallLog"
						If($WriteProgress) {
							Write-Progress -Activity $Computer -Status "Invoke-Command : Get-NetConnection : GetFirewallLog" -ID $ProgressID -ParentID $ProgressParentID
						}
						$GetFirewallLogSplat = [ordered]@{}
						If($Port) {
							$GetFirewallLogSplat.Port = $Port
						}
						If($FirewallLogActiveProfileOnly) {
							$GetFirewallLogSplat.ActiveProfileOnly = $True
						}
						If($FirewallLogTail) {
							$GetFirewallLogSplat.Tail = $FirewallLogTail
						}
						If($FirewallLogTailTimeThreshold) {
							$GetFirewallLogSplat.TailTimeThreshold = $FirewallLogTailTimeThreshold
						}
						$GetFirewallLogSplat.VerbosePreference=$VerbosePreference
						Foreach($GetFirewallLogParameter in $GetFirewallLogSplat.GetEnumerator())
						{	Write-Verbose "$(Get-Date) : $Computer : Get-NetConnection | GetFirewallLog: $($GetFirewallLogParameter.Key) = $($GetFirewallLogParameter.Value)"
						}
						$FirewallLog = @{}
						ForEach($FirewallLogEntry in (Get-FirewallLog @GetFirewallLogSplat)) {
							$FirewallLogEntryKey = "$($FirewallLogEntry.Action)$($FirewallLogEntry.AddressFamily)$($FirewallLogEntry.Protocol)$($FirewallLogEntry.LocalPort)"
							If($FirewallLog.ContainsKey($FirewallLogEntryKey)) {
							}
							Else {
								$FirewallLog.$FirewallLogEntryKey = [System.Collections.ArrayList]::new()
							}
							[void]$FirewallLog.$FirewallLogEntryKey.Add($FirewallLogEntry)
						}
					}
	
					$NetConnections = [System.Collections.ArrayList]::new()
					Write-Verbose "$(Get-Date) : $Computer : Get-NetConnection : Getting TCP connections and/or UDP endpoints."
					If($WriteProgress) {
						Write-Progress -Activity $Computer -Status "Invoke-Command : Get-NetConnection : Getting TCP connections and/or UDP endpoints." -ID $ProgressID -ParentID $ProgressParentID
					}
					If($TCP -Or !$UDP) {
						Write-Verbose "$(Get-Date) : $Computer : Get-NetConnection : Get-NetTCPConnection."
						[array]$NetTCPConnection = Get-NetTCPConnection
						If($Port) {
							Write-Verbose "$(Get-Date) : $Computer : Get-NetConnection : Get-NetTCPConnection : Filtering Get-NetTCPConnection results ($($NetTCPConnection.Count)) via Port and populating NetConnections ArrayList."
							$NetTCPConnection | Where-Object {$Port -Contains $_.LocalPort -Or $Port -Contains $_.RemotePort} | ForEach-Object { [void]$NetConnections.Add($_) }	
						}
						Else {
							Write-Verbose "$(Get-Date) : $Computer : Get-NetConnection : Get-NetTCPConnection : Add Get-NetTCPConnection results ($($NetTCPConnection.Count)) to NetConnections ArrayList."
							$NetTCPConnection | ForEach-Object { [void]$NetConnections.Add($_) }	
						}
					}
					If($UDP -Or !$TCP) {
						Write-Verbose "$(Get-Date) : $Computer : Get-NetConnection : Get-NetUDPEndpoint."
						[array]$NetUDPEndpoint = Get-NetUDPEndpoint
						If($Port) {
							Write-Verbose "$(Get-Date) : $Computer : Get-NetConnection : Get-NetUDPEndpoint : Filtering Get-NetUDPEndpoint ($($NetUDPEndpoint.Count)) via Port and populating NetConnections ArrayList."
							$NetUDPEndpoint | Where-Object {$Port -Contains $_.LocalPort -Or $Port -Contains $_.RemotePort} | ForEach-Object { [void]$NetConnections.Add($_) }	
						}
						Else {
							Write-Verbose "$(Get-Date) : $Computer : Get-NetConnection : Get-NetUDPEndpoint : Add Get-NetUDPEndpoint ($($NetUDPEndpoint.Count)) results to NetConnections ArrayList."
							$NetUDPEndpoint | ForEach-Object { [void]$NetConnections.Add($_) }	
						}
					}
					Write-Verbose "$(Get-Date) : $Computer : Get-NetConnection : $($NetConnections.Count) connections in NetConnections ArrayList to process."
					$NetworkConnection = ForEach($NetConnection in $NetConnections) {
						If($WriteProgress) {
							Write-Progress -Activity $Computer -Status "Invoke-Command : Get-NetConnection : Processing TCP connections and/or UDP endpoints." -ID $ProgressID -ParentID $ProgressParentID
						}
						$NetConnectionProperties = [Ordered]@{Computer=$Computer}
						If($NetProperties -Contains "LocalAddress") {
							$NetConnectionProperties.AddressFamily = switch (([IPAddress]$NetConnection.LocalAddress).AddressFamily) {
								"InterNetwork"		{"IPv4"}
								"InterNetworkV6"	{"IPv6"}
							}
							If($IPv4 -Or $IPv6) {
								If($NetConnectionProperties.AddressFamily -eq "IPv4" -And !$IPv4) {
									Write-Verbose "$(Get-Date) : $Computer : Get-NetConnection : $($NetConnectionProperties.AddressFamily) excluded.  Parameters: IPv4 ($IPv4) & IPv6 ($IPv6)."
									continue
								}
								If($NetConnectionProperties.AddressFamily -eq "IPv6" -And !$IPv6) {
									Write-Verbose "$(Get-Date) : $Computer : Get-NetConnection : $($NetConnectionProperties.AddressFamily) excluded.  Parameters: IPv4 ($IPv4) & IPv6 ($IPv6)."
									continue
								}
							}
						}
						$NetConnectionProperties.Protocol = switch ($NetConnection.CimClass.CimClassName) {
							"MSFT_NetTCPConnection"	{"TCP"}
							"MSFT_NetUDPEndpoint"	{"UDP"}
						}
						ForEach($NetProperty in $NetProperties) {
							$NetConnectionProperties."$NetProperty" = $NetConnection."$NetProperty"
						}
						If($GetFirewallLog) {
							If(($NetConnectionProperties.Protocol -eq "TCP" -And $NetConnection.State -eq "Listen") -Or $NetConnectionProperties.Protocol -eq "UDP") {
								#Attach firewall logs for TCP Connections in the Listen state and UDP endpoints 
								$NetConnectionProperties.FirewallLog = [PSCustomObject][Ordered]@{
									Allow=""
									Drop=""
								}
								$FirewallLogAllowKey = "ALLOW$($NetConnectionProperties.AddressFamily)$($NetConnectionProperties.Protocol)$($NetConnectionProperties.LocalPort)"
								If($FirewallLog.ContainsKey($FirewallLogAllowKey)) {
									$NetConnectionProperties.FirewallLog.Allow = $FirewallLog.$FirewallLogAllowKey
									$NetConnectionProperties.FirewallLogAllowCount = $NetConnectionProperties.FirewallLog.Allow.Count
									$NetConnectionProperties.FirewallLogAllowRemoteAddress = (($NetConnectionProperties.FirewallLog.Allow).RemoteAddress | Select-Object -Unique) -Join "`r`n"
								}
								$FirewallLogDropKey = "DROP$($NetConnectionProperties.AddressFamily)$($NetConnectionProperties.Protocol)$($NetConnectionProperties.LocalPort)"
								If($FirewallLog.ContainsKey($FirewallLogDropKey)) {
									$NetConnectionProperties.FirewallLog.Drop = $FirewallLog.$FirewallLogDropKey
									$NetConnectionProperties.FirewallLogDropCount = $NetConnectionProperties.FirewallLog.Drop.Count
									$NetConnectionProperties.FirewallLogDropRemoteAddress = (($NetConnectionProperties.FirewallLog.Drop).RemoteAddress | Select-Object -Unique) -Join "`r`n"
								}
							}
						}
						If($NetProperties -Contains "State") {
							If($NetConnectionProperties.Protocol -eq "TCP") {
								If($NetConnection.State -eq "Listen") {
									#Stage properties for TCP connections directed at listening TCP ports.
									$NetConnectionProperties.TcpConnection = [System.Collections.ArrayList]::new()
									$NetConnectionProperties.TcpConnectionSummary = ""
								}
								Else {
									#Record properties for TCP connections directed at listening TCP ports.
									$NetConnectionProperties.RemoteAddress = $NetConnection.RemoteAddress
									$NetConnectionProperties.RemotePort = $NetConnection.RemotePort
								}
							}
						}
						If($GetServiceDetails -And $NetConnection.OwningProcess) {
							$Service = $Win32Service.($NetConnection.OwningProcess)
							If($Service) {
								$NetConnectionProperties.ServiceDisplayName = $Service.DisplayName -Join "`r`n"
								$NetConnectionProperties.Service = $Service
							}
						}
						If($GetProcessDetails -And $NetConnection.OwningProcess) {
							$Process = $Win32Process.($NetConnection.OwningProcess)
							If($Process) {
								$NetConnectionProperties.ProcessName = $Process.Name
								$NetConnectionProperties.Process = $Process
								If($Process.ParentProcessId) {
									$ParentProcess = $Win32Process.($Process.ParentProcessId)
									If($ParentProcess) {
										$NetConnectionProperties.ParentProcessName = $ParentProcess.Name
										$NetConnectionProperties.ParentProcess = $ParentProcess
									}
								}
							}
						}
						[PSCustomObject]$NetConnectionProperties
					}
					Write-Verbose "$(Get-Date) : $Computer : Get-NetConnection : $($NetworkConnection.Count) connections processed.  Linking TCP connections not in a Listen state to TCP connections in a Listen state."
					If($NetProperties -Contains "State") {
						If($WriteProgress) {
							Write-Progress -Activity $Computer -Status "Invoke-Command : Get-NetConnection : Linking TCP connections to listening ports." -ID $ProgressID -ParentID $ProgressParentID
						}
						ForEach($NetConnection in ($NetworkConnection | Where-Object {$_.Protocol -eq "TCP" -And $_.State -eq "Listen"})) {
							[array]$TcpConnections = $NetworkConnection | Where-Object {$_.Protocol -eq "TCP" -And $_.AddressFamily -eq $NetConnection.AddressFamily -And $_.LocalPort -eq $NetConnection.LocalPort}
							If($TcpConnections.Count -ge 1) {
								ForEach($TcpConnection in ($TcpConnections | Where-Object State -ne "Listen")) {
									[void]$NetConnection.TcpConnection.Add($TcpConnection)
								}
								If($NetConnection.TcpConnection.Count -ge 1) {
									Write-Verbose "$(Get-Date) : $Computer : Get-NetConnection : $($NetConnection.TcpConnection.Count) TCP connection(s) found that match the AddressFamily ($($NetConnection.AddressFamily)) and LocalPort $($NetConnection.LocalPort) of a listening service or process."
									$NetConnection.TcpConnectionSummary = ($NetConnection.TcpConnection | Group-Object RemoteAddress, State | ForEach-Object {"$($_.Name), $($_.Count)"}) -Join "`r`n"
								}
							}
						}
					}
					If($Listen) {
						Write-Verbose "$(Get-Date) : $Computer : Get-NetConnection : Filtering $($NetworkConnection.Count) connections to only include TCP connections in a Listen state and UDP endpoints."
						$NetworkConnection | Where-Object {($_.Protocol -eq "TCP" -And $_.State -eq "Listen") -Or $_.Protocol -eq "UDP"} | Select-Object (Get-SelectProperties $NetworkConnection)
					}
					Else {
						Write-Verbose "$(Get-Date) : $Computer : Get-NetConnection : Returning $($NetworkConnection.Count) connections."
						$NetworkConnection | Select-Object (Get-SelectProperties $NetworkConnection)
					}
				}
	
				Get-NetConnection @using:GetNetConnectionParameters
			}
			Write-Verbose "$(Get-Date) : $Computer : Calling Invoke-Command."
			If($WriteProgress) {
				Write-Progress -Activity $Computer -Status "Calling Invoke-Command." -ID $GetNetConnectionParameters.ProgressID -ParentID $GetNetConnectionParameters.ProgressParentID
			}
			Invoke-Command @InvokeCommandSplat
			If($WriteProgress) {
				Write-Progress -Activity $Computer -ID $GetNetConnectionParameters.ProgressID -ParentID $GetNetConnectionParameters.ProgressParentID -Completed
			}

		}
		Else {
			Write-Warning "$(Get-Date) : $Computer : `'Test-NetConnection $Computer -Port 5985 -InformationLevel Quiet`' failed."
		}

	}

	$GetNetConnectionParameters = @{}
	ForEach($Parameter in @('NetProperties','Listen','IPv4','IPv6','TCP','UDP','Port','GetServiceDetails','ServiceProperties','GetProcessDetails','ProcessProperties','GetFirewallLog','FirewallLogActiveProfileOnly','FirewallLogTail','WriteProgress','VerbosePreference')) {
		$Variable = $Null; $Variable = Get-Variable $Parameter
		If($Variable) {
			$GetNetConnectionParameters."$($Variable.Name)" = $Variable.Value
			Write-Verbose "$(Get-Date) : Parameters : $($Variable.Name) = $($Variable.Value)."
		}
	}

	If($FirewallLogTailTime) {
		Write-Verbose "$(Get-Date) : FirewallLogTailTime parameter passed based on $FirewallLogTailTime $FirewallLogTailTimeDenomination.  Calculating threshold."
		$Now = [datetime]::Now
		$GetNetConnectionParameters.FirewallLogTailTimeThreshold = Switch ($FirewallLogTailTimeDenomination) {
			'Minutes'	{ $Now.AddMinutes(-$FirewallLogTailTime) }
			'Hours'		{ $Now.AddHours(-$FirewallLogTailTime) }
			'Days'		{ $Now.AddDays(-$FirewallLogTailTime) }
			'Months'	{ $Now.AddMonths(-$FirewallLogTailTime) }
			'Years'		{ $Now.AddYears(-$FirewallLogTailTime) }
		}
	}

	If($WriteProgress) {
		Write-Progress -Activity "$($MyInvocation.MyCommand.Name)" -ID $ProgressID
		$GetNetConnectionParameters.ProgressParentID = $ProgressID
		$GetNetConnectionParameters.ProgressID = $ProgressID+1
	}

	$SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
	$RunspacePool = [runspacefactory]::CreateRunspacePool(1, $Throttle, $SessionState, $Host)
	$RunspacePool.Open()
	$RunspaceJobs = New-Object System.Collections.ArrayList

	Function Get-RunspaceResults
	{
		param(
			$RunspaceJobs,
			[switch]$Wait
		)
		Do {
			$InstanceHasData = $false
			ForEach($Instance in $RunspaceJobs) {
				If($Instance.Job.isCompleted) {
					$Instance.PowerShell.EndInvoke($Instance.Job)
					$Instance.powershell.Dispose()
					$Instance.Job = $Null
					$Instance.PowerShell = $Null
					If($ForceGarbageCollection) {
						$GarbageCollectionMaxGeneration = [System.GC]::MaxGeneration
						$GarbageCollectionLogContentVariableGeneration = [System.GC]::GetGeneration($Instance)
						$GarbageCollectionTotalMemory = [math]::ceiling(([System.GC]::GetTotalMemory($False))/1MB*100)/100
						Write-Verbose "GC::GetGeneration(<Variable>) : $GarbageCollectionLogContentVariableGeneration | GC::MaxGeneration : $GarbageCollectionMaxGeneration | GC::TotalMemory : $GarbageCollectionTotalMemory"
						Write-Verbose "Invoke GC::Collect()"
						[System.GC]::Collect()
						$GarbageCollectionTotalMemory = [math]::ceiling(([System.GC]::GetTotalMemory($False))/1MB*100)/100
						Write-Verbose "GC::TotalMemory : $GarbageCollectionTotalMemory"
						Write-Verbose "Invoke GC::GetTotalMemory(forceFullCollection)"
						$GarbageCollectionTotalMemory = [math]::ceiling(([System.GC]::GetTotalMemory($True))/1MB*100)/100
						Write-Verbose "GC::TotalMemory : $GarbageCollectionTotalMemory"
					}
				}
				ElseIf($Null -ne $Instance.Job) {
					$InstanceHasData = $True
				}
			}
			If($InstanceHasData -and $Wait) {
				Start-Sleep -Milliseconds 100
			}
		}
		While ($InstanceHasData -and $Wait)
	}

}
Process {
	ForEach($Computer in $ComputerName) {
		If($Computer.GetType().FullName -eq "Microsoft.ActiveDirectory.Management.ADComputer") {
			Do {
				ForEach($Property in @('DNSHostname','Name','CN')) {
					If($Null -ne $Computer.$Property) {
						Write-Verbose "$(Get-Date) : $Computer : Using ADComputer property $Property : $($Computer.$Property)"
						$Computer = $Computer.$Property
						break
					}
				}
			}
			Until ($Computer.GetType().FullName -eq "System.String" -Or $Property -eq 'CN')
		}
		If($Computer.GetType().FullName -eq "Microsoft.ActiveDirectory.Management.ADComputer") {
			Write-Verbose "$(Get-Date) : $Computer : Unable to convert to ComputerName or DNS hostname."
			continue
		}
		Write-Verbose "$(Get-Date) : $Computer."
		$GetNetConnectionParameters.ProgressID++
		$PowerShell = [powershell]::Create().AddScript($GetNetConnectionScriptBlock).AddArgument($Computer).AddArgument($GetNetConnectionParameters)
		$PowerShell.RunspacePool = $RunspacePool
		$RunspaceProperties = [Ordered]@{}
		$RunspaceProperties.PowerShell = $PowerShell
		$RunspaceProperties.Job = $PowerShell.BeginInvoke()
		[void]$RunspaceJobs.Add([PSCustomObject]$RunspaceProperties)
		Get-RunspaceResults $RunspaceJobs
	}
}
End {
	Get-RunspaceResults $RunspaceJobs -Wait
	If($WriteProgress) {
		Write-Progress -Activity "$($MyInvocation.MyCommand.Name)" -ID $ProgressID -Completed
	}
}


