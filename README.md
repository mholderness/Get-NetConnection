# Get-NetConnection
PowerShell equivalent(ish) of NetStat via Invoke-Command

 Collects TCP Connections and UDP Endpoints via Get-NetTCPConnection and Get-NETUDPEndpoint respectively; wrapped within Invoke-Command.
 Links the OwningProcess to Services and/or Processes with the GetServiceDetails and/or GetProcessDetails parameters.
 The Windows Firewall log can be parsed via the GetFirewallLog parameter.
 Output can be focused by specifying various other parameters (such as Listen, IPv4, IPv6, TCP and UDP).  See Get-Help Detailed or Full for more information.
