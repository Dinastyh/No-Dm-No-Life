
#------------- Network -------------#

# Get network adapters and select wireless adapters only
$adapters = Get-NetAdapter

# Get IP address, subnet mask, default gateway, and MAC address for each adapter
$adapterInfo = foreach ($adapter in $adapters)
{
  $ipconfig = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex | Where-Object {$_.AddressFamily -eq "IPv4"}
  $ipAddress = $ipconfig.IPAddress
  $subnetMask = $ipconfig.PrefixLength
  $gateway = (Get-NetRoute -InterfaceIndex $adapter.ifIndex | Where-Object {$_.DestinationPrefix -eq "0.0.0.0/0.0.0.0"}).NextHop
  $macAddress = $adapter.MacAddress
  $dnsServers = (Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex).ServerAddresses

  # Output the information for this adapter
  [PSCustomObject]@{
    IPAddress = $ipAddress
    SubnetMask = $subnetMask
    DefaultGateway = $gateway
    MacAddress = $macAddress
    DnsServers = $dnsServers
  }
}

# Get configured proxy
$proxy = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyServer

# Get configured VPN
$vpn = Get-VpnConnection | Select-Object -ExpandProperty Name

# Get domain name
$domainName = ([System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()).DomainName

# Get computer name
$computerName = $env:COMPUTERNAME

# Net data request
$net = [PSCustomObject]@{
  AdaptersInfo = $adapterInfo
  Proxy = $proxy
  Vpn = $vpn
  DomainName = $domainName
  computerName = $computerName
}
#Miss wifi 






# Recap object
$final_object = [PSCustomObject]@{
  Net = $net
}

# Save data as json file
ConvertTo-Json $final_object | Set-Content result.json
