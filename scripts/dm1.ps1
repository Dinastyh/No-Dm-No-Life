
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
$proxyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$proxy = (Get-ItemProperty -Path $proxyPath).ProxyServer

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

#------------- Default Web-Browser -------------#

# Get the default web browser version
$startupMenuPath = 'HKLM:\SOFTWARE\Clients\StartMenuInternet'
$defaultInternetPath = 'HKLM:\SOFTWARE\Clients\StartMenuInternet'
$browserVersion = Get-ItemProperty  $startupMenuPath | Select-Object -ExpandProperty (Get-ItemProperty $defaultInternetPath | Where-Object {$_.Default}).Version

# Get the names of installed browser add-ons
$addOnsPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Ext\Settings'
$addOns = Get-ChildItem $addOnsPath | Select-Object -ExpandProperty Name

# Get the thumbprints of installed user certificates
$certificatesPath = 'Cert:\CurrentUser\My'
$certificates = Get-ChildItem $certificatesPath | Select-Object -ExpandProperty Thumbprint

# Get the names of registered identifiers
$identifiersPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\IdentityCRL\StoredIdentities'
$identifiers = Get-ChildItem $identifiersPath | Select-Object -ExpandProperty Name

# Get the URLs of user favorites
$favoritesPath = "$env:USERPROFILE\Favorites"
$favorites = (Get-ChildItem $favoritesPath -Recurse -Include *.url).FullName

# Get the URLs and titles of browser history
$historyPath = "$env:LOCALAPPDATA\Microsoft\Windows\WebCache\V01"
$history = Get-ChildItem $historyPath -Recurse | Where-Object {$_.Name -eq "WebCacheV01.dat"} | Select-Object -ExpandProperty FullName | ForEach-Object {((New-Object -ComObject 'Shell.Application').NameSpace('shell:').ParseName($_).GetFolder).Items()} | Select-Object -Property Name, Folder

$defaultWebBrowser = [PSCustomObject]@{
  browserVersion = $browserVersion
  addOns = $addOns
  certificates = $certificates
  identifiers = $identifiers
  favorites = $favorites
  history = $history
}


#------------- Firefox -------------#



#------------- Export json -------------#

# Recap object
$finalObject = [PSCustomObject]@{
  Net = $net
  DefaultWebBrowser = $defaultWebBrowser
}

# Save data as json file
ConvertTo-Json $finalObject | Set-Content result.json
