
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
  adaptersInfo = $adapterInfo
  proxy = $proxy
  vpn = $vpn
  domainName = $domainName
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

# Retrieve version information
$firefoxPath = 'HKLM:\SOFTWARE\Mozilla\Mozilla Firefox'
$firefoxVersion = (Get-ItemProperty -Path $firefoxPath -Name "CurrentVersion").CurrentVersion

# Retrieve add-ons installed
$firefoxAddOnsPath = "$env:APPDATA\Mozilla\Firefox\Profiles\*\extensions"
$firefoxAddOns = Get-ChildItem -Path $firefoxAddOnsPath -Directory | ForEach-Object { $_.Name }

# Retrieve installed user certificates
$firefoxCertificatesPath ='"Cert:\CurrentUser\My'
$firefoxCertificates = Get-ChildItem -Path $firefoxCertificatesPath | Select-Object -ExpandProperty Thumbprint

# Retrieve registered identifiers
$firefoxIdentifiersPath = 'HKCU:\Software\Mozilla\Firefox\RegisteredApplications'
$firefoxIdentifiers = Get-Item -Path $firefoxIdentifiersPath | Select-Object -ExpandProperty Property

# Get firefox Profiles
$firefoxProfilePath = "$env:APPDATA\Mozilla\Firefox\Profiles\*"
$firefoxProfile = (Get-ChildItem -Path $firefoxProfilePath -Directory | Select-Object -Last 1).FullName

# Get favorites 
$firefoxFavoritesPath = "$FirefoxProfile\bookmarkbackups"
$firefoxFavorites = (Get-ChildItem -Path $firefoxFavoritesPath -Filter "bookmarks*.json" | Select-Object -Last 1).FullName

# Get history
$firefoxHistoryPath = "$FirefoxProfile\places.sqlite"
$firefoxHistory = (Get-ChildItem -Path $firefoxHistoryPath).FullName

$firefox = [PSCustomObject]@{
  version = $firefoxVersion
  addOns = $firefoxAddOns
  certificates = $firefoxCertificates
  identifiers = $firefoxIdentifiers
  favorites = $firefoxFavorites
  history = $firefoxHistory
}

#------------- Longon cached -------------#

# Get the currently connected user accounts
$connectedAccounts = Get-LocalUser | Where-Object { $_.Enabled -eq $true}

# Get the cached accounts on the local machine
$cachedAccounts = Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.LocalAccount -eq $true }

$accounts = [PSCustomObject]@{
  logged = $connectedAccounts
  cached = $cachedAccounts
}

#------------- Applications Information -------------#

# Get a list of installed applications
$applications32Path = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
$applicationsPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" 
$applications = Get-ItemProperty $applications32Path, $applicationsPath|
  Where-Object { $_.DisplayName -and !$_.SystemComponent } |
  Select-Object DisplayName, Publisher, DisplayVersion

#------------- Start Menu -------------#

# Get information of start menu
$startMenuPath = "$env:APPDATA\Microsoft\Windows\Start Menu"
$startMenuItems = Get-ChildItem -Path $startMenuPath -Recurse | Where-Object { $_.Name -notlike "desktop.ini" }

#------------- Scheduled Tasks -------------#

# Get a list of scheduled tasks
$scheduledTasks = Get-ScheduledTask | Select-Object TaskName, TaskPath, State, LastRunTime, NextRunTime

#------------- Active Process -------------#

# Get a list of active process
$activeProcess = Get-Process | Select-Object Id,Name,MainWindowTitle

#------------- Activeport -------------#

# Get a list of active port
$activeTCPPorts = Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort | Format-Table

#------------- Export json -------------#

# Recap object
$finalObject = [PSCustomObject]@{
  net = $net
  defaultWebBrowser = $defaultWebBrowser
  firefox = $firefox
  accounts = $accounts
  applications = $applications
  startMenu = $startMenuItems
  scheduledTasks = $scheduledTasks
  activeProcess = $activeProcess
  activePort = $activeTCPPorts
}

# Save data as json file
ConvertTo-Json $finalObject | Set-Content result.json
