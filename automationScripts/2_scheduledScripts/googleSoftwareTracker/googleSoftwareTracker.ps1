### google software tracker script

#script to write tracker data to google sheets and/or PPMS

##requires a .p12 certificate file to be generated from the google sheets website first
#Run this script once as an Admin by right clicking powershell_ISE "run as admin"
#On first run, the script will create a new google sheet to store ppms tracker information
#follow instructions in .pdf stored with this file to setup the google sheets API

#Once the sheet is created, run script once a minute via task scheduler to update tracker data in the created google sheet



### Template scripts and functions ###
#Define a ps2exe compiler compatible script path variable, this cant run inside a sub-script
if ($MyInvocation.MyCommand.CommandType -eq "ExternalScript"){
    $ScriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition 
}else{
    $ScriptPath = Split-Path -Parent -Path ([Environment]::GetCommandLineArgs()[0]) 
    if (!$ScriptPath){ $ScriptPath = "." } 
}

Function wait {   
    Start-Sleep -Milliseconds 50  #delay for reading/writing to registry etc
}

function scriptName { 
    $myScriptPath = ($MyInvocation.Scriptname).Substring($ScriptPath.Length+1) -split(".ps1")
    return $myScriptPath[0]
}

function logdata($inputLog){
    #log data to console 
    try{if(![string]::IsNullOrEmpty($logToConsole)){if($logToConsole){$inputLog}}
    }catch{""}

    #log to file
    try{$logPathExists = (Test-Path $logPath)}catch{$logPathExists = $false}
    if($logToFile -and $logPathExists -and ![string]::IsNullOrEmpty($inputLog)){
        Add-Content -Path $logPath -Value $inputLog
    }elseif($logToFile -and !$logPathExists -and ![string]::IsNullOrEmpty($inputLog)){
        $global:log = $global:log + "`r`n"  + $inputLog
    }
}

function setFilePermissions($inputPath) {
    #set file/folder permissions
    try{
        # Get the existing ACL
        $acl = Get-Acl -Path $inputPath
        $rule1 = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($rule1)
        $rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($rule2)
        Set-Acl $inputPath $acl
        start-sleep -Milliseconds 500
        logdata "Set file/folder Permissions for $inputPath" 
    }catch{logdata "couldnt set file/folder permissions for $inputPath" }
}

function setRegPermissions ($inputReg) {
    #set registry access permissions for all users
    try{
        $acl = Get-Acl $($inputReg)
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule ("BUILTIN\Users","FullControl","ContainerInherit, ObjectInherit", "None", "Allow")
        $acl.SetAccessRule($rule)
        $acl |Set-Acl -Path $inputReg
        logdata "permissions set for registry $inputReg" 
    }catch{logdata "couldnt set registry permissions for $inputReg" }
}

function makeKey {
    param(
        [Parameter(Position=0,mandatory=$true)]
        [string] $regPath,
        [Parameter(Position=1)]
        [string] $name,
        [Parameter(Position=2)]
        [ValidateSet('String','ExpandString','Dword','Binary','MultiString','Qword','Unknown')]
        [string] $propertyType = "string",
        [Parameter(Position=3)]
        $value
    )

    #does registry root path exist
    try{Get-Item -Path $regPath -ErrorAction stop | out-null}
    catch{ 
        try{New-Item -Path $regPath -name Default -Value "default value" -Force }
        catch{logdata "couldnt make registry path: $regPath"}
    }
    if( (![string]::IsNullOrEmpty($name)) -and (![string]::IsNullOrEmpty($value)) ) {
        #create key and value
        try{
            New-ItemProperty -Path $regPath -Name $name -PropertyType string -Value $value -Force -ErrorAction Stop  | Out-Null 
            logdata "created registry key: $name"
        }catch{logdata "couldnt make registry key: $name"}
    }
}

function testURL {
    param($inputURL,$port = 80,$timeout = 1000)
    
    #fast test if the root level of a URL is responding
    $list = @($inputURL)
    $address = $list | %{
        $uri = [System.UriBuilder] $_
        $uri.Host
    }
    
    $requestCallback = $state = $null
    $client = New-Object System.Net.Sockets.TcpClient
    $beginConnect = $client.BeginConnect($address,$port,$requestCallback,$state)
    Start-Sleep -milli $timeOut
    if ($client.Connected) { $open = $true } else { $open = $false }
    $client.Close()
    return $open
}

$getSettingsFromURL = {
    $settingsTable = [Ordered]@{}

    if($getSettingsFromURLFlag){
        #get settings table content from URL 
        $cellText = $autodeleteList = $table = ""
        $propertyValues = @()
        $ppmsTimeout = try{(Get-ItemPropertyValue -Path $ppmsregPath -name ppmsTimeout -ErrorAction Stop)}catch{$ppmsTimeout = ""}

        if (testURL $settingsURL) {
            Try {
                logdata "getting settings from website"

                # Initialize $RawHTML
                $RawHTML = $null

                try {
                    $RawHTML = Invoke-WebRequest -TimeoutSec $ppmsTimeout -Uri $settingsURL -UseBasicParsing | Select-Object -ExpandProperty RawContent
                    logdata "Successfully retrieved content using Invoke-WebRequest."
                }
                catch {
                    logdata "Invoke-WebRequest failed: $($_.Exception.Message)"
                }

                # Proceed only if $RawHTML has content
                if ($RawHTML -ne $null) {
                    $NewHTMLObject = New-Object -com "HTMLFILE"
                    $NewHTMLObject.designMode = "on"
                    $RawHTMLBytes = [System.Text.Encoding]::Unicode.GetBytes($RawHTML)
                    try { $NewHTMLObject.write($RawHTMLBytes) }
                    catch { $NewHTMLObject.ihtmlDocument2_write($RawHTMLBytes) }
                    $NewHTMLObject.Close()
            
                    $NewHTMLObjectBody = $NewHTMLObject.body
                    $DivObjects = [array]$($NewHTMLObjectBody.getElementsByTagName("div"))
                    $table = [array]$($NewHTMLObjectBody.getElementsByTagName("TABLE"))
                    $table = $table | Where { $_.caption.innerText -eq $settingsTableName }
                }else {logdata "No content retrieved from $settingsTableName"}
            }Catch {logdata "$settingsURL unreadable (bad cert.?) or Table not found"}
        }else {logdata "$settingsURL not found"}

        If(![string]::IsNullOrEmpty($table)){
            $columns = $table.cells.length/$table.rows.length #get number of columns
            #Read each cell and format into a text string table

            ForEach($row in $table.rows){
                $propertyName = ""
                $propertyValues = @()
                If($row.rowIndex -gt 0){ #dont do it for the table headers
                    ForEach($cell in $row.cells){
                        if([string]::IsNullOrEmpty($Cell.innerText)){$cellText = $cell.innerText}
                        else{$cellText = $cell.innerText | ? {$_.trim() -ne "" }}

                        If(($cellText -ne "") -and ($cellText -ne $null)){
                            If($cell.cellIndex -eq 0){
                                $propertyName = $cellText
                            } 
                            if($cell.cellIndex -gt 0){
                                if(![string]::IsNullOrEmpty($cellText)){
                                    if(($cellText -match "True") -or ($cellText -match 1)) {$cellText = $true}
                                    else{$cellText = $false}
                                }else{$cellText = ""}
                                $propertyValues += $cellText
                            } 
                        }
                    }
                }
                if(![string]::IsNullOrEmpty($propertyName)){
                    $settingsTable.add($propertyName, $propertyValues)
                }
            }
        }else{logdata "$settingsTableName is empty or not found"}
    }else{logdata "getSettingsFromURLFlag is false, dont retrieve settings from $settingsURL"}
}

function goNoGo ($webFlag){   
    $runFlag = $false
    if(![string]::IsNullOrEmpty($webFlag)){
        if($webFlag){$runFlag = $true} #if web setting is true
        else{$runFlag = $false}
    }
    elseif($fallbackFlag){$runFlag = $true} 
    $output = [pscustomobject]@{
        log = "webFlag = $webFlag, fallbackFlag = $fallbackFlag => runFlag = $runFlag"
        runFlag = $runFlag
    }
    return $output
}

$defineSettings = {
    $start = (get-date).Ticks
    $userName = $env:USERNAME #get username
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 #set TLS1.2 for communications with ppms server

    $settingsName = (Get-ChildItem -Path $ScriptPath -Filter *settings*.ps1).Name  #find all settings files in script folder
    . "$($ScriptPath)\$settingsName"  #load configs from file
}

$isElevated = {
    #if the script hasnt been elevated, reset flags to control execution
    if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $ranAsAdminFlag = $true #set script elevation flags
        logdata "is elevated"
    }else{
        #add all your first run flags to reset here
        $ranAsAdminFlag = $elevateFlag = $makeTaskFlag = $makeLMFlag = $false
        $global:log = $null #clear log
    }
}

$checkStatus = {
    #check if task and logpath are set, else elevate and create as required
    #it's important to elevate only once as all code below the elevation command will be ran again, leading to duplication
    if(![string]::IsNullOrEmpty($taskname) -and ![string]::IsNullOrEmpty($taskPath)){
        try{
            Get-ScheduledTaskInfo -TaskName $taskname -TaskPath $taskPath -ErrorAction stop | Out-Null #this test doesnt work for system level tasks
        }catch{
            $taskInfo = Get-ScheduledTaskInfo -TaskName $taskname -TaskPath $taskPath 2>&1 #get error message to determine if system level task exists
            if($taskInfo.CategoryInfo.Category -match "PermissionDenied"){
            }
            elseif($taskInfo.CategoryInfo.Category -match "ObjectNotFound"){ #no task exists, set flags to create task after elevation
                logdata "task doesn't exist"
                $elevateFlag = $true
                $makeTaskFlag = $true
                logdata "makeTaskFlag = $makeTaskFlag" 
            }
        }
    }

    #check HKLM root path exists
    if(!(Test-Path $LM_rootPath)) {
        $elevateFlag = $true
        $makeLMFlag = $true
        logdata "makeLMFlag = $makeLMFlag" 
    }
}

$runAsAdmin = {
    #elevate to administrator to install tasks and create local machine keys etc
    #only do this once if required as any code below this script will be reloaded and run again creating duplicate log entries etc
    if ($elevateFlag -and !([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        logdata "elevate script" 
        Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
        exit;
    }elseif(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        #run this code if elevated already
    }
}

$makeHKLMroot = {
    if($makeLMFlag){
        #create root regpath if required
        try{
            New-Item -Path $LM_rootPath -Force -ErrorAction Stop | out-null
            logdata "registry path: $LM_rootPath created" 
        }
        catch{logdata "couldnt create registry path: $LM_rootPath" }

        setRegPermissions $LM_rootPath
    }
}

$createLog = {
    #get registry value for log path
    Try{
        $logRoot = (Get-ItemPropertyValue -Path $LM_rootPath -name logRootPath -ErrorAction Stop)
    }
    Catch{
        New-ItemProperty -Path $LM_rootPath -name logRootPath -Value $logRoot -Force | Out-Null #store root log path for use later
        logdata "logRoot not in registry, $LM_rootPath\logRootPath has been created" 
    }

    #create root logpath if required and set permissions
    if(!(Test-Path $logRoot)){
        New-Item -ItemType directory $logRoot -Force | Out-Null
        setFilePermissions $logRoot
    }

    #define this scripts logpath
    $logpath = $logRoot + "\$(scriptName)\" +  (Get-Date).ToString("yyyy_MM_dd") + "_" + $userName + "_$(scriptName)_log.txt" 

    #create log file
    if($logToFile -and !(Test-Path $logpath)){
        New-Item $logpath -Force | Out-Null
        logdata "$([string]((Get-Date).DateTime)) - $userName"
        logdata "logFile $logpath has been created"
    }
}

$startLog = {
    #create template info in log file at start of script run
    logdata "`r`n-------------------$(scriptName)-------------------------"
    logdata "$([string]((Get-Date).DateTime)) - $userName"
    logdata $global:log
}

$makeTask = {
    $madeTask = $false
    #create a scheduled task to run the script
    if($makeTaskFlag -and ![string]::IsNullOrEmpty($taskname)){
        #create task settings
        try{
            if($asSystem){$user = "NT Authority\System" }
            else{$user = "Builtin\Users"}
        
            $action = New-ScheduledTaskAction -WorkingDirectory $scriptPath -Execute $scriptToRun #working directory and name of file to execute 
            #$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hour 0) -WakeToRun -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Compatibility Win8 #system task settings
            $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Min 1) -WakeToRun -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Compatibility Win8 -MultipleInstances Queue #user specific task

            $principal1 = New-ScheduledTaskPrincipal -GroupId $user -RunLevel Highest
            $principal2 = New-ScheduledTaskPrincipal -GroupId $user 

            if($asSystem){
                $settings = $settings #create task as NT/System
                $principal = $principal1
            }elseif($asAdmin){
                $settings = $settings #create task as NT/System
                $principal = $principal1
            }
            else{
                $settings = $settings #create task as User
                $principal = $principal2
            }

            if($atLogon){
                $trigger = New-ScheduledTaskTrigger -AtLogOn 
                $task = Register-ScheduledTask -TaskName $taskName -Trigger $trigger -Action $action -Settings $settings -TaskPath $taskPath -Principal $principal  #task to run at logon
            }else{
                $trigger = New-ScheduledTaskTrigger -Daily -At 12am
                $task = Register-ScheduledTask -TaskName $taskName -Trigger $trigger -Action $action -Settings $settings -TaskPath $taskPath -Principal $principal  #task to run every minute
                $task.Triggers.Repetition.Duration = "P1D" #Repeat for a duration of one day
                $task.Triggers.Repetition.Interval = "PT1M" #Repeat every 1 minutes, use PT1H for every hour
            }
            logdata "created task settings for: $taskname"
        }catch{logdata "couldnt create task settings for: $taskname"}

        #create task using settings above
        try{
            $task | Set-ScheduledTask #create task
            logdata "created scheduled task: $taskname"
            $madeTask = $true
        }catch{
            logdata "couldnt set scheduled task: $taskname"
            $madeTask = $false
        }
        
        $makeTaskFlag = $false
    }
}


$endScript = {
    if($ranAsAdminFlag){
        #decrement installation counter
        try{$scriptNumber = [int](Get-ItemPropertyValue $LM_rootPath -Name installedScripts -ErrorAction SilentlyContinue )}catch{$scriptNumber = [int]0}
        if($(scriptName) -match "uninstall"){
            $scriptNumber = $scriptNumber - 1
            logdata "decrement scriptCounter to $scriptNumber"
        }
        elseif($madeTask){
            $scriptNumber = $scriptNumber + 1
            logdata "increment scriptCounter to $scriptNumber"
        }
        try{
            New-ItemProperty -Path $LM_rootPath -name installedScripts -Value $scriptNumber -Force -ErrorAction Stop | Out-Null 
        }
        catch{logdata "couldnt update installedScripts counter in registry"}
    }

    $end = [math]::Round(((Get-date).Ticks - $start)/10000000,1)
    Logdata "-------------------$(scriptName) completed in $end seconds-------------------`r`n"
}


### Custom scripts ###
$getLogonTime = {
    $userName = try{Get-ItemPropertyValue -Path $ppmsRegPath -name userLogin -ErrorAction Stop}catch{$userName = $env:USERNAME}
    if([string]::IsNullOrEmpty($userName)){$username = $env:USERNAME}

    #calculate time based on Australian datetime format
    $AUSCultureName = "en-AU" #get local datetime format
    $AUSCulture = [CultureInfo]::CreateSpecificCulture($AUSCultureName)

    #get this user sessions logonDateTime
    $quserResult = quser 2>&1
    $quserRegex = $quserResult | ForEach-Object -Process { $_ -replace '\s{2,}',',' }
    $quserObject = $quserRegex | ConvertFrom-Csv
    $breakFlag = $false
    foreach($user in $quserObject){
        if($user.USERNAME -match $username){
            if($user.USERNAME -match ">"){
                if($user.ID -match "Disc"){
                    $activeUser = [PSCustomObject] @{
                        'LOGON TIME' = $user.'IDLE TIME'
                    }
                }else{
                    $activeUser = [PSCustomObject] @{
                        'LOGON TIME' = $user.'LOGON TIME'
                    }
                    $breakFlag = $true
                    break
                }
                if($breakFlag){break}
            }
            if($breakFlag){break}
        }
    }
    if([cultureInfo]::CurrentCulture.Name -match "en-US"){
        $USCulture = [CultureInfo]::CreateSpecificCulture("en-US")
        $logonDateTime = [datetime]::Parse($activeUser.'LOGON TIME', $USCulture)

    }
    else{
        $AUSCulture = [CultureInfo]::CreateSpecificCulture("en-AU")
        $logonDateTime = [datetime]::Parse($activeUser.'LOGON TIME', $AUSCulture)
    }
    $logonDateTimeString = $logonDateTime.ToString("dd/MM/yyyy HH:mm:ss")
    logdata "logonDateTime = $logonDateTimeString"
}

$getConfigTime = {
    #determine when the ppmsConfig.ps1 script last ran
    try{
        $ConfigDateTime = [datetime]::Parse((Get-ItemPropertyValue -Path $ppmsRegPath -name ConfigDateTime -ErrorAction Stop), $AUSCulture)
        $ConfigDateTimeString = $ConfigDateTime.ToString("dd/MM/yyy HH:mm:ss")
        logdata "ConfigDateTime = $ConfigDateTimeString"
    }
    catch{
        $ConfigDateTime = $ConfigDateTimeString = ""
        logdata "couldnt get ConfigDateTime from registry"
    }
}

function getConnections() {
    $TeamViewerPort = @(5938) #Teamviewer default port is 5938
    $VNCPorts = @(5800,5900) #VNC default port is 5900, 5800 is also used
    $HorizonPorts = @(902,8443,4172) #Horizon default ports are 902, 8443, 4172
    $RDPPorts = @(3389) #RDP default port is 3389

    $remoteConnections = @()
    $remote = [PSCustomObject]@{}
    $connectionList = Get-NetTCPConnection | Where {$_.State -match "ESTABLISHED"}
    foreach($connection in $connectionList){
        $connectionType = ""
        if(($TeamViewerPort.count -ne 0) -and $TeamViewerPort.Contains([int]$($connection.LocalPort))){
            $connectionType = "TeamViewer"
        }
        if(($VNCPorts.Count -ne 0) -and $VNCPorts.Contains([int]$($connection.LocalPort))){
            $connectionType = "VNC"
        }
        if(($HorizonPorts.count -ne 0) -and $HorizonPorts.contains([int]$($connection.LocalPort))){
            $connectionType = "Horizon"
        }
        if(($RDPPorts.Count -ne 0) -and $RDPPorts.Contains([int]$($connection.LocalPort))){
            $connectionType = "RDP"
        }
        if(![string]::IsNullOrEmpty($connectionType)){
                if([cultureInfo]::CurrentCulture.Name -match "en-US"){
                    $USCulture = [CultureInfo]::CreateSpecificCulture("en-US")
                    $connectionDateTime = [datetime]::Parse($connection.CreationTime, $USCulture)
                }
                else{
                    $AUSCulture = [CultureInfo]::CreateSpecificCulture("en-AU")
                    $connectionDateTime = [datetime]::Parse($connection.CreationTime, $AUSCulture)
                }
                $connectionDateTimeString = $connectionDateTime.ToString("dd/MM/yyyy HH:mm:ss")

            $remote = [PSCustomObject]@{
                Type = $connectionType
                localAddress = $connection.LocalAddress
                LocalPort = $connection.LocalPort
                RemoteAddress = $connection.RemoteAddress
                RemotePort = $connection.RemotePort
                OwningProcess = $connection.OwningProcess

                CreationTime = $connectionDateTimeString

            }
            $remoteConnections += $remote
        }
    }
    return ($remoteConnections | sort {$_.creationTime} -Descending)
}

function filterConnections([string] $IP, [Array] $inputConnections){
    if($inputConnections.count -gt 0){
        $inputConnections = $inputConnections | sort {$_.creationTime} -Descending
        foreach($activeConnection in $inputConnections){
            if($activeConnection.RemoteAddress -match $IP){
                return $activeConnection.Type
            }
        }
    }
}

$getAccessToken = {
    if(testURL $googleScope){
        #get google sheet access token
        try {
            $certPath =  Get-ChildItem -Path $scriptpath\*.p12  
            $accessToken = Get-GOAuthTokenService -scope $googleScope -certPath $certPath -certPswd $certPswd -iss $iss 
            logdata "Access Token found"
        } catch {
            logdata "Access Token not found"
            $accessToken = $null
        }
    }else{$accessToken = $null}
}

$makeIdleType = {
    #get PC idle time (ie no user mouse or keyboard clicks)
    Try{
        Add-Type @'
        using System;
        using System.Diagnostics;
        using System.Runtime.InteropServices;

        namespace PInvoke.Win32 {

        public static class UserInput {

            [DllImport("user32.dll", SetLastError=false)]
            private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

            [StructLayout(LayoutKind.Sequential)]
            private struct LASTINPUTINFO {
                public uint cbSize;
                public int dwTime;
            }

            public static DateTime LastInput {
                get {
                    DateTime bootTime = DateTime.UtcNow.AddMilliseconds(-Environment.TickCount);
                    DateTime lastInput = bootTime.AddMilliseconds(LastInputTicks);
                    return lastInput;
                }
            }

            public static TimeSpan IdleTime {
                get {
                    return DateTime.UtcNow.Subtract(LastInput);
                }
            }

            public static int LastInputTicks {
                get {
                    LASTINPUTINFO lii = new LASTINPUTINFO();
                    lii.cbSize = (uint)Marshal.SizeOf(typeof(LASTINPUTINFO));
                    GetLastInputInfo(ref lii);
                    return lii.dwTime;
                }
            }
        }
    }
'@ #this line must have no spaces/tabs or characters etc in front of the '@ or it breaks the code
    }
    catch{logdata "idle time type already added"}
}

$calcIdleTime = {
    #calculate user interaction idle time on local PC
    $idleTicks = $([PInvoke.Win32.UserInput]::LastInputTicks)
    $startTicks = (Get-Date).Ticks

    try{$lastTicks = (Get-ItemPropertyValue -Path $softwareRegPath -name lastTicks -ErrorAction Stop) }catch{$lastTicks = 0}
    logdata "lastTicks = $lastTicks"
            
    try{$lastidleTicks = (Get-ItemPropertyValue -Path $softwareRegPath -name lastidleTicks -ErrorAction Stop) }catch{$lastidleTicks = 0}
    logdata "lastidleTicks = $lastidleTicks"

    try{$totalIdleTicks = (Get-ItemPropertyValue -Path $softwareRegPath -name totalIdleTicks -ErrorAction Stop) }catch{$totalIdleTicks = 0}
    logdata "totalIdleTicks = $totalIdleTicks"

    If(($lastTicks -eq 0) -or (($startTicks - $lastTicks) -gt ($sameSessionDelta * 600000000))) {
        #reset idleTime on first run
        $type = "reset"
        $totalIdleTicks = 0 
    }
    elseIf($idleTicks -eq $lastIdleTicks) { 
        #increment idleTime
        $type = "idle+"
        $totalIdleTicks = $startTicks - $lastTicks + $totalIdleTicks 
    }
    else{
        #dont increment idleTime
        $type = "click"
        $totalIdleTicks = $totalIdleTicks
    }

    $totalIdleSecs = [math]::Round($totalIdleTicks/10000000)
    $totalIdleMins = [math]::Round($totalIdleTicks/600000000)
    logdata "calculate total idle Mins : type = $type : startTicks = $startTicks : lastTicks = $lastTicks : idleTicks = $idleTicks : totalIdleTicks = $totalIdleTicks : totalIdleSecs = $totalIdleSecs : totalIdleMins = $totalIdleMins"
            
    $lastTicks = $startTicks #store last runTime value for next calculation
    New-ItemProperty -Path $softwareRegPath -name lastTicks -Value $startTicks -Force | Out-Null  
    New-ItemProperty -Path $softwareRegPath -name lastIdleTicks -Value $idleTicks -Force | Out-Null         
    New-ItemProperty -Path $softwareRegPath -name totalIdleTicks -Value $totalIdleTicks -Force | Out-Null
}

$sessionStats = {

    #get PC details
    try{
        $IP_Address = Get-ItemPropertyValue -Path $LMRegPath -name ipAddress -ErrorAction SilentlyContinue
        $MAC_Address = Get-ItemPropertyValue -Path $LMRegPath -name macAddress -ErrorAction SilentlyContinue
    }catch{logdata "couldnt get pc details from registry"}

    #other stats
    $sessionType = [string]($activeUser.SESSIONNAME)
    $RDP_DisconnectTime = $activeUser.RDP_disconnectTime #get session disconnect time
    $totalRAM = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).sum /1mb
    $availableMBytes = (((Get-Counter '\Memory\Available MBytes').CounterSamples | where CookedValue).CookedValue | measure -sum).sum
    $RAMpercent = [math]::round(($totalRAM - $availableMBytes)/$totalRAM,2)*100
    logdata "RAMpercent used = $RAMpercent"


    #store the time as last time script ran
    $lastDateTime = [datetime]::Parse((Get-Date -Format ("dd/MM/yyyy HH:mm:ss")), $AUSCulture) #datestamp on PC
    $lastDateTimeString = $lastDateTime.ToString("dd/MM/yyy HH:mm")
    logdata "lastDateTime = $lastDateTimeString"

    #calculate total session time
    $lastDateTimeToPrint = $lastDateTime
    if($lastDateTimeToPrint.Second -gt 30){ $lastDateTimeToPrint = $lastDateTimeToPrint.AddMinutes(1) }
    $lastDateTimeToPrint = $lastDateTimeToPrint.AddSeconds(-($lastDateTimeToPrint.Second))
    $lastDateTimeToPrintString = $lastDateTimeToPrint.ToString("dd/MM/yyy HH:mm")

    $lastConfigDateTimeToPrint = $lastConfigDateTime
    if($lastConfigDateTimeToPrint.Second -gt 30){ $lastConfigDateTimeToPrint = $lastConfigDateTimeToPrint.AddMinutes(1) }
    $lastConfigDateTimeToPrint = $lastConfigDateTimeToPrint.AddSeconds(-($lastConfigDateTimeToPrint.Second))
    $lastConfigDateTimeToPrintString = $lastConfigDateTimeToPrint.ToString("dd/MM/yyy HH:mm")

    $totalSessionTime = [math]::Round(($lastDateTimeToPrint - $lastConfigDateTimeToPrint).TotalMinutes)
            
    #determine if it's a local or remote session and calculate length of session type
    if($totalSessionTime -ne 0){
        try{$lastLocalSession = [int](Get-ItemPropertyValue -Path $softwareRegPath -name lastLocalSession -ErrorAction Stop)}catch{$lastLocalSession = 0}
        if($sessionType -like "*console*") {$localSession = $lastLocalSession + 1} else{$localSession = $lastLocalSession}
        try{$lastRemoteSession = [int](Get-ItemPropertyValue -Path $softwareRegPath -name lastRemoteSession -ErrorAction Stop)}catch{$lastRemoteSession = 0}
        if($sessionType -like "*RDP*") {$remoteSession = $lastRemoteSession + 1} else{$remoteSession = $lastRemoteSession}

        #determine if total PC RAM is being heavily used
        try{$lastRAM25 = [int](Get-ItemPropertyValue -Path $softwareRegPath -name lastRAM25 -ErrorAction Stop)}catch{$lastRAM25 = 0}
        try{$lastRAM50 = [int](Get-ItemPropertyValue -Path $softwareRegPath -name lastRAM50 -ErrorAction Stop)}catch{$lastRAM50 = 0}
        try{$lastRAM75 = [int](Get-ItemPropertyValue -Path $softwareRegPath -name lastRAM75 -ErrorAction Stop)}catch{$lastRAM75 = 0}
        try{$lastRAM100 = [int](Get-ItemPropertyValue -Path $softwareRegPath -name lastRAM100 -ErrorAction Stop)}catch{$lastRAM100 = 0}

        if ($RAMpercent -le 25) {$RAM25 = $lastRAM25 + 1} else{$RAM25 = $lastRAM25}
        if ($RAMpercent -gt 25 -and $RAMpercent -le 50) {$RAM50 = $lastRAM50 + 1} else{$RAM50 = $lastRAM50}
        if ($RAMpercent -gt 50 -and $RAMpercent -le 75) {$RAM75 = $lastRAM75 + 1} else{$RAM75 = $lastRAM75}
        if ($RAMpercent -gt 75) {$RAM100 = $lastRAM100 + 1} else{$RAM100 = $lastRAM100}
        }else{
            $localSession = $remoteSession = $lastLocalSession = $lastRemoteSession = $lastRam25 = $lastRAM50 = $lastRAM75 = $lastRAM100 = 0
            $ram25 = $ram50 = $ram75 = $ram100 = 0
    }

    $activeSessionTime = $localSession + $remoteSession

    New-ItemProperty -Path $softwareRegPath -name lastDateTime -Value $lastDateTimeString -Force | Out-Null
    New-ItemProperty -Path $softwareRegPath -name lastLocalSession -Value $([int]$localSession) -Force | Out-Null
    New-ItemProperty -Path $softwareRegPath -name lastRemoteSession -Value $([int]$remoteSession) -Force | Out-Null
    New-ItemProperty -Path $softwareRegPath -name lastRAM25 -Value $([int]$RAM25) -Force | Out-Null
    New-ItemProperty -Path $softwareRegPath -name lastRAM50 -Value $([int]$RAM50) -Force | Out-Null
    New-ItemProperty -Path $softwareRegPath -name lastRAM75 -Value $([int]$RAM75) -Force | Out-Null
    New-ItemProperty -Path $softwareRegPath -name lastRAM100 -Value $([int]$RAM100) -Force | Out-Null

    $runTime = [math]::Round(((Get-date).Ticks - $start)/10000000,1)
    Logdata "current runtime = $runTime seconds"

    #format gathered session info 
    $GUID = try{Get-ItemPropertyValue -Path $softwareRegPath -name guid -ErrorAction Stop }catch{$GUID = ""}
                    
    #get user details
    try{
        $userID = Get-ItemPropertyValue -Path $ppmsRegPath -name userID -ErrorAction SilentlyContinue
        $fullName = Get-ItemPropertyValue -Path $ppmsRegPath -name userFullname  -ErrorAction SilentlyContinue
        $group = Get-ItemPropertyValue -Path $ppmsRegPath -name userGroup -ErrorAction SilentlyContinue
        $affiliation = Get-ItemPropertyValue -Path $ppmsRegPath -name groupAffiliation -ErrorAction SilentlyContinue
        $department = Get-ItemPropertyValue -Path $ppmsRegPath -name groupDepartment -ErrorAction SilentlyContinue 
        $external = Get-ItemPropertyValue -Path $ppmsRegPath -name groupExternal -ErrorAction SilentlyContinue 
        $groupName = Get-ItemPropertyValue -Path $ppmsRegPath -name groupName -ErrorAction SilentlyContinue 
    }catch{logdata "couldnt get ppms user details from registry"}

    if([string]::IsNullOrEmpty($affiliation)){
        $affiliation = $department
        $group = $groupName
    }

    #get ppms session details
    if(![string]::IsNullOrEmpty($ppmsID) -and ![string]::IsNullOrEmpty($ppmsCode)){
        $sessionFlag = $false
        $sessionID = ""
        if(testURL $ppmsURL){
            try{
                logdata "get current booking details from PPMS server"
                $currentBooking = Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "action=getbooking&id=$ppmsID&code=$ppmsCode" -ErrorAction Stop
                $ppmsExists = $true
                if($currentBooking -match "error: request not authorized"){
                logdata "currentBooking = $currentBooking"
            }
            }catch{
                $sessionID = ""
                logdata "couldnt contact ppms to get session ID"
                $ppmsExists = $false
            } 
        }else{
            logdata "ppms website appears to be down"
            $ppmsExists = $false
        }  
         
        $currentBookingArray = $currentBooking -split "\r\n" #format output from $currentBooking
                
        $lastBookedUser = try{(Get-ItemPropertyValue -Path $softwareRegPath -name lastBookedUser -ErrorAction Stop)}catch{$lastBookedUser = ""}
        logdata "registry value for lastBookedUser = $lastBookedUser"
        if(![string]::IsNullOrEmpty($currentBookingArray[0])){$bookedUser = $currentBookingArray[0]}else{$bookedUser = $lastBookedUser}
        if(($bookedUser -eq "0") -or ($bookedUSer -eq 0)){$bookedUser = ""}
        New-ItemProperty -Path $softwareRegPath -Name lastBookedUser -Value $bookedUser -Force | Out-Null
        logdata "bookedUser = $bookedUser"
    }
    else{
        $bookedUser = ""
        logdata "no ppms settings - bookedUser is therefore empty"
    }
}

$configureSheet = {
    logdata "`r`n-------------------Google Sheets Configurator-------------------------"
    
    #load UMN-Google module
    try{
        $loadModule = (Get-Module -ListAvailable | Where-Object{$_.Name -like '*UMN-Google*'})
        if($loadModule.Name -match "UMN-Google"){
            Import-Module -Name umn-google -Force  -ErrorAction stop
            logdata "UMN-Google Module found on PC and loaded"
            $failedModuleFlag = $false

        }else{
            logdata "UMN-Google Module not found on PC"
            $failedModuleFlag = $true
        }
    }
    catch{
        logdata "couldnt find UMN-Google Module on PC"
        $failedModuleFlag = $true
    }
    
    if($failedModuleFlag -eq $true){
        #install google module if required, must be run as admin on first use to install the module
        try{$moduleInstalled = (Get-InstalledModule -Name UMN-Google -ErrorAction stop).Name}catch{$moduleInstalled = ""}
        if($moduleInstalled -match "UMN-Google"){logdata "umn-google module already installed"}
        else{
            try{
                logdata "try to install umn-google module"
                Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted -ErrorAction stop
                Install-Module -name umn-google -Scope AllUsers -Confirm:$False -SkipPublisherCheck -Force -ErrorAction stop | Out-Null
                Import-Module -Name UMN-Google -Force -ErrorAction stop
                logdata "UMN-google module installed and imported"
            }catch{logdata "unable to install umn-google module"}
        }
    }

    #generate values
    $sheetTitle = $sheetTitle + " " + [string](Get-Date).Year #add year to spreadsheet name
    $sheetName = "Sessions"
    logdata "sheetTitle = $sheetTitle"
    logdata "sheetName = $sheetName"

    #get table content from URL without requiring Internet Explorer dlls
    $cellText = $softwareList = ""
    $softwareArray = @()
    $table = $null

    if(testURL $softwareURL){
        Try{
            logdata "getting software list from website"
            $NewHTMLObject = New-Object -com "HTMLFILE"
            $RawHTML = Invoke-WebRequest -TimeoutSec $ppmsTimeout -Uri $softwareURL -UseBasicParsing | Select-Object -ExpandProperty RawContent 
            $NewHTMLObject.designMode = "on"
            $RawHTML = [System.Text.Encoding]::Unicode.GetBytes($RawHTML)
            try{$NewHTMLObject.write($RawHTML)}
            catch{$NewHTMLObject.ihtmlDocument2_write($RawHTML)}
            $NewHTMLObject.Close()
            $NewHTMLObjectBody = $NewHTMLObject.body
            $DivObjects = [array]$($NewHTMLObjectBody.getElementsByTagName("div"))
            $table = [array]$($NewHTMLObjectBody.getElementsByTagName("TABLE"))
            $table = $table | Where{$_.caption.innerText -eq $softwareTableName}
        }Catch {
            logdata "URL or software Table not found"
        }
    }

    If(![string]::IsNullOrEmpty($table)){
        #Read each cell and format into a text string table
        ForEach($row in $table.rows){
            If($row.rowIndex -gt 0){ #dont do it for the table headers
                ForEach($cell in $row.cells){
                    $cellText = $cell.innerText | ? {$_.trim() -ne "" }
                    If(($cellText -ne "") -and ($cellText -ne $null)){
                        If($cell.cellIndex -eq 1){$softwareArray += $cellText.Trim()}
                    }
                }
            }
        }
        #convert arrays to strings for saving in registry
        $softwareList = [system.String]::Join(",", $softwareArray)
        #write to registry
        New-ItemProperty -Path $softwareRegPath -Name softwareList -Value $softwareList -Force | Out-Null
        logdata "softwareList = $softwareList"
    } 
    Else {
        logdata "website table is empty - use local registry values"
        $softwareList = (Get-ItemPropertyValue -Path $softwareRegPath -name softwareList)
        #convert to arrays
        $softwareArray = $softwareList -split "," 
        logdata "softwareList = $softwareList"
    }

    $gotHeaderFlag = $false
    if(![string]::IsNullOrEmpty($softwareList)){
        # Create sheet headers
        $headersList = New-Object System.Collections.ArrayList($null)
        #Define Column Headers of Spreadsheet
        $headers = @("PC_GUID", "System", "pcName", "IP_Address", "MAC_Address", "bookedUser", "pcUser", "userID", "fullName", "Group", "Affiliation", "External", "logonDateTime", "lastDateTime", "Session_Duration","local_ConnectionTime", "RDP_ConnectionTime", "total_ConnectionTime", "total_UserIdleTime", "total_RDP_DisconnectTime", "totalRAM", "RAM25", "RAM50", "RAM75", "RAM100", "-") #column headers for tracker data
        $headers = $headers + $softwareArray
        $headersString = $headers -join "`t"
        $headersList.Add($headers) | Out-Null
        #generate sheet column identifiers
        $columns = @()
        $letters = @("A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z")
        $breakFlag = $false
                    
        foreach($firstletter in $letters){
            foreach($secondLetter in $letters){
                $columns += $firstLetter + $secondLetter
                if(($letters.Count+$columns.Count) -eq ($headers.Count)){
                    $breakFlag = $true
                    break
                }
            }
            If($breakFlag){break}
        } 

        $columnNames = $letters + $columns
        $columnNamesString = $columnNames -join "`t"
        $endColumn = $columnNames[$columnNames.Count-1] 
        logdata "endColumn = $endColumn"
        New-ItemProperty -Path $softwareRegPath -name columnNames -Value $columnNamesString -Force | Out-Null
        New-ItemProperty -Path $softwareRegPath -name endColumn -Value $endColumn -Force | Out-Null
        New-ItemProperty -Path $softwareRegPath -name headersString -Value $headersString -Force | Out-Null
        $gotHeaderFlag = $true
    }

    . $getAccessToken #get access token from google sheets
    start-sleep -Seconds 1

    #if you have permission, then proceed
    if(![string]::IsNullOrEmpty($accessToken)){
                
        #look for latest spreadsheet
        $spreadsheetList = @()
        for($i = 0;$i -le 100;$i++){
            if($i -eq 0){$postfix = ""}else{$postfix = "_$i"}
            $sheetTitleName = $sheetTitle + $postfix
            try{$spreadsheetID = (Get-GSheetSpreadSheetID -accessToken $accessToken -fileName $sheetTitleName -WarningAction SilentlyContinue -ErrorAction stop )}
            catch{logdata "failed to get spreadsheetID from google"}
            If(![string]::IsNullOrEmpty($spreadsheetID)){
                $thisSpreadsheet = [PSCustomObject]@{
                    Title = $sheetTitleName
                    ID = $spreadsheetID
                }
                $spreadsheetList += $thisSpreadsheet
            }else{break}
        }
        
        #if we found the latest spreadsheet, update the sheetTitle and ID
        $tempSpreadsheetID = ($spreadsheetList[$spreadsheetList.count-1]).ID
        $tempSheetTitle = ($spreadsheetList[$spreadsheetList.count-1]).Title
        if(![string]::IsNullOrEmpty($tempSheetTitle) -and ![string]::IsNullOrEmpty($tempSpreadsheetID)) {
            $sheetTitle = $tempSheetTitle
            $spreadsheetID = $tempSpreadsheetID
        }

        #if sheet exists check its size, if it's too big, create a new spreadsheet.  If it doesnt exist, create a spreadsheet
        $createSpreadsheetFlag = $false
        if($spreadsheetList.Count -gt 0){
            logdata "spreadsheet exists, check it's size"

            #get sheet properties from spreadsheet 
            try{
                $sheetProperties = Get-GSheetSpreadSheetProperties -accessToken $accessToken -spreadSheetID $spreadsheetID
                logdata "sheetProperties = $sheetProperties"    
            }
            catch{
                $sheetProperties = ""
                logdata "couldnt get sheet properties"
            }

            #check if spreadsheet isnt too large, if it is, create a new spreadsheet
            foreach($count in $sheetproperties.sheets.properties.gridProperties){
                $cells += $count.rowCount * $count.columnCount
            }
            logdata "number of cels in sheet is $cells"
            if($cells -ge [int]$maxCells){
                logdata "existing spreadsheet is too large: $sheetTitle"
                if($sheetTitle -match "_[0-9]"){$sheetTitle = $sheetTitle -replace "_[0-9]" , "_$([int]$($sheetTitle.Split("_")[1]) + 1)" }
                else{$sheetTitle = $sheetTitle + "_1" }
                logdata "make new spreadsheet: $sheetTitle"
                $createSpreadsheetFlag = $true
            }
        }
        else{
            logdata "no spreadsheet exists, create a new spreadsheet"
            $createSpreadsheetFlag = $true
        }


        #create spreadsheet if required
        if($createSpreadsheetFlag){
            try{
                $spreadsheetID = (New-GSheetSpreadSheet -accessToken $accessToken -title $sheetTitle -ErrorAction stop).spreadsheetId
                Set-GFilePermissions -accessToken $accessToken -fileID $spreadsheetID -emailAddress $userAccount -role writer -type group | Out-Null
                logdata "new spreadsheet created with spreadsheetID: $spreadsheetID and sheetTitle: $sheetTitle"
            }
            catch{logdata "couldnt make new spreadsheet"}
        }


        #get sheet properties from spreadsheet 
        try{
            $sheetProperties = Get-GSheetSpreadSheetProperties -accessToken $accessToken -spreadSheetID $spreadsheetID
            logdata "sheetProperties = $sheetProperties"    
        }
        catch{
            $sheetProperties = ""
            logdata "couldnt get sheet properties"
        }
                
        New-ItemProperty -Path $softwareRegPath -name spreadsheetID -Value $spreadsheetID -Force | Out-Null


        #get sheet name from spreadsheet and check headers match
        $matchSheetFlag = $false
        if($sheetProperties -ne ""){
            $sheetFoundFlag = $true
            $arrayToCheck = $sheetProperties.sheets.properties.title -match $($sheetName -replace "[0-9]" , '') | Sort-Object -Descending
            if($arrayToCheck -notmatch "False"){
                foreach($sheet in $sheetproperties.sheets.properties.title){
                    $headerRange = "A1:$($endColumn)1"
                    $uri = "https://sheets.googleapis.com/v4/spreadsheets/$spreadSheetID/values/$sheet!A1:ZZ1"
                    $headValues = Invoke-RestMethod -Method GET -Uri $uri -Headers @{"Authorization"="Bearer $accessToken"} -ErrorAction SilentlyContinue
                    try{$sheetHeaders = ($headValues.values).GetValue(0)}catch{$sheetHeaders = @()}
                    $compare = Compare-Object -ReferenceObject $sheetHeaders -DifferenceObject $Headers
                    if($compare.InputObject.Length -eq 0){
                        $matchSheetFlag = $true
                        $matchHeaderFlag = $true
                        logdata "sheet $sheet already exists and headers match"
                        $sheetName = $sheet
                        break
                    }else{
                        $matchSheetFlag = $true
                        $matchHeaderFlag = $false
                        logdata "sheet $sheet already exists but headers dont match"
                    }
                }
            }else{
                $matchSheetFlag = $false
                logdata "sheet $sheetName doesnt exist"
            }
        }
        else{
            logdata "couldnt get sheet properties"
            $sheetFoundFlag = $false
            $matchSheetFlag = $false
            $matchHeaderFlag = $false
        }

        $makeSheetFlag = $false
        If($matchSheetFlag -and !$matchHeaderFlag){
            $sheetName = $($sheetName -replace "[0-9]" , '') + $([string]([int]($arrayToCheck[0] -replace "[^0-9]" , '')  + 1))
            logdata "new sheet name = $sheetName"
            $makeSheetFlag = $true
        }

        #create sheet in spreadsheet
        If($sheetFoundFlag -and (!$matchSheetFlag -or $makeSheetFlag)){
            logdata "creating sheet in spreadsheet"
            # Create new sheet
            try{Add-GSheetSheet -accessToken $accessToken -sheetName $sheetName -spreadSheetID $SpreadsheetID }
            catch{logdata "couldnt Add new sheet"}
    
            # Assign Permissions
            try{Set-GFilePermissions -accessToken $accessToken -fileID $SpreadsheetID -role writer -type group -emailAddress $userAccount | Out-Null}
            catch{logdata "couldnt set permissions for sheet"}

            #write column headers
            try{Set-GSheetData -accessToken $accessToken -sheetName $sheetName -spreadSheetID $spreadsheetID -rangeA1 "A1:$($endColumn)1" -values $headersList | Out-Null}
            catch{logdata "couldnt write headers for sheet"}
            logdata "sheet $sheetName created"

            foreach($sheet in $sheetproperties.sheets){
                if($sheet.properties.title -match "sheet*"){
                    logdata "removing unwanted sheets"
                    try{Remove-GSheetSheet -accessToken $accessToken -sheetName $($sheet.properties.title) -spreadSheetID $SpreadsheetID | Out-Null}
                    catch{logdata "couldnt remove sheet, maybe already removed"}
                }
            }
        }

        try{
            $spreadsheetURL = (Get-GSheetSpreadSheetProperties -accessToken $accessToken -spreadSheetID $spreadsheetID).spreadsheetURL
            logdata "spreadsheetURL = $spreadsheetURL"
            $softwareTracker_ConfigFlag = "false" #reset flag so configuration doesnt run again
            New-ItemProperty -Path $ppmsRegPath -name softwareTracker_ConfigFlag -Value $softwareTracker_ConfigFlag -Force | Out-Null
        }
        catch{
            logdata "couldnt get spreadsheet URL"
            $spreadsheetURL = "not found"
        }

        New-ItemProperty -Path $softwareRegPath -name spreadsheetURL -Value $spreadsheetURL -Force | Out-Null
        New-ItemProperty -Path $softwareRegPath -name softwareURL -Value $softwareURL -Force | Out-Null
        New-ItemProperty -Path $softwareRegPath -name softwareTableName -Value $softwareTableName -Force | Out-Null
        New-ItemProperty -Path $softwareRegPath -name sheetTitle -Value $sheetTitle -Force | Out-Null
        New-ItemProperty -Path $softwareRegPath -name sheetName -Value $sheetName -Force | Out-Null
    
        $runTime = [math]::Round(((Get-date).Ticks - $start)/10000000,1)
        Logdata "current runtime = $runTime seconds"

    }
}

$getUserDetails = {
    logdata "get user PC session info"
    $quserResult = quser 2>&1
    $quserRegex = $quserResult | ForEach-Object -Process { $_ -replace '\s{2,}',',' }
    $quserObject = $quserRegex | ConvertFrom-Csv
    $breakFlag = $false
    foreach($user in $quserObject){
        if($user.USERNAME -match $username){
            if($user.USERNAME -match ">"){
                logdata "user = $(($user.USERNAME).trim(">"))"
                #get last recorded total idle/disconnect time
                try{$lastRDP_DisconnectTime = [int](Get-ItemPropertyValue -Path $softwareRegPath -name RDP_DisconnectTime -ErrorAction Stop) }
                catch{$lastRDP_DisconnectTime = 0}

                if($user.ID -match "Disc"){ 
                    #RDP disconnected session 
                    logdata "RDP user session disconnected"
                    $RDP_totalIdleTime = $lastRDP_DisconnectTime + 1
                    New-ItemProperty -Path $softwareRegPath -name RDP_DisconnectTime -Value $RDP_totalIdleTime -Force | Out-Null
                    
                    $activeUser = [PSCustomObject] @{
                        USERNAME = ($user.USERNAME).Trim(">")
                        SESSIONNAME = "RDP_Disconnected"
                        ID = $user.SESSIONNAME
                        STATE = $user.ID
                        RDP_disconnectTime = $RDP_totalIdleTime
                        'LOGON TIME' = $user.'IDLE TIME'
                    }
                }else{
                    #local session or active RDP session
                    $activeUser = [PSCustomObject] @{
                        USERNAME = ($user.USERNAME).Trim(">")
                        SESSIONNAME = $user.SESSIONNAME
                        ID = $user.ID
                        STATE = $user.STATE
                        RDP_disconnectTime = $lastRDP_DisconnectTime
                        'LOGON TIME' = $user.'LOGON TIME'
                    }
                    logdata "PC user session is active"
                    $breakFlag = $true
                    break
                }
                if($breakFlag){break}
            }
            if($breakFlag){break}
        }
    }
    if([string]::IsNullOrEmpty($user.USERNAME)){$user.USERNAME = $env:username}
}

$trackingScript = {
    #get current time
    $nowDateTime = [datetime]::Parse((Get-Date -Format ("dd/MM/yyyy HH:mm:ss")), $AUSCulture) #datestamp on PC
    $nowDateTimeString = $nowDateTime.ToString("dd/MM/yyyy HH:mm")

    #prevent this script from running before ppmsconfig.ps1
    try{$configRan = $ConfigDateTime.AddSeconds(0)}catch{$configRan = $nowDateTime}

    #prevent this script from running before ppmsconfig.ps1
    #logon datetime is only minute accurate
    #so check if config ran after this logon to ensure we're comparing the correct sessions and this script ran after config due to the lack of time accuracy in logon time
    if(($configRan -gt $logonDateTime) -and ($configRan -lt $nowDateTime)){
        $random = Get-Random –Minimum 000 -Maximum $([int]$maxDelay)
        start-sleep -Milliseconds $random
        logdata "config script has run - running script after $random ms delay"

        #get ppms details from registry, which were generated by ppmsConfig.ps1
        try{
            $ppmsURL = try{(Get-ItemPropertyValue -Path $ppmsregPath -name ppmsURL -ErrorAction stop)}catch{$ppmsURL = ""} #PPMS URL
            $ppmsPF = try{(Get-ItemPropertyValue -Path $ppmsregPath -name ppmsPF -ErrorAction stop)}catch{$ppmsPF = ""} #PPMS URL
            $ppmsID = try{(Get-ItemPropertyValue -Path $ppmsregPath -name ppmsID -ErrorAction Stop)}catch{$ppmsID = ""}
            $ppmsCode = try{(Get-ItemPropertyValue -Path $ppmsregPath -name ppmsCode -ErrorAction Stop)}catch{$ppmsCode = ""}  
            $ppmsTimeout = try{(Get-ItemPropertyValue -Path $ppmsregPath -name ppmsTimeout -ErrorAction Stop)}catch{$ppmsTimeout = ""}
            $pumapiKey = try{(Get-ItemPropertyValue -Path $ppmsregPath -name pumapiKey -ErrorAction stop)}catch{$pumapiKey = ""}
            $apiKey = try{(Get-ItemPropertyValue -Path $ppmsregPath -name apiKey -ErrorAction stop)}catch{$apiKey = ""}
            $system = try{(Get-ItemPropertyValue -Path $ppmsRegPath -name systemName -ErrorAction Stop) }catch{$system = ""}
        }
        catch{
            logdata "couldnt get ppms registry info"
        }
        $runTime = [math]::Round(((Get-date).Ticks - $start)/10000000,1)
        Logdata "current runtime = $runTime seconds"

        ##check if PPMS Server exists for later use####################
        if($reportToPPMS -eq 1){
            if(![string]::IsNullOrEmpty($ppmsURL) -and ![string]::IsNullOrEmpty($ppmsID) -and ![string]::IsNullOrEmpty($userName) -and ![string]::IsNullOrEmpty($ppmsCode)){
                logdata "`r`n---------------PPMS Exists?---------------"
                if(testURL $ppmsURL){
                    logdata "ppms website exists"
                    $ppmsExists = $true
                }else{
                    logdata "ppms website appears to be down"
                    $ppmsExists = $false
                }
            }else{
                logdata "ppms details are missing - dont report"
                $ppmsExists = $false
            }
            
            $runTime = [math]::Round(((Get-date).Ticks - $start)/10000000,1)
            Logdata "current runtime = $runTime seconds"
        }

        ##Report software usage to google sheet####################
        if($enableSoftwareTracker -eq 1){
            logdata "`r`n---------------Software Tracker - Check Last Session Details---------------"
        
            #check for registry path else create it
            If((Test-Path $softwareRegPath) -eq $false) {New-Item -Path $softwareRegPath -name Default -Value "default value" -Force | Out-Null}


            #get last time this script ran to check if the session already exists
            try{$lastDateTime = [datetime]::Parse((Get-ItemPropertyValue -Path $softwareRegPath -name lastDateTime -ErrorAction SilentlyContinue), $AUSCulture)}
            catch{
                $lastDateTime = [datetime]::Parse(("1/1/1900 00:00:00"),$AUSCulture) #first run, init variable
                logdata "lastDateTime doesnt exist in registry"    
            }
            logdata "lastDateTime = $($lastDateTime.ToString("dd/MM/yyy HH:mm"))"


            #if new login is within say 5 minutes (configured in config script) of last login by this user, report as if its the same session
            if(($($lastDateTime.AddMinutes($sameSessionDelta)) - $configDateTime).TotalMinutes -ge 0){
                #"same session, use last logins GUID and use the last stored configTime as logonTime"
            
                try{$lastConfigDateTime = [datetime]::Parse((Get-ItemPropertyValue -Path $softwareRegPath -name lastConfigDateTime -ErrorAction SilentlyContinue), $AUSCulture)}
                catch{$lastConfigDateTime = $logonDateTime} #first run, init variable
                $lastConfigDateTimeString = $lastConfigDateTime.ToString("dd/MM/yyy HH:mm")

                $GUID = (Get-ItemPropertyValue -Path $softwareRegPath -name guid -ErrorAction SilentlyContinue)
            
                logdata "existing session GUID = $GUID"
            }
            else{
                #"new session and ppmsConfig has run, so create new GUID and use this configTime to update lastLogonTime and reset counters"
            
                $GUID = [GUID]::NewGuid() #get unique login ID for user session on PC
                logdata "new session GUID = $GUID"

                #initialise counters
                $lastConfigDateTime = $ConfigDateTime
                $lastConfigDateTimeString = $($ConfigDateTime.ToString("dd/MM/yyy HH:mm"))

                #get session details by comparing active remote sessions login times to the local session login
                $myList = getConnections
                $remoteAddress = $remoteType = ""
                foreach($login in $myList){
                    if($login.creationTime -match $lastConfigDateTimeString){
                        $remoteAddress = $myList[0].remoteAddress
                        $remoteType = $myList[0].Type
                    }
                }

                New-ItemProperty -Path $softwareRegPath -name remoteAddress -Value $remoteAddress -Force | Out-Null
                New-ItemProperty -Path $softwareRegPath -name remoteType -Value $remoteType -Force | Out-Null
                New-ItemProperty -Path $softwareRegPath -name lastConfigDateTime -Value $lastConfigDateTimeString -Force | Out-Null
                New-ItemProperty -Path $softwareRegPath -name lastTicks -Value 0 -Force | Out-Null           
                New-ItemProperty -Path $softwareRegPath -name lastIdleTicks -Value 0 -Force | Out-Null         
                New-ItemProperty -Path $softwareRegPath -name totalIdleTicks -Value 0 -Force | Out-Null
                New-ItemProperty -Path $softwareRegPath -name RDP_DisconnectTime -Value 0 -Force | Out-Null
                New-ItemProperty -Path $softwareRegPath -name lastRAM25 -Value 0 -Force | Out-Null
                New-ItemProperty -Path $softwareRegPath -name lastRAM50 -Value 0 -Force | Out-Null
                New-ItemProperty -Path $softwareRegPath -name lastRAM75 -Value 0 -Force | Out-Null
                New-ItemProperty -Path $softwareRegPath -name lastRAM100 -Value 0 -Force | Out-Null
                New-ItemProperty -Path $softwareRegPath -name lastLocalSession -Value 0 -Force | Out-Null
                New-ItemProperty -Path $softwareRegPath -name lastRemoteSession -Value 0 -Force | Out-Null
                New-ItemProperty -Path $softwareRegPath -name guid -Value $GUID -Force | Out-Null
                New-ItemProperty -Path $softwareRegPath -Name lastBookedUser -Value 0 -Force | Out-Null
            }
            logdata "lastConfigDateTime = $lastConfigDateTimeString"


            #run configurator on first run since ppmsConfig.ps1 ran, to check/create required google sheet
            try{$softwareTracker_ConfigFlag = Get-ItemPropertyValue -Path $ppmsRegPath -name softwareTracker_ConfigFlag -ErrorAction stop}catch{$softwareTracker_ConfigFlag = ""}
            logdata "softwareTracker_ConfigFlag = $softwareTracker_ConfigFlag"
            
            $runTime = [math]::Round(((Get-date).Ticks - $start)/10000000,1)
            Logdata "current runtime = $runTime seconds"

            if($softwareTracker_ConfigFlag -eq "true") {
                . $configureSheet #if required modify/create new sheet
                        }
            else{logdata "google sheet already configured"}
            
            $runTime = [math]::Round(((Get-date).Ticks - $start)/10000000,1)
            Logdata "current runtime = $runTime seconds"


            #################################################################
            logdata "`r`n---------------Software Tracker---------------"
            
            if([string]::IsNullOrEmpty($accessToken)){. $getAccessToken }#get access token from google sheets
            start-sleep -Seconds 1

            if(![string]::IsNullOrEmpty($accessToken)){
                $breakCodeflag = $false
                #read registry values
                try{
                    $spreadsheetID = (Get-ItemPropertyValue -Path $softwareRegPath -name spreadsheetID -ErrorAction Stop)
                    $sheetName = (Get-ItemPropertyValue -Path $softwareRegPath -name sheetName -ErrorAction Stop)
                    $sheetTitle = (Get-ItemPropertyValue -Path $softwareRegPath -name sheetTitle -ErrorAction Stop)
                    $softwareURL = (Get-ItemPropertyValue -Path $softwareRegPath -name softwareURL -ErrorAction Stop) #Get questions from website, if the URL or table doesnt exist, the code will look for a local file 
                    $softwareTableName = (Get-ItemPropertyValue -Path $softwareRegPath -name softwareTableName -ErrorAction Stop)  #name of the table that contains a list of software processes, IDs and Codes
                }
                catch{
                    logdata "couldnt get spreadsheet details from registry, end script"
                    $breakCodeflag = $true
                }

                #get list of software to track from website
                if(!$breakCodeflag){
                    try{
                        $softwareList = (Get-ItemPropertyValue -Path $softwareRegPath -name softwareList -ErrorAction Stop)
                        $columnNamesString = (Get-ItemPropertyValue -Path $softwareRegPath -name columnNames -ErrorAction Stop)
                        $endColumn = (Get-ItemPropertyValue -Path $softwareRegPath -name endColumn -ErrorAction Stop)
                        $columnNames = ($columnNamesString).split("`t")
                        logdata "endColumn = $endColumn"
                        logdata "total columns = $($columnNames.count)"
                        #convert to arrays
                        $softwareArray = $softwareList -split "," 
                        logdata "softwareList = $softwareList"
                    }catch{
                        logdata "couldnt get software list from registry, end script"
                        $softwareArray = $softwareList = $null
                        $breakCodeflag = $true
                    }
                }

                #calculate and report stats
                if(!$breakCodeflag){
                    #get PC session info
                    . $getUserDetails #record actual user
                    . $makeIdleType #insert .net code to monitor idle time
                    . $calcIdleTime #calculate the time unused
                    . $sessionStats #calculate session stats

                
                    #creata data array to write to spreadsheet
                    $pcName = $env:computerName
                    $headersString = (Get-ItemPropertyValue -Path $softwareRegPath -name headersString -ErrorAction SilentlyContinue)
                    $headers = $headersString.split("`t")
                    $dataList = New-Object System.Collections.ArrayList($null)
                    $fixedData = @("$GUID", "$system", "$pcName", "$IP_Address", "$MAC_Address", "$bookedUser", "$userName", "$userID", "$fullName", "$group", "$affiliation", "$external", "$lastConfigDateTimeToPrintString", "$lastDateTimeToPrintString", "$totalSessionTime", "$localSession", "$remoteSession", "$activeSessionTime", "$totalIdleMins", "$RDP_DisconnectTime", $totalRAM, "$RAM25", "$RAM50", "$RAM75", "$RAM100", "-") #tracker data to write to sheet
                    $data = New-Object string[] $($headers.Count - $fixedData.Count)
                    $data = $fixedData + $data
                    logdata "headers count = $($headers.count)"
                    logdata "headers = $headers"
                    logdata "data = $([string]$data)"

                    #track software usage
                    $runningPrograms = $runningProgram = $runningProgramList = @()
                    $index = $programIndex = 0
                    $runningProcesses = (Get-Process | ? {$_.SI -eq (Get-Process -PID $PID).SessionId}).ProcessName
                    Foreach($program in $softwareArray){
                        #If program is running, track it (only tracks this users programs)
                        $search = $program + '*'
                        #If((((gps | ? { $_.MainWindowTitle}).ProcessName) -like $search)){ 
                        If($runningProcesses -like $search){
                            $runningPrograms += $program
                            #$index = $softwareArray.IndexOf($program)
                            $programIndex = [Array]::IndexOf($headers, $program)
                            $programColumn = $columnNames[$programIndex]
                            $runningProgram = [PSCustomObject]@{
                                Name = $program
                                Index = $programIndex
                                Column = $programColumn
                                CurrentTime = ""
                                NewTime = ""
                            }  
                            $runningProgramList += $runningProgram    
                        }
                    }

                    #find spreadsheet
                    $foundGUIDFlag = $gotSheetFlag = $false
                    $uri = "https://sheets.googleapis.com/v4/spreadsheets/$spreadSheetID/values/$sheetName!A:A"
                    if(testURL $uri){
                        try{
                            $GUIDcolumn = Invoke-RestMethod -Method GET -Uri $uri -Headers @{"Authorization"="Bearer $accessToken"} -ErrorAction stop
                            $gotSheetFlag = $true
                        }
                        catch{
                            logdata "couldnt get sheet data - possible timeout"
                        }
                    }

                    #find matching GUID in spreadsheet
                    if($gotSheetFlag){
                        foreach($item in $GUIDcolumn.values){
                            if($item -match $GUID){
                                $matchedRow = $GUIDcolumn.values.IndexOf($item) + 1
                                logdata "matched GUID = row $matchedRow"
                                $foundGUIDFlag = $true
                                break
                            }
                        }
                    }

                    #write data to spreadsheet
                    $wroteDataFlag = $false
                    if($foundGUIDFlag){  
                        try{$spreadsheetURL = Get-ItemPropertyValue -Path $softwareRegPath -name spreadsheetURL -ErrorAction Stop}catch{$spreadsheetURL = ""}
                        start-sleep -Milliseconds 20
                        logdata "update existing session data in $spreadsheetURL"
                        start-sleep -Milliseconds 20
                        try{
                            $GUIDrange = "$($matchedRow):$($matchedRow)"
                            logdata "GUIDrange = $GUIDrange"
                            $uri = "https://sheets.googleapis.com/v4/spreadsheets/$spreadSheetID/values/$sheetName!$GUIDrange"
                            $GUIDrow = Invoke-RestMethod -Method GET -Uri $uri -Headers @{"Authorization"="Bearer $accessToken"} -ErrorAction SilentlyContinue
                        }catch{
                            $GUIDRow = ""
                            logdata "couldnt get row data"
                        }

                        #add 1 minute to each running program
                        If(![string]::IsNullOrEmpty($GUIDRow)){
                            logdata "update running software times"
                            foreach($programRow in $runningProgramList){
                                $currentTime = $($GUIDrow.values)[$($programRow.Index)] #get current run time value for program in google sheet
                                $newTime = [int]$currentTime + 1 #increase run time value
                                $data[$($programRow.Index)] = $newTime #update value in data array
                                $programRow.CurrentTime = $currentTime
                                $programRow.newTime = $newTime
                                logdata $programRow

                            }
                        } 
                        $dataList.Add($data) | Out-Null #create datalist to write
    
                    
                        # Upload CSV data to Google Sheets with Set-GSheetData
                        if($debug -eq 0){
                            try{
                                $sheetOutput = Set-GSheetData -accessToken $accessToken -sheetName $sheetName -spreadSheetID $SpreadsheetID -values $dataList -rangeA1 "A$($matchedRow):$($endColumn)$($matchedRow)" -ErrorAction Stop 
                                logdata "wrote data to existing row $($sheetOutput.updatedRange)"
                                $wroteDataFlag = $true    
                            }
                            catch{
                                $wroteDataFlag = $false
                                logdata "couldnt update data"
                            }
                        }
                    }
                    elseif($gotSheetFlag -and ($debug -eq 0)){
                        #row doesnt exist, so create new row for data
                        logdata "create new session data to $spreadsheetURL"
                        $dataList.Add($data) | Out-Null #create datalist to write
                        try{
                            $sheetOutput = Set-GSheetData -accessToken $accessToken -sheetName $sheetName -spreadSheetID $SpreadsheetID -values $dataList -append -ErrorAction Stop
                            logdata "wrote data to new row $($sheetOutput.updates.updatedRange)"
                            $wroteDataFlag = $true
                        }
                        catch{
                            $wroteDataFlag = $false
                            logdata "couldnt create new row for data"
                        }
                    }
                    else{
                        $wroteDataFlag = $false
                        logdata "cant find sheet, or debug is on"
                    }

                    #if the spreadsheet was found and written to
                    if($wroteDataFlag -and $ppmsExists){
                        #write session GUID to ppms notes of current session
                        if(![string]::IsNullOrEmpty($ppmsID) -and ![string]::IsNullOrEmpty($ppmsCode)){

                            if($currentBookingArray[0] -match $userName){$sessionID = $currentBookingArray[2]} #get the current booking ID number
                            if(![string]::IsNullOrEmpty($sessionID)){
                                logdata "booked session $sessionID"
                                $sessionFlag = $true
                            }else{ logdata "no current booked sessions"}


                            #if no current ppms booking then get unbooked session ID
                            if([string]::IsNullOrEmpty($sessionID) -and !$sessionFlag ){
                                logdata "Check for unbooked sessions in ppms"
                                    try{
                                        $unbookedLoginReport = Get-ItemPropertyValue -Path $ppmsRegPath -name unbookedLoginReport -ErrorAction stop #The report number to retrieve current unbooked sessionID on this system
                                        $body = "action=report$unbookedLoginReport&systemid=$ppmsID&dateformat=print&outformat=json&apikey=$apiKey&coreid=$ppmsPF"
                                        $response = Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/API2/ -Method 'POST' -Body $body -ErrorAction stop
                                        $stopSearch = $false
                                    }catch{
                                        $sessionID = ""
                                        $sessionFlag = $false   
                                        logdata "couldnt contact ppms to get unbooked session ID" 
                                    }

                                if([string]::IsNullOrEmpty($sessionID)){
                                    foreach($naughtyUser in $response){
                                        if($naughtyUser.user_login -match $userName){
                                            $sessionID = $naughtyUser.session_ID
                                            logdata "unbooked session $sessionID"
                                            $sessionFlag = $true
                                            $stopSearch = $true
                                            break
                                        }
                                        if($stopSearch){break}
                                    }
                                }else{logdata "no current unbooked ppms sessions"} 
                            }else{
                                $sessionFlag = $true
                                logdata "no ppms unbooked session ID"
                            }


                            #if ppms session exists, write to note
                            if(![string]::IsNullOrEmpty($sessionID) -and $sessionFlag){
                                try{
                                    #get current session notes for booking
                                    [string]$note = Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "apikey=$pumapiKey&action=getsessionnote&resid=$sessionID" -ErrorAction SilentlyContinue
                                    Start-Sleep -Milliseconds 50
    
                                    #if GUID hasnt already been written to the booking note
                                    If($note -notmatch [string]$GUID){
                                        #format current booking note and append new note information
                                        If(($note -match "\w") -eq $true -and $($note[$note.Length+1] -ne ",")) {$comma = "|"}Else{$comma = ""}
                                        $time = (Get-Date).ToString("HH:mm")
                                        $GUIDnote = "GUID_" + [string]$GUID
                                        $note = $note + "$comma$time=$GUIDnote"
                                        if($debug -eq 0){Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "apikey=$pumapiKey&action=setsessionnote&resid=$sessionID&note=$note" -ErrorAction SilentlyContinue | Out-Null} #set session note for booking
                                        logdata "ppms session $sessionID updated with GUID $GUID"
                                    }else{logdata "ppms session note for GUID $GUID already exists"}
                                } catch {
                                    $note = ""
                                    logdata "couldnt contact ppms server for booking note"
                                }
                            }
                        }
                        else{logdata "no ppmsID and/or ppmsCode, dont update ppms note"}
                    }else{logdata "google sheet not found, dont update ppms note"}
                }
                else{logdata "script was forced to end"}
            }
            else{logdata "cant get google sheets access token"}
        
            #$softwareTracker_ConfigFlag = "false" #reset flag - moved this to the end of the configurator
            #New-ItemProperty -Path $ppmsRegPath -name softwareTracker_ConfigFlag -Value $softwareTracker_ConfigFlag -Force | Out-Null
        }
        else{logdata "software tracker disabled"}
    }
    else{logdata "ppmsConfig.ps1 hasnt run yet"}
}


###############################################
### Main Code ###
. $defineSettings #get settings file and set flags
. $isElevated #test to see if the script has already been elevated to admin
. $checkStatus #check if everything has been installed before
. $runAsAdmin #elevate permissions if required and loop back to the top of the script
. $makeHKLMroot #create HKLM registry path if required
. $createLog #configure logging and create logfile
. $startLog #write start info to log
. $makeTask #create task scheduler task to run script regularly
. $getSettingsFromURL #get global script settings from web


###Custom code ###
if(!$settingsTable.DisableAll){
    $goFlag = goNogo $settingsTable.softwareTracker #determine if the script should run
    logdata $goFlag.log
    if($goFlag.runFlag){
        . $getLogonTime
        . $getConfigTime
        . $trackingScript
    }else{logdata "goFlag = false, script didnt run"}
}else{logdata "disableAll flag = true, didnt run script"}

#End code ###
. $endScript #write end info to log
###############################################
