### ppms tracker script

#script to log user login info to PPMS

#Run this script once as an Admin by right clicking powershell_ISE "run as admin"

#Once the sheet is created, run script once a minute via task scheduler to update ppms



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
        }
        catch{
            logdata "couldnt get ppms registry info"
        }
        $runTime = [math]::Round(((Get-date).Ticks - $start)/10000000,1)
        Logdata "current runtime = $runTime seconds"

        ##Report Logon to PPMS Server####################
        if($reportToPPMS -eq 1){
            if(![string]::IsNullOrEmpty($ppmsURL) -and ![string]::IsNullOrEmpty($ppmsID) -and ![string]::IsNullOrEmpty($userName) -and ![string]::IsNullOrEmpty($ppmsCode)){
                logdata "`r`n---------------PPMS Logon Tracker---------------"
                if(testURL $ppmsURL){
                    try{
                        $ppmsLogon = Invoke-RestMethod -uri "$ppmsURL/rt.asp?i=$ppmsID&u=$userName&f=1" -Method Post -Body "$ppmsCode" -ContentType "application/x-www-form-urlencoded"  #send ppms server user and system details for tracking
                        logdata "ppms logon : $ppmsLogon"
                    }catch{
                        logdata "something went wrong in report login to ppms"
                    }
                }else{
                    logdata "ppms website appears to be down"
                }
            }else{
                logdata "ppms details are missing - dont report"
            }
            
            $runTime = [math]::Round(((Get-date).Ticks - $start)/10000000,1)
            Logdata "current runtime = $runTime seconds"
        }
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
    $goFlag = goNogo $settingsTable.ppmsTracker #determine if the script should run
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
