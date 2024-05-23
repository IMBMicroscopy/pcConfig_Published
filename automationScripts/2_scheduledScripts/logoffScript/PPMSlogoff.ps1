#ppmsLogoff script
#Powershell script designed to be run via Task Scheduler to Determine Current Booking Time remaining
# and when the next session starts and automatically logoff users where appropriate


$debug = $false
$scriptStart = (Get-Date)

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

        if(testURL $settingsURL){
            Try{
                logdata "getting settings from website"
                $NewHTMLObject = New-Object -com "HTMLFILE"
                $RawHTML = Invoke-WebRequest -TimeoutSec $ppmsTimeout -Uri $settingsURL -UseBasicParsing | Select-Object -ExpandProperty RawContent 
                $NewHTMLObject.designMode = "on"
                $RawHTML = [System.Text.Encoding]::Unicode.GetBytes($RawHTML)
                try{$NewHTMLObject.write($RawHTML)}
                catch{$NewHTMLObject.ihtmlDocument2_write($RawHTML)}
                $NewHTMLObject.Close()
                $NewHTMLObjectBody = $NewHTMLObject.body
                $DivObjects = [array]$($NewHTMLObjectBody.getElementsByTagName("div"))
                $table = [array]$($NewHTMLObjectBody.getElementsByTagName("TABLE"))
                $table = $table | Where{$_.caption.innerText -eq $settingsTableName}
            }Catch {
                logdata "URL or Table not found"
            }
        }

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
        }
    }
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

$unblockFiles = {
    if($madeTask){
        Try{
            Get-ChildItem $scriptPath -Recurse | Unblock-File -ErrorAction SilentlyContinue | Out-Null        #unblock downloaded files to allow script execution
            logdata "scriptPath $scriptPath has been unblocked" 
        }catch{logdata "could unblock $scriptPath"}
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
$getUser = {
    #calculate time based on Australian datetime format
    $AUSCultureName = "en-AU" #get local datetime format
    $AUSCulture = [CultureInfo]::CreateSpecificCulture($AUSCultureName)

    #get this user sessions logonDateTime
    $quserResult = quser 2>&1
    $quserRegex = $quserResult | ForEach-Object -Process { $_ -replace '\s{2,}',',' }
    $quserObject = $quserRegex | ConvertFrom-Csv
    $break = $false
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
                    $break = $true
                    break
                }
                if($break){break}
            }
            if($break){break}
        }
    }
    
    if([cultureInfo]::CurrentCulture.Name -match "en-US"){
        $USCulture = [CultureInfo]::CreateSpecificCulture("en-US")
        $logonDateTime = [datetime]::Parse($activeUser.'LOGON TIME', $USCulture)
    }else{
        $AUSCulture = [CultureInfo]::CreateSpecificCulture("en-AU")
        $logonDateTime = [datetime]::Parse($activeUser.'LOGON TIME', $AUSCulture)
    }
    $logonDateTimeString = $logonDateTime.ToString("dd/MM/yyyy HH:mm:ss")
    logdata "logonDateTime = $logonDateTimeString"
}

$getConfigTime = {
    #determine when the ppmsConfig script last ran
    try{
        $configDateTime = [datetime]::Parse((Get-ItemPropertyValue -Path $ppmsRegPath -name configDateTime -ErrorAction Stop), $AUSCulture)
        $configDateTimeString = $configDateTime.ToString("dd/MM/yyy HH:mm:ss")
        logdata "configDateTime = $configDateTimeString"
    }
    catch{
        $configDateTime = $configDateTimeString = ""
        logdata "couldnt get configDateTime from registry"
    }
}

$logoff = {
    #get current time
    $nowDateTime = [datetime]::Parse((Get-Date -Format ("dd/MM/yyyy HH:mm:ss")), $AUSCulture) #datestamp on PC
    $nowDateTimeString = $nowDateTime.ToString("dd/MM/yyyy HH:mm:ss")

    #prevent this script from running before config.ps1
    try{$configRan = $configDateTime.AddSeconds(0)}catch{$configRan = $nowDateTime}

    if($configDateTime -gt $logonDateTime){
        logdata "config script has run"

        if(!$debug){$isAdmin = net localgroup administrators | Where {$_ -eq $pcUser}}else{$isAdmin = ""}
        $PCname = (Get-ItemPropertyValue -Path $ppmsRegPath -name PCname) #Equipment name
        $ppmsURL = (Get-ItemPropertyValue -Path $ppmsRegPath -name ppmsURL) #PPMS URL
        $ppmsPF = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name ppmsPF) #PPMS Platform ID or PF number, Appears in the URL
        $ppmsID = (Get-ItemPropertyValue -Path $ppmsRegPath -name ppmsID) #PPMS equipment ID 
        $ppmsCode = (Get-ItemPropertyValue -Path $ppmsRegPath -name ppmsCode) #PPMS equipment code
        $pumapiKey = (Get-ItemPropertyValue -Path $ppmsRegPath -name pumapiKey) #PUMAPI key, must have user management turned on
        $apiKey = (Get-ItemPropertyValue -Path $ppmsRegPath -name apiKey) #API key, must have write mode turned on
        $emailFrom = [string](Get-ItemPropertyValue -Path $ppmsRegPath -name emailFrom) #Define email account in From address
        $emailAdminFlag = (Get-ItemPropertyValue -Path $ppmsRegPath -name emailAdminFlag) #Allow emails to Admins when they are logged in for more than $adminTimer
        $smtpClient = [string](Get-ItemPropertyValue -Path $ppmsRegPath -name smtpClient) #Define smtp email client
        $adminTimer = (Get-ItemPropertyValue -Path $ppmsRegPath -name adminTimer) #Define when an email is sent to the admin user
        $adminCounter = (Get-ItemPropertyValue -Path $ppmsRegPath -name adminCounter) #Count how many times the script has run since login
        $ignoreAdminFlag = (Get-ItemPropertyValue -Path $ppmsRegPath -name ignoreAdminFlag) #If enabled dont show popup or logoff admin user
        $Timer = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name Timer) #Specify how long after the booking ends that the user is automatically logged off
        $browser = (Get-ItemPropertyValue -Path $ppmsRegPath -name browser) #web browser to open PPMS
        $ppmsTimeout = (Get-ItemPropertyValue -Path $ppmsRegPath -name ppmsTimeout) #ppms communications timeout
    
        wait

        Try{
            #logdata "getUserInfo : $userInput - Attempting PPMS server connection"
            Invoke-RestMethod -TimeOutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "apikey=$pumapiKey&action=getuser&login=$userInput&withuserid=true&format=json" #get user details from PPMS server  
            $ppmsExists = $true
        }Catch{
            #logdata "getUserInfo - couldnt get user contact info from ppms server"
            $ppmsExists = $false
        }

        If($ppmsExists){
            #Check which group a user belongs to
            . "$scriptPath\scripts\getUserInfo.ps1"

            #Function to send email
            . "$scriptPath\scripts\sendEmail.ps1"


            try{$ppmsSystem = (Get-ItemPropertyValue -Path $ppmsRegPath -name pcName -ErrorAction stop) }
            catch{
                if(![string]::IsNullOrEmpty($ppmsCode) -and $ppmsCode -ne 0){
                    #get system name
                    $systems = ""
                    Try{
                        logdata "getSystemName - Attempting PPMS server connection"
                        $systems = Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "action=getsystems&apikey=$pumapiKey&id=$ppmsID&format=csv&noheaders=true" 
                    } Catch {
                        logdata "getSystemName - Couldnt contact PPMS server"
                        $systems = ""
                    }
                    If($systems -ne "") {
                        $systems = $systems -split ","
                        $ppmsSystem = ""
                        $ppmsSystem = $systems[3].Trim('"')
                        logdata "system name = $ppmsSystem"
                    }
                }else{$ppmsSystem = ""}
            }

            If ($ppmsSystem -ne "") {
                #Get PPMS Booking Information
                Try{
                    logdata "getPPMSBookings - Attempting PPMS server connection"
                    $currentBooking = Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "action=getbooking&id=$ppmsID&code=$ppmsCode" #get current booking details from PPMS server
                    wait
                    $nextBooking = Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "action=nextbooking&id=$ppmsID&code=$ppmsCode" #get next booking details from PPMS server
                    wait
                } Catch {
                    $currentBookingArray = $nextBookingArray = @()
                    logdata "getPPMSBookings couldnt contact PPMS server"
                }

                #Format the PPMS booking information into something useable
                $currentBookingArray = $currentBooking -split "\r\n"
                $nextBookingArray = $nextBooking -split "\r\n"
                If($debug -eq $false){
                    $nowUser = $currentBookingArray[0]
                    $nextUser = $nextBookingArray[0]
                    $nowMins = [int]$currentBookingArray[1]
                    $nextMins = [int]$nextBookingArray[1]
                }
                $sessionID = $currentBookingArray[2]
                logdata "current sessionID = $sessionID"
                #Display in console the current and next users
                logdata "nowUser = $nowUser : nowMins = $nowMins"
                logdata "nextUser = $nextUser : nextMins = $nextMins"

                #format minutes into something useable
                ."$scriptPath/scripts/formatMinutes.ps1"
                $formatNow = formatMinutes $nowMins
                $formatNext = formatMinutes $nextMins
    

                #If the logged in user isnt an admin or they're an admin and the ignoreAdminFlag is true, then run the main script
                If (($ignoreAdminFlag -eq 0) -or ($pcUser -ne $isAdmin)) {
                    logdata "$pcUser isnt an admin account, so run main script"
           
                    $userID = (getUserInfo $pcUser).userID
                    $CRLF = "&#x0a;"  #Used in the popup message to create a new line of text
                    $earlyUser = 0

                    #Read Registry Values
                    #$Alert = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name Alert) #Specify when the dialog box appears to warn a user their booking is running out
                    $AlertLong = (Get-ItemPropertyValue -Path $ppmsRegPath -name AlertLong) #Value must be positive (-1 to disable). For bookings longer than 8hours, specify how many minutes before the end of their booking the dialog box appears to warn a user their booking is running out
                    $Alert8 = (Get-ItemPropertyValue -Path $ppmsRegPath -name Alert8)#Value must be positive (-1 to disable). For bookings less than or equal to 8hours, specify how many minutes before the end of their booking the dialog box appears to warn a user their booking is running out
                    $Alert3 = (Get-ItemPropertyValue -Path $ppmsRegPath -name Alert3)#Value must be positive (-1 to disable). For bookings less than or equal to 3hours, specify how many minutes before the end of their booking the dialog box appears to warn a user their booking is running out
                    $Alert1 = (Get-ItemPropertyValue -Path $ppmsRegPath -name Alert1)#Value must be positive (-1 to disable). For bookings less than or equal to 1hours, specify how many minutes before the end of their booking the dialog box appears to warn a user their booking is running out
                    $maxGap = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name maxGap)#Specify the maximum gap between a users two bookings so they arent logged off $Timer minutes after the first booking ends
                    $maxExtension = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name maxExtension)#Specify the maximum length users can extend/make a booking with the script
                    $extendComment = (Get-ItemPropertyValue -Path $ppmsRegPath -name extendComment)#Comment shown in PPMS when booking is extended
                    $Counter = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name Counter) #Record how much time is remaining until a user is automatically logged off
                    $Iteration = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name Iteration) #record number of times script has ran during a booking
                    $popUpTimer = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name popUpTimer) #Specify how long the dialog box appears before automatically closing
                    $emailTimer = (Get-ItemPropertyValue -Path $ppmsRegPath -name emailTimer) #Define when an email is sent to the regular user
                    $pesterGoodFlag = (Get-ItemPropertyValue -Path $ppmsRegPath -name pesterGoodFlag) #If enabled show the "Stop pestering me" button during a booking to allow users to prevent popups
                    $pesterBadFlag = (Get-ItemPropertyValue -Path $ppmsRegPath -name pesterBadFlag) #If enabled show the "Stop pestering me" button outside of a booking to allow users to prevent popups
                    $extendBookingFlag = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name extendBookingFlag)#Enable/Disable ability to extend bookings from the script
                    $logoffUserFlag = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name logoffUserFlag) #Enable/Disable user logoff
                    $sameGroupFlag = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name sameGroupFlag) #Enable(1)/Disable(0) Allow users from the same group to share bookings
                    $sameProjectFlag = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name sameProjectFlag) #Enable(1)/Disable(0) Allow users from the same Project to share bookings
                    $okayGoodFlag = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name okayGoodFlag) #Flag if a user has pressed the okay button
                    $okayBadFlag = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name okayBadFlag) #flag if a user has pressed the okay button, acknowledging they will be logged off soon
                    $firstRunFlag = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name firstRunFlag) #If first run of script, ask user if they want to receive emails
                    $userEmailFlag = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name userEmailFlag) #If first run of script, ask user if they want to receive emails
                    $ignoreUserList = (Get-ItemPropertyValue -Path $ppmsRegPath -name ignoreUserList) #Dont show alert window popups or auto-logoff if there's a booking from anyone in this list, this will still track logged in users, separate ppms usernames with commas - useful for running workshops on analysis VMs etc
            
                    wait
        
                    #load other scripts
                    . "$scriptPath\scripts\CustomForm.ps1" 
                    . "$scriptPath\scripts\extendBooking.ps1"
    
                    #get maxExtension value
                    $extensionArray = extendBooking 

                    #Custom Popup buttons
                    $extendButton = "Quick Book until $($extensionArray.extendEndShortString)"
                    $ppmsButton = "Open PPMS"
                    $okayButton = "Okay"
                    $logoffButton = "log Off"
                    $reportIncident = "Report Incident" 
    
                    $Warning = "$PCname"
                    $message = ""  #reset popup message

                    #Open PPMS in browser, required on systems that run old IE versions, edit if required
                    Function openPPMS {
                        try{[system.Diagnostics.Process]::Start($browser,"$ppmsURL/planning/?pf=$ppmsPF&item=$ppmsID") | Out-Null
                            logdata "open ppms with browser : $browser"}
                        catch{
                            try{[system.Diagnostics.Process]::Start("chrome","$ppmsURL/planning/?pf=$ppmsPF&item=$ppmsID") | Out-Null
                            logdata "open ppms with browser : chrome"}
                            catch{[system.Diagnostics.Process]::Start("msedge","$ppmsURL/planning/?pf=$ppmsPF&item=$ppmsID") | Out-Null
                            logdata "open ppms with browser : edge"}
                        }
                    }

                    #Report Incident
                    Function reportIncident {
                        Do{
                            #Call IncidentLevel script, this allows powershell to repeatedly popup the message rather than causing errors if you embed IncidentLevel code in this script
                            . "$scriptPath\scripts\IncidentLevel.ps1" 
                            If($WPFMessageBoxOutput -eq "Cancel"){Break}
                            } While (($Severity -ne $null) -and ($incidentDescription -eq ""))  

                        If(($Severity -ne $null) -and ($incidentDescription -ne "")){
                            $rawIncidentDetails = $incidentDescription
                            $incidentDetails = "user: $pcUser" + "`r`n" + $incidentDescription
                            $incidentDescription = $($incidentDetails).replace(" ","+") #replace spaces in textbox output with + to enable spaces in Invoke-webrequest.  need to remove these + for emails etc
                            $incidentDescription = $($incidentDescription).replace("`r`n","%0a%0a") #replace carriage return with URL safe equivalent
                            $incidentDescription = $($incidentDescription).replace("`r","%0a%0a") #replace carriage return with URL safe equivalent
                            $incidentDescription = $($incidentDescription).replace("`n","%0a%0a") #replace line feed with URL safe equivalent

                            $incidentOutput = Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "action=createinc&apikey=$pumapiKey&id=$ppmsID&severity=$severityNumber&descr=$incidentDescription"
                   
                            #format incident output from PPMS API call
                            $incidentOutput = $incidentOutput.Trim()
                            $incidentOutput = $incidentOutput.TrimEnd("`r")
                            $incidentOutput = $incidentOutput.TrimEnd("`n")
                            $incidentOutput -match "#(?<content>.*) " #find incident ID using Regex
                            $incidentID = $matches['content']
                            $incidentLink = "$ppmsURL/inc/?inc=$incidentID" 

                            $emailBody = "An Incident Has Been Reported On $PCname by $pcUser.`r`n`r`n" + $incidentLink + "`r`n`r`n" + $rawIncidentDetails + "`r`n`r`nKind Regards,`r`n"+"IMB Microscopy`r`n"+"$From`r`n"
                            #sendEmail $emailFrom $pcUser $smtpClient $emailBody
                            sendEmail -emailBody $emailBody -emailSubject "Attention - $pcName"
                            logdata "Incident Email Sent"

                            If($slackFlag){
                                #Slack message
                                    $author = $PCname
                                    $Title =  "ppmsLogoff script"
                                    $message = "An Incident Has Been Reported On $PCname by $pcUser.`r`n`r`n" + $incidentLink + "`r`n`r`n" + $rawIncidentDetails
                                    $channel = "equipment"
                                    $icon = ":microscope:" 
                                    $color = "#FFA500"  #orange

                                    $body = ConvertTo-Json @{
                                        username = $author
                                        pretext = $Title
                                        text = $message
                                        channel = $channel
                                        icon_emoji = $icon
                                        color = $color
                                    }

                                    try {
                                        Invoke-RestMethod -uri $uriSlack -Method Post -body $body -ContentType 'application/json' | Out-Null
                                    } catch {
                                        logdata "oops, Slack not working"
                                    }
                            }

                            If($teamsFlag){
                                #Teams message
                                $script =  "PPMSLogoff script"
                                $message = "An Incident Has Been Reported On $PCname by $pcUser.`r`n`r`n" + $incidentLink + "`r`n`r`n" + $rawIncidentDetails
                                $text = $script + "<br/>" + $message

                                try {
                                    $body = '{"title": ' + "'" + $PCname + "'" + ',"text": ' + "'" + $text + "'" + '}'
                                    Invoke-RestMethod -Method post -ContentType 'Application/Json' -Body $body -Uri $webHook
                                } catch {
                                    logdata "oops, Teams not working"
                                }
                            }
                        }
                    }

                    #If the Extend Button functionality is enabled, display the Extend booking button in the popup as required
                    Function showButtons ([int]$extendBooking, [int]$pesterUser) {
                        If($extensionArray.extendLength -le 0 -or ($pcUser -ne $nowUser)) {$extendBooking = 0}
                        If ($extendBooking -eq 1 -and $pesterUser -eq 1) {
                            return $customButtons = @($extendButton, $ppmsButton, $reportIncident,  $okayButton)
                        }
                        if ($extendBooking -eq 1 -and $pesterUser -eq 0){
                            return $customButtons = @($extendButton, $ppmsButton, $reportIncident)
                        }
                        If ($extendBooking -eq 0 -and $pesterUser -eq 1) {
                            return $customButtons = @($ppmsButton, $reportIncident, $logoffButton, $okayButton)
                        }
                        If ($extendBooking -eq 0 -and $pesterUser -eq 0) {
                            return $customButtons = @($ppmsButton, $reportIncident, $logoffButton)
                        }
                    }

                    Function doButtonAction ($WPFMessageBoxOutput) {
                        If ($WPFMessageBoxOutput -eq $extendButton) {
                            If(($extensionArray.ExtendFlag -eq 1) -and ![string]::IsNullOrEmpty($userID)) {
                                #Function to get project info
                                . "$scriptPath\scripts\getProjects.ps1"
                                $myProjectID = (getProjects -session $sessionID).id
                                if([string]::IsNullOrEmpty($myProjectID)) {$myProjectID = "0"}
                                try{
                                    $newExtension = Invoke-RestMethod -TimeoutSec $ppmsTimeout -Uri $ppmsURL/API2/ -Method "POST" -ContentType "application/x-www-form-urlencoded; charset=UTF-8" -Body "action=SetSessionBooking&apikey=$apiKey&start=$($extensionArray.extendStartStringPPMS)&end=$($extensionArray.extendEndStringPPMS)&systemid=$ppmsID&projectid=$myProjectID&SE1=false&SE2=false&comment=$extendComment&repeat=0&assisted=false&user=$userID&assistant=0&form=" -ErrorAction stop | Out-Null
                                    logdata "booking extended to $($extensionArray.extendEndShortString) with booking ID: $($newExtension.id)"
                                }catch{logdata "couldnt extend booking"}
                                #New-WPFMessageBox -Content "Your session will end at $($extensionArray.extendEndShortString)"
                            } 
                            Else {logdata "
                                Extend Booking not possible"
                            }
                        }
                        ElseIf ($WPFMessageBoxOutput -eq $okayButton){
                            logdata "set flag so booking ending popup doesnt appear next time"
                            $okayGoodFlag = 1
                            New-ItemProperty -Path $ppmsRegPath -name okayGoodFlag -Value $okayGoodFlag -Force > $null
                            wait
                            try{$note = Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "apikey=$pumapiKey&action=getsessionnote&resid=$sessionID"} #set session note for booking
                            catch{$note = ""
                                logdata "couldnt get booking note from ppms"
                            }
                            If(($note -match "\w") -eq $true -and $($note[$note.Length+1] -ne ",")) {$comma = ","}Else{$comma = ""}
                            $time = (Get-Date).ToString("HH:mm")
                            $note = $note + "$comma$time=pesterOff"
                            try{Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "apikey=$pumapiKey&action=setsessionnote&resid=$sessionID&note=$note"} #set session note for booking
                            catch{logdata "couldnt make booking note"}
                        }
                        ElseIf ($WPFMessageBoxOutput -eq $ppmsButton) {openPPMS}
                        ElseIf ($WPFMessageBoxOutput -eq $logoffButton){. "$scriptPath\scripts\logoff.ps1"}
                        ElseIf ($WPFMessageBoxOutput -eq $reportIncident){reportIncident}
                        Else {}
                    }

                    #configure the custom popup form
                    $Params2 = @{
                        Title = $PCname
                        TitleFontSize = 20
                        TitleBackground = 'Purple'
                        TitleTextForeground = 'White'
                        ButtonType = 'None'
                        Sound = 'Windows Exclamation'
                        ContentFontSize = 18
                    }

            #Conditional Stuff #############################################################################################################################
            
                    $winGroup = (getUserInfo $pcUser).group
                    logdata "logged in users group = $winGroup"
                    $nowGroup = (getUserInfo $nowUser).group
                    logdata "Booked users group = $nowGroup"
            
                    #test for special user types to ignore, ie: Trainings and Workshops etc
                    $ignoreUserArray = $ignoreUserList -split "," #convert ignoreUserList to array
                    if(![string]::IsNullOrEmpty($ignoreUserList) -and ($ignoreUserArray -contains $nowUser)){
                        $ignoreUser = 1
                        logdata "ignore user: $nowuser"
                    }else{$ignoreUser = 0}
            
                    #do users share a project (alternative to belonging to the same group)
                    $sameProject = $false
                    if($sameProjectFlag -and !$ignoreUser){
                        #Load script to check if two users share a project
                        . "$scriptPath\scripts\sharedProjects.ps1"
                        if(![string]::IsNullOrEmpty($pcUser) -and ![string]::IsNullOrEmpty($nowUser)){
                            $sameProject = sharedProjects -user1 $pcUser -user2 $nowUser
                        }
                    } 
                    logdata "sameProject = $sameProject"

                    #If the users belong to existing ppms groups
                    If(!([string]::IsNullOrEmpty($winGroup)) -and !([string]::IsNullOrEmpty($nowGroup))){
                        #and if group booking sharing is enabled
                        If ($sameGroupFlag -or $sameProjectFlag) {
                            If (($winGroup -eq $nowGroup) -or $sameProject -or $ignoreUser) {
                                $sameGroup = 1
                                logdata "Windows user belongs to the same group as the booked user, or share a project, or is a special user - sameGroup = 1"
                            }
                            Else {
                                $sameGroup = 0
                                logdata "Windows user belongs to a different group to the booked user and doesn't share a project and isnt a special user - sameGroup = 0"
                            }
                        } #new stuff below
                        Else {
                            logdata "sameGroupFlag = $sameGroupFlag, sameProjectFlag = $sameProjectFlag"
                            If($pcUser -eq $nowUser){
                                $sameGroup = 1
                                logdata "logged in user = current booked user, sameGroup = 1"
                            }
                            Else {
                                $sameGroup = 0
                                logdata "Strict user booking policy applies - sameGroup = 0"
                            }
                        }
                    } Else {
                        $sameGroup = 0
                        logdata "$pcUser - you dont belong to a valid group in PPMS, or there isnt a current booking"
                    } #end new stuff
        <#
                    Else {
                        $sameGroup = 0
                        logdata "Strict user booking policy applies"
                    }
        #>
         

                    #If the logged in user has a booking now, or the logged in user belongs to the same group as someone with a booking
                    If (($pcUser -eq $nowUser) -or ($sameGroup -eq 1) -or ($ignoreUser -eq 1)) {
                        logdata "logged in user has a booking or belongs to same group as someone with a booking"
            
                        if($ignoreUser -eq 1){$pcUser = $nowUser}  #allow unknown login user to login to workshops etc listed in $ignoreUserList

                        #On first run of script,
                        If($firstRunFlag -eq 1) {
                            . "$scriptPath\scripts\userEmails.ps1"  #ask if user wants to receive email reminders
                            . "$scriptPath\scripts\askQuestion.ps1" #random popup questionairre
                        }
        
                        If ([int]$okayBadFlag = 1) { #reset no booking popup flag
                            $okayBadFlag = 0
                            logdata "reset okayBadFlag to 0"
                            New-ItemProperty -Path $ppmsRegPath -name okayBadFlag -Value $okayBadFlag -Force > $null
                            wait
                        }

                        If ($Iteration -ne 0) { #reset Iterations which are only used when the booking has ended
                            $Iteration = 0
                            logdata "reset Iteration to 0"
                            New-ItemProperty -Path $ppmsRegPath -name Iteration -Value $Iteration -Force > $null
                            wait
                        }
        
                        #If the logged in user has a booking, and also has the next booking, with less than $maxGap between them
                        If (($nowUser -eq $nextUser) -and (($nowMins + $maxGap) -ge $nextMins)) {
                            #Dont do Anything
                            logdata "Dont pop up a warning for this booking"
                            logdata "nowUser = nextUser"
                            logdata "nowMins = $nowMins"
                            logdata "nextMins = $nextMins"
                            If ($okayGoodFlag = 1) { #reset booking popup flag if it's the last booking
                                $okayGoodFlag = 0
                                logdata "reset okayGoodFlag to 0"
                                New-ItemProperty -Path $ppmsRegPath -name okayGoodFlag -Value $okayGoodFlag -Force > $null
                                wait
                            }
                        }

                        #If the logged in user doesnt have the next booking, or they do but it's more than $maxGap away
                        If (($nowUser -ne $nextUser) -or (($nowUser -eq $nextUser) -and (($nowMins + $maxGap) -lt $nextMins))) {
                            logdata "nowUser != nextUser"
                            logdata "okayGoodFlag = $okayGoodFlag"
                            logdata "nowMins = $nowMins"
                            $extendBooking = 0
                
                            #send user email
                            If(($nowMins -eq $AlertLong) -or ($nowMins -eq $Alert8) -or ($nowMins -eq $Alert3) -or ($nowMins -eq $Alert1)) {
                                logdata "send email and reset pester user flag"
                                $sendEmailFlag = 1
                                $okayGoodFlag = 0
                            } Else{$sendEmailFlag = 0}

                            If(($userEmailFlag -eq 1) -and ($sendEmailFlag -eq 1)) {
                                logdata "send user email"
                                $emailBody = "Your session on $PCname ends in $formatNow.`r`n`r`n"+"Kind Regards,`r`n"+"IMB Microscopy`r`n"+"$From`r`n"
                                sendEmail -emailBody $emailBody -emailSubject "Attention - $PCname"
                                logdata "session alert email sent"
                            }Else {logdata "User requested to not receive an alert email, or Alert time not satisfied"}

                            #If the user doesnt have much time remaining and they havent dismissed the popup before
                            If ((($nowMins -le $Alert1) -or ($userEmailFlag -eq 1)) -and ($nowMins -ge 1) -and ($okayGoodFlag -eq 0)) {
                                logdata "your booking will end in $formatNow"
                                $message = "$pcUser, your booking for $PCname will end in $formatNow$CRLF$CRLF"
                                        
                                #If there's a booking after by someone else
                                If (($nextUser -ne "") -and ($nextUser -ne $pcUser)) {
                                    $message = $message + "$nextUser has a booking for $PCname commencing in $formatNext$CRLF$CRLF"
                                    }
                                #If the current user is also the next user           
                                ElseIf ($nextUser -eq $pcUser){
                                    $message = $message + "You have a booking for $PCname commencing in $formatNext$CRLF$CRLF"
                                }
                                #There arent any future bookings
                                Else {
                                    logdata "No future bookings - Display Extend booking button"
                                    $extendBooking = $extendBookingFlag
                                    $message = $message + "There are no future bookings for $PCname$CRLF$CRLF"
                                }
                                #If theres a booking after and the gap is greater than the popup alert time 
                                If (($nextUser -ne "") -and (($nextMins - $nowMins) -ge $Alert1)) {
                                    logdata "Theres a booking after the gap - Display Extend booking button"
                                    $extendBooking = $extendBookingFlag
                                    $message = $message + "Extend your booking, or you will be automatically logged off in $(formatMinutes ($nowMins + $Timer))$CRLF$CRLF"
                
                                }
                                #If theres a booking after and the gap is less than the popup alert or there isnt a next user
                                ElseIf ((($nextUser -ne "") -and (($nextMins - $nowMins) -lt $Alert1)) -or ($nextUser -eq "")) {
                                    $message = $message + "Please save your work and logoff before the end of your session$CRLF$CRLF"+"Or you will be automatically logged off in $(formatMinutes ($nowMins + $Timer))$CRLF$CRLF"
                                }
                 
                                If($pesterGoodFlag -eq 1) {
                                    $pesterUser = 1
                                } Else { $pesterUser = 0} 
            
                                $buttons = showButtons $extendBooking $pesterUser
                
                                $scriptEnd = (Get-Date)
                                $VBStime = 5000 #how long VBS script takes to run, need to tweak this to prevent two scripts running at once
                                $scriptTime = [math]::Floor(60000 - ($scriptEnd - $scriptStart).TotalMilliseconds - $VBStime)/1000
                                if(((Get-Date).Second -gt 0) -and ((Get-Date).Second -lt 10)){
                                    logdata "show popup window"
                                    New-WPFMessageBox @Params2 -CustomButton $buttons -Content $message -Timeout $scriptTime
                                    doButtonAction $WPFMessageBoxOutput
                                }else{logdata "dont show popup window as it's not the start of the minute between 0-10 secs"}
                            }
                        }
                    }
                    Else {
                        #logged in user doesnt have a booking

                        "$pcUser doesnt have a booking"
                        $Counter = $Timer - $Iteration
                        "Counter = $Counter"

                        #If time has run out, logoff the user
                        If ($Counter -le 0) {
                            logdata "Counter < 0, logoff if logoffUserFlag = 1"
                            If ($logoffUserFlag -eq 1) {
                                #$session = ((quser /server:$server | ? { $_ -match $pcUser }) -split ' +')[1]
                                #logoff $session
                                shutdown /l /f
                            }
                        }

                        #Send email to the logged in user
                        If ($Counter -eq $emailTimer) {
                            If($userEmailFlag -eq 1) {
                                $emailBody = "Please logoff your session on $PCname.`r`n`r`n"+"Kind Regards,`r`n"+"IMB Microscopy`r`n"+"$emailFrom`r`n"
                                #sendEmail $PCname $emailFrom $pcUser $smtpClient $emailBody
                                sendEmail -emailBody $emailBody -emailSubject "Attention - $PCname"
                                logdata "End of session email sent"
                            }Else {logdata "User requested to not receive an alert email"}
                        }

                        If ($okayGoodFlag = 1) { #reset booking popup flag 
                            $okayGoodFlag = 0
                            logdata "reset okayGoodFlag to 0"
                            New-ItemProperty -Path $ppmsRegPath -name okayGoodFlag -Value $okayGoodFlag -Force > $null
                            wait
                        }
                        logdata "okayBadFlag = $okayBadFlag"
                        #If logged in user doesnt have a booking before logging in 
                        If (($okayBadFlag -eq 0)){
                            $extendBooking = 0
                            $message = "$pcUser, you don't have a session booked at this time-slot for $PCname$CRLF$CRLF"
                            #If there is a current booking
                            If ($nowUser -ne "") {
                                $message = $message + "$nowUser has a session which ends in $formatNow$CRLF$CRLF"
                                #next user exists
                                If ($nextUser -ne "") {
                                    #next user is you
                                    If($nextUser -eq $pcUser) {
                                        If(($Counter -ge $nextMins) -and ($nextMins -eq 0)) {
                                            $hideWindow = $true
                                            logdata "hidewindow = true 1"
                                        } Else {$hideWindow = $false}
                                        If(($Counter -ge $nextMins) -and ($nextMins -gt 0)) {
                                            $message = $message + "Luckily, you have a session commencing in $formatNow$CRLF$CRLF"+"So you won't be automatically logged off$CRLF$CRLF"+"Next time, please log-on only during your session$CRLF$CRLF"
                                        }
                                        Elseif($Counter -lt $nextMins) {
                                            $message = $message + "You have a session commencing in $formatNext minute/s $CRLF$CRLF"+"Next time, please log-on only during your session$CRLF$CRLF"
                                            If ($logoffUserFlag -eq 1) {$message = $message + "You will be automatically logged off in $(formatMinutes $Counter)$CRLF$CRLF"}
                                        }
                                    }
                                    #next user is someone else
                                    Else {
                                        $message + "$nextUser has a session commencing in $formatNext$CRLF$CRLF"
                                        If ($logoffUserFlag -eq 1) {$message = $message + "You will be automatically logged off in $(formatMinutes $Counter)$CRLF$CRLF"}
                                        Else {$message = $message + "Next time, please log-on only during your session$CRLF$CRLF"}
                                    }
                                }
                                #no next user
                                Else {
                                    If ($Counter -ge $nowMins) {
                                        $message = $message + "Please make a booking immediately$CRLF$CRLF"
                                        If ($logoffUserFlag -eq 1) {$message = $message + "Otherwise, you will be automatically logged off in $(formatMinutes $Counter)$CRLF$CRLF"}
                                        Else {$message = $message + +"Next time, please make a booking before logging on$CRLF$CRLF"}
                                    }
                                    Elseif ($Counter -lt $nowMins) {
                                        If($logoffUserFlag -eq 1) {$message = $message + "You will be automatically logged off in $(formatMinutes $Counter)$CRLF$CRLF"}
                                        Else{$message = $message + "Please ensure you have a booking before logging on next time$CRLF$CRLF"}
                                    }
                                }
                            }
                            #no current booking
                            Else {
                                #If $nextUser is You
                                If($nextUser -eq $pcUser) {
                                    If(($Counter -ge $nextMins) -and ($nextMins -eq 0)) {
                                        $hideWindow = $true
                                        logdata "hidewindow = true 2"
                                    } Else {$hideWindow = $false}
                    	            If (($Counter -ge $nextMins) -and ($nextMins -gt 0)) {
                                        $message = $message + "Luckily, you have a session commencing in $formatNext$CRLF$CRLF"+"So you won't be automatically logged off$CRLF$CRLF"+"Next time, please log-on only during your session$CRLF$CRLF"
                                        $earlyUser = 1
                                    }
                                    Elseif ($Counter -lt $nextMins) {
                                        $message = $message + "You have a session commencing in $formatNext$CRLF$CRLF"
                                        If ($logoffUserFlag -eq 1) {$message = $message + "Make a booking or you will be automatically logged off in $(formatMinutes $Counter)$CRLF$CRLF"}
                                        Else {$message = $message + "Next time, please log-on during your session$CRLF$CRLF"}
                                    }
                	            }
            	                #$nextUser is someone else
                                Elseif($nextUser -ne "") {
                                    $message = $message + "$nextUser has a session commencing in $formatNext$CRLF$CRLF"
                                    If ($logoffUserFlag -eq 1) {$message = $message + "Make a booking or you will be automatically logged off in $(formatMinutes $Counter)$CRLF$CRLF"}
                                    Else {$message = $message + "Next time, please log-on during your session$CRLF$CRLF"}
            	                }
                                #There isnt a next user
                                Else {
                                    If ($logoffUserFlag -eq 1) {$message = $message + "Please make a booking, logoff or you will be automatically logged off in $(formatMinutes $Counter)$CRLF$CRLF"}
                                    Else {$message = $message + "Please make a booking or logoff immediately$CRLF$CRLF"}
            	                }
                            }
                            If($pesterBadFlag -eq 1 -or $earlyUser -eq 1) {$pesterUser = 1} Else { $pesterUser = 0}
                            $buttons = showButtons $extendBooking $pesterUser
                            $scriptEnd = (Get-Date)
                            $VBStime = 5000 #how long VBS script takes to run, need to tweak this to prevent two script running at once
                            $scriptTime = [math]::Floor(60000 - ($scriptEnd - $scriptStart).TotalMilliseconds - $VBStime)/1000
                            $Iteration = $Iteration + 1
                            "Iteration = $Iteration"
                            New-ItemProperty -Path $ppmsRegPath -name Iteration -Value $Iteration -Force > $null
                            wait

                            If($hideWindow -eq $false){
                                if(((Get-Date).Second -gt 0) -and ((Get-Date).Second -lt 10)){
                                    logdata "show popup window"
                                    New-WPFMessageBox @Params2 -CustomButton $buttons -Content $message -Timeout $scriptTime
                                    doButtonAction $WPFMessageBoxOutput
                                }else{logdata "dont show popup window as it's not 0-10 secs"}
                            }Else {logdata "hide window - same user has last and next booking"}
                        }
                    }
                }
                Else {
                    logdata "is an Admin, script ignored"
                    logdata "adminCounter = $adminCounter"
                    If($emailAdminFlag -eq 1) {
                        #Send email to the logged in admin on every multiple of $adminTimer
                        logdata "adminCounter = $adminCounter"
                        logdata "adminTimer = $adminTimer"
                        If (($adminCounter -ne 0) -and ($adminCounter % $adminTimer -eq 0)) {
                            logdata "adminTimer value reached, send email"
                            $emailBody = "An Admin session has been running on $PCname for $(formatMinutes $adminCounter).`r`n`r`n"+"Kind Regards,`r`n"+"IMB Microscopy`r`n"+"$From`r`n"
                            #sendEmail $PCname $emailFrom $pcUser $smtpClient $emailBody
                            sendEmail -emailBody $emailBody -emailSubject "Attention - $PCname"
                            logdata "Admin session running email sent"
                        }
                    }Else {logdata "Admin requested to not receive an alert email"}
                    $adminCounter = $adminCounter + 1
                    New-ItemProperty -Path $ppmsRegPath -name adminCounter -Value $adminCounter -Force > $null
                    wait
                }
            }else{logdata "couldn't determine ppms system"}
        }else{logdata "cannnot connect to ppms server"}
    }else{logdata  "config script hasnt run yet"}
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
    $goFlag = goNogo $settingsTable.logoff #determine if the script should run
    logdata $goFlag.log
    if($goFlag.runFlag){
        $hideWindow = $false
        $logoffNow = ""
                                If($debug -eq $true){
        $pcUser = "uqjspri1"
        $nowUser = "uqjspri1"
        $nextUser = ""
        $nowMins = 14
        $nextMins= 0
    } Else {$pcUser = $env:UserName}
        . $getUser
        . $getConfigTime
        . $Logoff
    }else{logdata "goFlag = false, script didnt run"}
}else{logdata "disableAll flag = true, didnt run script"}

###End code ###
. $endScript #write end info to log
###############################################
