<#
autoDeleteFiles script

Requires - autoDelete_Settings.ps1

A Script to autoDelete files once a threshold (lowTide) of free space has been exceeded

The script will start with the oldest files and progressively delete newer files until the required free HDD space (highTide) is achieved

At each defined file age criterion, the script will delete the largest files first, check the HDD space, and repeat for smaller and smaller files until the HDD free space meets the % free space required

If the free HDD space is not met on the first age criterion, the script will move to the next age criterion and repeat

The script will work it's way through the age and size criteria until it either frees up enough HDD space (highTide), or it exhausts the criteria, then the script will end

A Logfile may be generated in the chosen location to report actions

Installation requirements:
    Win7 will require .NET 4.5 or higher and then WPF5.1 to be installed first, these should be included in the installation folder, or download them from the links below: 
    	https://www.microsoft.com/en-au/download/details.aspx?id=30653
    	https://www.microsoft.com/en-us/download/details.aspx?id=54616

The script can scan multiple root folders per drive
    Open and run "freeHDD.ps1" in Powershell_ISE to determine the current free space on each drive selected to assist in setting up the "Config.ps1" file parameters
    Open "Config.ps1" in PowerShell_ISE and configure the script parameters as required then save

#>

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
                $settings = $settings #create task as elevated User
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

$getUser = {
    $quserResult = quser 2>&1
    $quserRegex = $quserResult | ForEach-Object -Process { $_ -replace '\s{2,}',',' }
    $quserObject = $quserRegex | ConvertFrom-Csv
    $break = $false
    $userArray = @()
    foreach($user in $quserObject){
        if($user.ID -notmatch "Disc"){
            $activeUser = [PSCustomObject] @{
                USERNAME = ($user.USERNAME).Trim(">")
                'LOGON TIME' = $user.'LOGON TIME'
            }
        $userArray += $activeUser
        }
    }
    $sortArray = $userArray | Sort-Object {$_.'LOGON TIME'} -Descending
    $username = ($sortArray[0]).USERNAME 
}

$getPCname = {
    #get PCname
    $PCname = try{(Get-ItemPropertyValue -Path $LM_rootPath\PPMSscript -name systemName -ErrorAction Stop) }catch{$system = [string]($env:COMPUTERNAME)}
}

$getFullName = {
    #get users full name
    try{$userFullname = (Get-ItemPropertyValue -Path $ppmsregPath -name userFullname -ErrorAction Stop)}catch{$userFullName = $username}
}

Function Log {
    #Function to format text into logfile format
    Param(
        $indent,
        $logInput
    )

    $myLog = $indent + $logInput + "`r`n" #Format log

    #log data to console 
    try{if(![string]::IsNullOrEmpty($logToConsole)){if($logToConsole){$myLog}}
    }catch{""}

    #log to file
    try{$logPathExists = (Test-Path $logPath)}catch{$logPathExists = $false}
    if($logToFile -and $logPathExists -and ![string]::IsNullOrEmpty($logInput)){
        Add-Content -Path $logPath -Value $myLog
    }elseif($logToFile -and !$logPathExists -and ![string]::IsNullOrEmpty($logInput)){
        $global:log = $global:log + "`r`n"  + $myLog
    }
}

$sendEmail = {
#send email to facility staff
    If($emailFlag){
        if(testURL -inputURL $smtpClient -port $emailPort ){
            #email message
            $emailSubject = "Attention - $PCname - autoDelete script"   
            $emailBody = "System: $pcName`r`nUser Name: $username`r`nFull Name: $userFullname`r`n`r`n" + $msg

            $secpasswd = ConvertTo-SecureString $emailPass -AsPlainText -Force #convert plain text email password to hashed password
            $credentials = New-Object System.Management.Automation.PSCredential ("$emailUser", $secpasswd) #generate a hashed credential for secure email server

            $emailParams = @{
                From = $emailFrom
                To = $emailToAdmin
                Subject = $emailSubject 
                Body = $emailBody + "`r`n`r`n" + $emailSig
                SmtpServer = $smtpClient
                port = $emailPort
            }
    
            If($secureEmailFlag -eq 1) {
                $emailParams.UseSsl = $true
                $emailParams.Credential = $credentials  
            }
    
            Try{Send-MailMessage @emailParams}
            Catch{log -logInput "oops, emails not working"}
        }
    }else{log -logInput "Email - webserver appears to be down"}
}

$sendSlack = {
    If($slackFlag){
    #Slack message
        $author = $PCname
        $Title =  "autoDelete script"
        $message = "low HDD space after scriptrun at $fullUsername($USERNAME) login`r`n Adjust config script parameters`r`n Logfile saved to $logPath"
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

        if(testURL $uriSlack){
            try {
                Invoke-RestMethod -uri $uriSlack -Method Post -body $body -ContentType 'application/json' | Out-Null
            } catch {
                log -logInput "Slack - something went wrong"
            }
        }Else{log -logInput "Slack - website appears to be down"}
    }
}

$sendTeams = {
    If($teamsFlag){
        #Teams message
        $script =  "AutoDelete script"
        $message = "$msg  <br/> <br/> Full Name: $userFullname <br/> Username: $USERNAME"  #"low HDD space warning <br/> Username: $USERNAME"
        $text = $script + "<br/>" + $message

        if(testURL $webHook){
            try {
                $body = '{"title": ' + "'" + $PCname + "'" + ',"text": ' + "'" + $text + "'" + '}'
                Invoke-RestMethod -Method post -ContentType 'Application/Json' -Body $body -Uri $webHook
            } catch {
                log -logInput "Teams - something went wrong"
            }
        }Else{log -logInput "Teams - website appears to be down"}
    }
}

$customParams = {
    #configure Remove-item parameters for use in $deleteFiles subscript
    $removeParams = @{} #reset parameters
    If($deleteFilesFlag){ #Add the -include parameter and it's values if required
        $removeParams += @{
            Include = $deleteTypes
        }

    }
    If($excludeFilesFlag){ #Add the -exclude parameter and it's values if required
        $removeParams += @{
            Exclude = $excludeFiles
        }
    } 
}

$deleteFiles = {
    #subscript to delete files and folders
    $deleteStartTime = Get-Date #get file deletion start time
    $deleteStartTimeString = $deleteStartTime.DateTime #format to string
    Log -logInput "`t`t`t`t`t`t`t`tStart file deletion on $deleteStartTimeString" #write to log
    $files = Get-ChildItem -Path $path -Recurse | Where-Object {($PSItem.LastWriteTime -lt (Get-Date).AddDays(-$agethreshold)) -and (($PSItem.Length/1GB) -gt $sizeThreshold)} #Get list of files that meet the criteria
    If($files -ne $null){ #If there are files that meet the age and size criteria
        $fileCount = 0 #reset file counter
        Foreach($file in $files){ #For each file, delete if it meets the deleteTypes and excludeFiles criteria
            
            If($enableDeletion){$output = $file | Remove-Item -Recurse @removeParams -Force -ErrorAction SilentlyContinue -Verbose 4>&1} #Delete file if it meets the criteria (4>&1 writes the verbose stream to the output stream for logging)
            If($output -ne $null){ #If the file was deleted
                $fileCount++ #increment the filecount variable
                Log -logInput "`t`t`t`t`t`t`t`t`t$output of size $([Math]::Round(($file.length/1MB),2))MB" #if the file was deleted, write to log
            }
        }
        If($fileCount -eq 0){Log -logInput "`t`t`t`t`t`t`t`tThere are no files greater than $age days old and $($size)GB to delete, that meet the criteria"} #If there were files, but they didnt meet the excludeFiles and deleteTypes criteria write to log
    }Else{Log -logInput "`t`t`t`t`t`t`t`t`tThere are no files greater than $age days old and $($size)GB to delete"} #If there were no files that met the age and size criteria, write to log
    $deleteEndTime = Get-Date #get file deletion end time
    $deleteEndTimeString = $deleteEndTime.DateTime #format to string
    Log -logInput "`t`t`t`t`t`t`t`tEnd file deletion on $deleteEndTimeString" #write to log
    Log -logInput "`t`t`t`t`t`t`t`tFile deletion time = $($deleteEndTime - $deleteStartTime)" #write to log
}

$getTides = {
    #get lowTide and highTide values for this drive
    $lowTide = $highTide = ""
    $validDriveIndex = $driveIndex = -1
    $validDriveIndex = $($driveTable.keys).indexOf($driveLetter)
    if($validDriveIndex -ne -1){
        $driveIndex = $($lowTideTable.keys).indexOf($driveLetter)
        $lowTide = $lowTideTable[$driveIndex]
        $highTide = $highTideTable[$driveIndex]
    }
}

$getHDDspace = {
#subscript to determine amount of free HDD space in %
    Try{
        $disk = Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DriveType -eq '3' -and $_.DeviceID -eq $drive}
        $freeHDD = [long]([long]$disk.FreeSpace/[long]$disk.Size*100) #calculate the disk free space in %
        If($freeHDD -lt $lowTide){$lowStatus = "less"} Else{$lowStatus = "more"} #generate status string
        If($freeHDD -lt $highTide) {$highStatus = "less"} Else{$highStatus = "more"} #generate status string
        if($excludeDriveNames.Contains($disk.VolumeName)) {$freeHDD = -1} #ignore drives with a specified name such as USB security keys
    }Catch{
        $freeHDD = -1 #handle non-existent drive
    }    
}

$tailRecursion = {
    #subscript to start at the lowest folder level of $startPath and delete all empty folders working back up to $startPath

    param($path) #define path 
    foreach ($childDirectory in Get-ChildItem -ErrorAction SilentlyContinue $path -Directory) {& $tailRecursion -Path $childDirectory.FullName} #recursively generate filepaths to lowest level
    $currentChildren = Get-ChildItem -ErrorAction SilentlyContinue $path #get folder path
    $isEmpty = $currentChildren -eq $null #is folder empty?
    #If the folder is empty and isnt the top level folder, delete it
    if ($isEmpty -and ($path -ne $startPath)) {
        If($enableDeletion){[String]$removeOutput = Remove-Item -ErrorAction SilentlyContinue $Path -Recurse -Exclude $excludeFiles -Verbose 4>&1 }#delete empty folder 
        $removeOutput = "`t`t`t`t`t`t" + $removeOutput
        Log -logInput $removeOutput #write to log
    }
}

$scanDrives = {
    $breakout = $false #reset flag to end deletion when freeHDD criteria are met
    $lowTideFlag = $false #reset delete flag

    #if current user isnt the last user, run script
    try{$lastUser = Get-ItemPropertyValue -Path $autoDeleteRegPath -Name lastUser -ErrorAction stop }catch{$lastUser = ""}
    if(($lastUser -notmatch $username)){
        New-ItemProperty -Path $autoDeleteRegPath -Name lastUser -Value $username -Force | out-null
        #Scan each drive sequentially
        Foreach($driveLetter in $driveTable.keys){
            #Log #Write empty line to Log
            $drive = $driveLetter+":" #format for use in getHDDSpace etc

            . $getTides #calculate low and high tides
        
            . $getHDDspace #get % of free HDD space
        
            If($freeHDD -ne -1){ #If the HDD exists
            $driveStartTime = Get-Date #get start time of script
            $driveStartTimeString = $driveStartTime.DateTime #format to string
            Log -logInput "`tStart scan of $drive on $driveStartTimeString" #write to log

                Log -logInput "`t`tThe $($drive) HDD has $freeHDD% free space which is $lowStatus than the lowTide = $lowTide%, and $highStatus than the highTide = $highTide% " #write free space to log
                If($freeHDD -lt $lowTide){ #if there isnt enough freeHDD, start deletion scan
                    Foreach($startPath in $($driveTable.$driveLetter)){ #iterate over each startPath in startPathArray
                        $startPath = Resolve-Path $startPath -Verbose 2>&1 #resolve full path if there are wildcards, such as C:\Users\*\Desktop =  C:\Users\j.bloggs\Desktop
                        Foreach($path in $startPath){ #where there are multiple paths defined by wildcards
                            Log -logInput "`t`t`tStart Path = $path" #write to log
                            $validPath = Test-Path $path #check if startPath is a valid path
                            If($validPath){ #if the path is valid, begin scan
                                If($excludePathFlag) { #check to see if path is in the excluded path list
                                    $isExcludedPath = ($excludePaths -contains $path)
                                } Else{$isExcludedPath = $false} 
                                If(!$isExcludedPath){ #If path isnt in the excluded path list
                                    $pathStartTime = Get-Date #get start time of script
                                    $pathStartTimeString = $pathStartTime.DateTime #format to string
                                    Log -logInput "`t`t`t`tStart Scan of $path on $pathStartTimeString"
                                    #Progressively delete files by age and size until there is atleast $lowTide % free
                                    Foreach($age in $ageThresholdArray){ 
                                        Log -logInput "`t`t`t`t`tSet file age deletion threshold to $age days" #write to log
                                        $agethreshold = $age #set threshold for deletion subscript
                                        Foreach($size in $sizeThresholdArray){
                                            Log -logInput "`t`t`t`t`t`tSet file size deletion threshold to $size GB"  #write to log
                                            $sizethreshold = $size #set threshold for deletion subscript
                                            . $getHDDspace #get % of free HDD space
                                            Log -logInput "`t`t`t`t`t`t`tThe $($drive) HDD has $($freeHDD)% free space which is $lowStatus than the lowTide = $($lowTide)%, and $highStatus than the highTide = $($highTide)% " #write free space to log
                                            If($freeHDD -lt $lowTide){$lowTideFlag = $true} #If freeHDD is less than the lowTide mark, begin deletion
                                            ElseIf($freeHDD -ge $highTide){$lowTideFlag = $false} #If freeHDD is greater or equal to highTide mark, stop deletion
                                            If($lowTideFlag -and ($freeHDD -lt $highTide)) {#begin deletion of files if freeHDD is less than lowTide and keep going until highTide is met
                                                . $deleteFiles #call deletion subscript
                                            }Else{
                                                Log -logInput "`t`t`t`t`t`t`t`tThe HDD has more than the required $highTide% free - no further deletion required" #write to log
                                                $breakout = $true #set flag to stop scan for all loops
                                                Break #break out of loop
                                            }
                                            If($breakout){Break} 
                                        }
                                        If($breakout){Break}
                                    }
                                    $folderStartTime = Get-Date #get folder deletion start time
                                    $folderStartTimeString = $folderStartTime.DateTime #format to string
                                    Log -logInput "`t`t`t`t`tStart folder deletion on $folderStartTimeString" #write to log
                            
                                    & $tailRecursion -Path $path #call subscript to delete empty folders recursively
                            
                                    $folderEndTime = Get-Date #get folder deletion end time
                                    $folderEndTimeString = $folderEndTime.DateTime #format to string
                                    Log -logInput "`t`t`t`t`tEnd folder deletion on $folderendTimeString" #write to log
                                    Log -logInput "`t`t`t`t`tFolder deletion time = $($folderEndTime - $folderStartTime)" #write to log
                            
                                    . $getHDDspace #get % of free HDD space
                                    Log -logInput "`t`t`t`tThe HDD has $freeHDD% free space" #write to log
                            
                                    $pathEndTime = Get-Date #get path scan start time
                                    $pathEndTimeString = $pathEndTime.DateTime #format to string
                                    Log -logInput "`t`t`t`tEnd Scan of $path on $pathEndTimeString" #write to log
                                    Log -logInput "`t`t`t`t$path scan time = $($PathEndTime - $PathStartTime)" #write to log
                                } Else {Log -logInput "`t`t`t`t$path is in the excluded path list"}
                            }Else{Log -logInput "`t`t`t`t$path isnt a valid Path"}
                            If($breakout){Break}
                        }
                        If($breakout){Break}
                    }
                } Else {Log -logInput "`t`t`tPlenty of free space, so no need to delete anything"}
                $driveEndTime = Get-Date #get path scan start time
                $driveEndTimeString = $driveEndTime.DateTime #format to string
                Log -logInput "`tEnd Scan of $drive on $driveEndTimeString" #write to log
                Log -logInput "`t$drive scan time = $($driveEndTime - $driveStartTime)" #write to log

            }else{ Log -logInput "`tThe $drive HDD doesn't exist"} #Write to Log
        }
    }else{Log -logInput "current user = last user, dont scan or delete"}
}

$formatMsg = {
    $sendEmailFlag = $sendSlackFlag = $sendTeamsFlag = $false #reset email flag
    $emailMsg = ""
    Foreach($driveLetter in $driveTable.keys){
        #Log #Write empty line to Log
        $drive = $driveLetter+":" #format for use in getHDDSpace etc
        . $getTides #calculate low and high tides
        . $getHDDspace #get % of free HDD space
        If(($freeHDD -ne -1) -and ($freeHDD -lt $lowTide)) {
            $msg = "The free HDD space is less than $lowTide% and the autoDeleteFiles Script cant clear any more space on $drive, you may need to adjust the scan parameters"
            Log -logInput $msg
            $emailMsg = $emailMsg + $msg + "`r`n"
            $warningDate = Get-Date -Format "yyyMMdd"
            $warning = Get-ItemPropertyValue -Path $autoDeleteRegPath -name Warning 
            If($warning -ne $warningDate){ #only send warning email/slack once a day
                $sendEmailFlag = $sendSlackFlag = $sendTeamsFlag = $true
                New-ItemProperty -Path $autoDeleteRegPath -name Warning -Value $warningDate -Force
            }        
        }
    }
}

$sendMsg = {
    #send email to admins warning of low disk space
    If($sendEmailFlag){
        Log -logInput "Low HDD free space email sent"
        . $sendEmail
    } 
    #send slack message warning of low disk space
    If($sendSlackFlag){
        Log -logInput "Low HDD free space slack message sent"
        . $sendSlack
    } 

    #send slack message warning of low disk space
    If($sendTeamsFlag){
        Log -logInput "Low HDD free space Teams message sent"
        . $sendTeams
    } 
}



###############################################
### Main Code ###
. $defineSettings #get settings file and set flags
. $getUser #override username with active user, required since we're running the task as System, not user
. $isElevated #test to see if the script has already been elevated to admin
. $checkStatus #check if everything has been installed before
. $runAsAdmin #elevate permissions if required and loop back to the top of the script
. $makeHKLMroot #create HKLM registry path if required
. $createLog #configure logging and create logfile
. $startLog #write start info to log
. $makeTask #create task scheduler task to run script regularly
#. $getSettingsFromURL #get global script settings from web

### Custom Code ###
makeKey $autoDeleteRegPath
. $getPCname
. $getFullName
start-sleep -Seconds 5
$goFlag = Get-ItemPropertyValue -Path $LM_rootPath -name runAutoDeleteFlag #since system user cannot connect to internet, get webflag from registry which was generated in ppmsConfig.ps1
if($goFlag){
    . $customParams
    . $scanDrives
    . $formatMsg
    . $sendMsg
    if($enableDeletion){Clear-RecycleBin -Force -ErrorAction SilentlyContinue} #Empty all recycle bins
}else{logdata "goFlag = false, script didnt run"}


### End code ###
. $endScript #write end info to log
###############################################
