#Script to configure the PC for use in the facility
#install powershell modules, adjust group policy settings etc

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
$unblockFiles = {
    #find root pcConfig folder
    $rootIndex = $scriptPath.IndexOf($rootName)
    $rootPath = $ScriptPath.Substring(0,$rootIndex) + $rootName 

    # Get all files recursively
    try {
        Get-ChildItem -Path "C:\Windows\pcConfig" -File -Recurse -ErrorAction Stop | Unblock-File -ErrorAction Stop
        logdata "Files unblocked successfully"
    }
    catch {
        logdata "Failed to unblock files: $($_.Exception.Message)"
    }
}

$installModules = {
    logdata "check for installed modules"
    #configure powershell module installation
    try{
        if(!((Get-PackageProvider -ListAvailable).Name -contains "nuget")) {
            logdata "installing package provider Nuget"
            try{Install-packageprovider -name NuGet -Force -Scope AllUsers -ErrorAction stop -Confirm:$False }
            catch{logdata "couldnt install package provider Nuget"}
        }else{logdata "nuget module already installed"}
    }catch{logdata "couldnt get package provider list"}

    #install powershell-Get for installing other modules
    try{
        if(!((Get-PackageProvider -ListAvailable).Name -contains "PowershellGet")) {
            logdata "installing package provider powershellGet"
            try{Install-module -name PowershellGet -Force -Scope AllUsers -AllowClobber -ErrorAction stop -Confirm:$False }
            catch{logdata "couldnt install package provider powershellGet"}
        }else{logdata "powershellGet module already installed"}
    }catch{logdata "couldnt get package provider list"}

    #install PSrepository
    try{
        if(!((Get-PSRepository).name -contains "PSGallery")) {
            logdata "installing PSrepository"
            try{Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted}
            catch{logdata "couldnt set PS Repository"}
        }else{logdata "PSrepository already installed"}
    }catch{logdata "couldnt get repository list"}
}

$configurations = {

    #set execution policy
    try {$currentPolicy = Get-ExecutionPolicy -Scope LocalMachine}
    catch{logdata "couldnt get current execution Policy"}
    
    if ($currentPolicy -ne 'Bypass') {
        try {
            Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine -Force -ErrorAction Stop
            $currentPolicy = Get-ExecutionPolicy -Scope LocalMachine
            logdata "Execution policy successfully set to: $currentPolicy"
        }catch{logdata "Couldn't update execution policy"}
    }else{logdata "Execution policy already set to: $currentPolicy"}

    #set .net TLS security level
    try{
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value "1" -Type DWord
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value "1" -Type DWord
        logdata "Setting TLS security level"
    }
    catch{logdata "couldnt set TLS security level"}


    #set pcConfig permissions
    $rootIndex = $scriptPath.IndexOf($rootName)
    $rootPath = $ScriptPath.Substring(0,$rootIndex) + $rootName #+ "\"
    setFilePermissions $rootPath #set permissions of folder above the one that holds this script

    #disable lock PC
    try{
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DisableLockWorkstation -Value 1 -Force | Out-Null 
        logdata "disable lock PC"
    }
    catch{"unable to disable PC lock"}

    #disable screensaver password
    try{
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name Power -Value "default value" -Force | Out-Null
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power" -name PowerSettings -Value "default value" -Force | Out-Null 
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings" -Name 0e796bdb-100d-47d6-a2d5-f7d2daa51f51 -Value "default value" -Force | Out-Null 
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name DCSettingIndex -Value 0 -Force | Out-Null 
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name ACSettingIndex -Value 0 -Force | Out-Null 
        logdata "Disable Screensaver password"
    }
    catch{logdata "unable to disable screensaver password"}

    #disable Fast User Switching
    try{
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name HideFastUserSwitching -Value 1 -Force | Out-Null
        logdata "Disable Fast User Switching"
    }
    catch{logdata "unable to disable Fast User Switching"}

    #create desktop logoff shortcut
    try{
        $ShortcutPath = "C:\users\public\desktop\Logoff.lnk"
        $IconLocation = "C:\windows\System32\SHELL32.dll"
        $IconArrayIndex = 27
        $Shell = New-Object -ComObject ("WScript.Shell")
        $Shortcut = $Shell.CreateShortcut($ShortcutPath)
        $Shortcut.TargetPath = "C:\windows\System32\logoff.exe"
        $Shortcut.IconLocation = "$IconLocation, $IconArrayIndex"
        $Shortcut.Save()
        logdata "created desktop logoff shortcut"
    }
    catch{logdata "couldnt create desktop logoff shortcut"}

    #disable windows defender to allow scripts to run
    try{
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -Force | Out-Null
        logdata "windows defender has been disabled" 
    }
    catch{logdata "unable to disable windows defender"}

    # Set Firefox Maintenance Service registry setting to allow background updates without admin
    $regPath = "HKLM:\SOFTWARE\Mozilla\MaintenanceService"

    # Check if the key exists
    if (!(Test-Path $regPath)) {
        # Create the key if missing
        New-Item -Path "HKLM:\SOFTWARE\Mozilla" -Name "MaintenanceService" -Force
    }

    # Set AttemptAdmin to 1
    Set-ItemProperty -Path $regPath -Name "AttemptAdmin" -Value 1 -Type DWord

    # Confirm the setting
    $attemptAdmin = Get-ItemPropertyValue -Path $regPath -Name "AttemptAdmin"
    logdata "Mozilla Maintenance Service AttemptAdmin is now set to: $attemptAdmin"

    # Make sure MozillaMaintenance service is set to Automatic
    Set-Service -Name MozillaMaintenance -StartupType Automatic

    # Start the service if it's not running
    Start-Service -Name MozillaMaintenance -ErrorAction SilentlyContinue

    logdata "Mozilla Maintenance Service set to Automatic and started (if not running)."


    #set UAC to minimum to prevent popups when scripts run
    $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    # Read current values
    $currentEnableLUA = Get-ItemPropertyValue -Path $uacPath -Name "EnableLUA"
    $currentPromptBehavior = Get-ItemPropertyValue -Path $uacPath -Name "ConsentPromptBehaviorAdmin"
    $currentSecureDesktop = Get-ItemPropertyValue -Path $uacPath -Name "PromptOnSecureDesktop"
    try {
        Set-ItemProperty -Path $uacPath -Name "EnableLUA" -Value 1
        Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 0
        Set-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop" -Value 0

        logdata "`nUAC settings updated to minimum level." 
        logdata "A system reboot is required for changes to take full effect." 
    }
    catch {
        logdata "Error updating registry: $_" 
    }


    # Disable Attachment Manager Security to prevent popups when running .vbs files etc
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"
    New-Item -Path $regPath -Force | Out-Null

    # Set SaveZoneInformation to 1 (do not save zone info = no warning)
    Set-ItemProperty -Path $regPath -Name "SaveZoneInformation" -Value 1 -Type DWord

    logdata "Attachment Manager configured: Open File - Security Warning disabled."
}


###############################################
### Main Code ###
. $defineSettings #get settings file and set flags
. $isElevated #test to see if the script has already been elevated to admin
. $checkStatus #check if everything has been installed before

$elevateFlag = $true #manual override to ensure elevation for this script

. $runAsAdmin #elevate permissions if required and loop back to the top of the script
. $makeHKLMroot #create HKLM registry path if required
. $createLog #configure logging and create logfile
. $startLog #write start info to log
. $makeTask #create task scheduler task to run script regularly

###custom code ###
. $unblockFiles #unblock downloaded files so they can run
. $installModules
. $configurations
$madeTask = $true #required to override settings in $endscript to write to registry that would otherwise prevent the installer from progressing
#end code ###
. $endScript #write end info to log
###############################################

