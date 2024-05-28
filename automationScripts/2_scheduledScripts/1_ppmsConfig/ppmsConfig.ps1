#ppmsConfig script
#Script to get/set ppms details of the PC for use by other scripts 

#check system name against PPMS, if it fails, ask user to select from list, if that fails, fall back to local system name, no need for manual definition.
#save these values to LMregpath and set user permissions so they're readable by all users
#on each login of user, copy LMRegpath to ppmsRegPath
#to reset system details, login as admin and delete task scheduler task, then run this script again.


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

$getCoresList = {
    $facilities = ""
    if(testURL $ppmsURL){
        $body = "action=GetCoresList&outformat=json&apikey=$apikey&filter=active" #get list of cores, add filter=active-all to also list myPPMS core
        $facilities = Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/API2/ -Method 'POST' -Body $body
    }
}

$userSelectCore = {
    if($ranAsAdminFlag){
        if([string]::IsNullOrEmpty($PF)){
            . $getCoresList
            logdata "Ask the user to select a PPMS Core from list"
            Add-Type -AssemblyName System.Windows.Forms
            Add-Type -AssemblyName System.Drawing

            $form = New-Object System.Windows.Forms.Form
            $form.Text = 'Select a PPMS Core'
            $form.Size = New-Object System.Drawing.Size(350,300)
            $form.StartPosition = 'CenterScreen'

            $okButton = New-Object System.Windows.Forms.Button
            $okButton.Location = New-Object System.Drawing.Point(75,220)
            $okButton.Size = New-Object System.Drawing.Size(75,23)
            $okButton.Text = 'OK'
            $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $form.AcceptButton = $okButton
            $form.Controls.Add($okButton)

            $cancelButton = New-Object System.Windows.Forms.Button
            $cancelButton.Location = New-Object System.Drawing.Point(150,220)
            $cancelButton.Size = New-Object System.Drawing.Size(75,23)
            $cancelButton.Text = 'Cancel'
            $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
            $form.CancelButton = $cancelButton
            $form.Controls.Add($cancelButton)

            $label = New-Object System.Windows.Forms.Label
            $label.Location = New-Object System.Drawing.Point(10,20)
            $label.Size = New-Object System.Drawing.Size(280,20)
            $label.Text = 'Please select a PPMS Core Facility: '
            $form.Controls.Add($label)

            $listBox = New-Object System.Windows.Forms.ListBox
            $listBox.Location = New-Object System.Drawing.Point(10,40)
            $listBox.Size = New-Object System.Drawing.Size(260,20)
            $listBox.Height = 150

            [void] $listBox.Items.AddRange($($facilities.longName | sort))
            [System.Media.SystemSounds]::Asterisk.Play()

            $form.Controls.Add($listBox)
            $form.Topmost = $true
            $result = $form.ShowDialog()

            if ($result -eq [System.Windows.Forms.DialogResult]::OK)
            {
                $selectedCore = $listBox.SelectedItem
            }else{
                $selectedCore = ""
                logdata "user cancelled Core selection"
            }
            logdata "user selected Core = $selectedCore"

            if(![string]::IsNullOrEmpty($selectedCore)){
                $ppmsPF = ($facilities | Where-Object{$_.longName -eq $selectedCore}).id
            }else{$ppmsPF = $PF} #fallback to manually set PF in config file.
        }
        else{
            logdata "use default PF = $PF"
            $ppmsPF = $PF
        }
        logdata "ppmsPF = $ppmsPF"
    }
}

$userSelectType = {
    logdata "Ask the user to select a PPMS instrument from list"
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Select a PPMS Instrument'
    $form.Size = New-Object System.Drawing.Size(350,300)
    $form.StartPosition = 'CenterScreen'

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(75,220)
    $okButton.Size = New-Object System.Drawing.Size(75,23)
    $okButton.Text = 'OK'
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $okButton
    $form.Controls.Add($okButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(150,220)
    $cancelButton.Size = New-Object System.Drawing.Size(75,23)
    $cancelButton.Text = 'Cancel'
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $cancelButton
    $form.Controls.Add($cancelButton)

    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10,20)
    $label.Size = New-Object System.Drawing.Size(280,20)
    $label.Text = 'Please select an Instrument: '
    $form.Controls.Add($label)

    $listBox = New-Object System.Windows.Forms.ListBox
    $listBox.Location = New-Object System.Drawing.Point(10,40)
    $listBox.Size = New-Object System.Drawing.Size(260,20)
    $listBox.Height = 150

    [void] $listBox.Items.AddRange($($systems.system | sort))
    [System.Media.SystemSounds]::Asterisk.Play()

    $form.Controls.Add($listBox)
    $form.Topmost = $true
    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK)
    {
        $selectedName = $listBox.SelectedItem
    }else{
        $selectedName = ""
        logdata "user cancelled instrument selection"
    }
    logdata "user selected instrument = $selectedName"
}

$getPPMSInstrument = {
    $systems = $system = $systemName = $ppmsID = $ppmsCode = ""

    if($autoDetect = 1){ $autoPCname = $env:COMPUTERNAME -replace($ignore,"")} #get local PC name and remove any prefix as defined in settings

    #has the system been manually configured before (ie: PC name doesnt exist in PPMS?)
    try{$manualConfigFlag = Get-ItemPropertyValue -Path $LMRegPath -name manualConfig -ErrorAction SilentlyContinue}
    catch{$manualConfigFlag = 0}

    #if the system has been manually configured before
    if($manualConfigFlag -eq 1){
        #get ppms system details from registry
        try{
            logdata "get system details from $LMRegPath"
            $SystemName = (Get-ItemPropertyValue -Path $LMRegPath -name systemName -ErrorAction SilentlyContinue)
            $ppmsPF = (Get-ItemPropertyValue -Path $LMRegPath -name ppmsPF -ErrorAction SilentlyContinue)
            $ppmsID = (Get-ItemPropertyValue -Path $LMRegPath -name ppmsID -ErrorAction SilentlyContinue)
            $ppmsCode = (Get-ItemPropertyValue -Path $LMRegPath -name ppmsCode -ErrorAction SilentlyContinue)
        }
        catch{
            logdata "system detail fields not found in $LMRegPath"
            $SystemName = $ppmsID = $ppmsCode = $ppmsPF = ""
        }
    }
    else{
         #get ppms instrument details using autoPCname, if valid use them,
         Write-Host "getPPMSinstrument - ppmsPF = $ppmsPF"
        if(testURL $ppmsURL){
            try{
                logdata "retrieve system details from ppms"
                $body = "action=Report$systemReport&outformat=json&apikey=$apikey&coreid=$ppmsPF" 
                $systems = Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/API2/ -Method 'POST' -Body $body
                $systems = $systems | Where-Object Active -eq True
                $ppmsExists = $true

                #test using autodetected pc name
                logdata "compare PPMS list of instruments against $autoPCname"
                foreach($system in $systems){
                    if ($system.system -match  $(([string]$autoPCname).trim())){
                        $systemName = $system.system
                        $ppmsID = $system.id
                        $ppmsCode = $system.code
                    }
                }
            }catch{
                logdata "couldnt retrieve system details from ppms"
                $ppmsExists = $false
            }
        }else{
            logdata "ppms appears to be down"
            $ppmsExists = $false
        }

        #else check HKLM for saved details
        if([string]::IsNullOrEmpty($systemName)){
            logdata "no match for instrument in ppms against $autoPCname"
            #get ppms system details from registry
            try{
                logdata "get system details from $LMRegPath"
                try{$SystemName = (Get-ItemPropertyValue -Path $LMRegPath -name systemName -ErrorAction Stop)}
                catch{logdata "couldnt get systemName from $LMRegPath"}
                
                try{$ppmsPF = (Get-ItemPropertyValue -Path $LMRegPath -name ppmsPF -ErrorAction Stop)}
                catch{logdata "couldnt get ppmsPF from $LMRegPath"}

                try{$ppmsID = (Get-ItemPropertyValue -Path $LMRegPath -name ppmsID -ErrorAction Stop)}
                catch{logdata "couldnt get ppmsID from $LMRegPath"}
                
                try{$ppmsCode = (Get-ItemPropertyValue -Path $LMRegPath -name ppmsCode -ErrorAction Stop)}
                catch{logdata "couldnt get ppmsCode from $LMRegPath"}
            }
            catch{
                logdata "system detail fields not found in $LMRegPath"
                $SystemName = $ppmsID = $ppmsCode = ""
            }
        }

        #else ask user to select from list of PPMS instruments
        if([string]::IsNullOrEmpty($systemName)){
            logdata "No match found in PPMS for $autoPCname"
            .$userSelectType 
            $selectedInstrument = $systems | Where-Object{$_.System -eq $selectedName}
            if(![string]::IsNullOrEmpty($selectedInstrument.system)){
                $systemName = $selectedInstrument.system
                $ppmsID = $selectedInstrument.id
                $ppmsCode = $selectedInstrument.code
            }
        }

        if([string]::IsNullOrEmpty($ppmsCode)){
            $systemName = $env:computername
            $manualConfigFlag = 1
            logdata "ppmsCode is empty, revert to using local system name $env:computername"
        }
    }

    logdata "ppms system = $systemName"
    logdata "ppms PF = $ppmsPF"
    logdata "ppms ID = $ppmsID"
    logdata "ppms Code = $ppmsCode"
}

$getConfigDateTime = {
    #calculate time based on Australian datetime format
    $AUSCultureName = "en-AU" #get local datetime format
    $AUSCulture = [CultureInfo]::CreateSpecificCulture($AUSCultureName)

    #get current login time
    $configDateTime = [datetime]::Parse((Get-Date -Format ("dd/MM/yyyy HH:mm:ss")), $AUSCulture)
    $configDateTimeString = $configDateTime.ToString("dd/MM/yyy HH:mm:ss")
    logdata "configDateTime = $configDateTimeString"
}

$getPPMSUserDetails = {
    #get ppms user details
    $userDetails = [PSCustomObject] @{
        login = $userName
        lname = ""
        fname = ""
        group = ""
        phone = ""
        userEmail = ""
        userID = ""
        affiliation = ""
        active = ""
    }

    if($ppmsExists){
        Try{
            #get ppms values
            logdata "getting user details from ppms"
            $userDetails = Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "apikey=$pumapiKey&action=getuser&login=$userName&withuserid=true&format=json" #get user details from PPMS server
            $ppmsExists = $true
        }Catch{
            logdata "couldnt get user details from ppms"
            $ppmsExists = $false
        }
    }

    $fullName = $userDetails.lname + " " + $userDetails.fname
    logdata "fullname = $fullname"
}

$getGroupDetails = {
    #get the affiliation for the users group
    $groupDetails = [PSCustomObject] @{
        affiliation = ""
    }

    if($ppmsExists){
        Try{
            $unitLogin = $userDetails.unitlogin
            $groupDetails = Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "apikey=$pumapiKey&action=getgroup&unitlogin=$unitLogin&format=json" #get user details from PPMS server
            Start-Sleep -milliseconds 50
        }Catch{
            logdata "couldnt get group details"
        }
    }
}

$filterDetails = {
    $userLogin = $userDetails.login
    $userID = $userDetails.userid
    $userGroup = $userDetails.unitlogin
    $groupName = $groupDetails.unitname
    $groupAffiliation = $groupDetails.affiliation
    $groupDepartment = $groupDetails.department
    $groupInstitution = $groupDetails.institution
    $groupExternal = $groupDetails.ext


    logdata "user login = $userLogin"
    logdata "user ID = $userID"
    logdata "user group = $userGroup"
    logdata "group name = $groupName"
    logdata "group affiliation = $groupAffiliation"
    logdata "group Department = $groupDepartment"
    logdata "group Institution = $groupInstitution"
    logdata "group External = $groupExternal"
}

$ppmsDetails = { 
    #check for registry
    If((Test-Path $ppmsRegPath) -eq $false) {New-Item -Path $ppmsRegPath -name Default -Value "default value" -Force | Out-Null}
    
    New-ItemProperty -Path $ppmsRegPath -name userLogin -Value $userLogin -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name userFullname -Value $fullName -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name userGroup -Value $userGroup -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name userID -Value $userID -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name groupName -Value $groupName -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name groupAffiliation -Value $groupAffiliation -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name groupDepartment -Value $groupDepartment -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name groupInstitution -Value $groupInstitution -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name groupExternal -Value $groupExternal -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name systemName -Value $systemName -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name ppmsURL -Value $ppmsURL -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name ppmsPF -Value $ppmsPF -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name ppmsID -Value $([string]$ppmsID) -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name ppmsCode -Value $([string]$ppmsCode) -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name PCname -Value $systemName -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name systemName -Value $systemName -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name pumapiKey -Value $pumapiKey -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name apiKey -Value $apiKey -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name ppmsTimeout -Value $ppmsTimeout -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name ConfigDateTime -Value $configDateTimeString -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name logToFile -Value $logToFile -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name logToConsole -Value $logToConsole -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name unbookedLoginReport -Value $unbookedLoginReport -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name projectsForUserReport -Value $projectsForUserReport -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name systemReport -Value $systemReport -Force | Out-Null

    #local machine reg path
    If((Test-Path $LMRegPath) -eq $false) {New-Item -Path $LMRegPath -name Default -Value "default value" -Force | Out-Null}
    New-ItemProperty -Path $LMRegPath -name systemName -Value $systemName -Force | Out-Null
    New-ItemProperty -Path $LMRegPath -name ppmsPF -Value $([string]$ppmsPF) -Force | Out-Null
    New-ItemProperty -Path $LMRegPath -name ppmsID -Value $([string]$ppmsID) -Force | Out-Null
    New-ItemProperty -Path $LMRegPath -name ppmsCode -Value $([string]$ppmsCode) -Force | Out-Null
    if($manualConfigFlag -eq 1){New-ItemProperty -Path $LMRegPath -name manualConfig -Value 1 -Force | Out-Null}


    #reset counters
    #if flag is empty or doesnt exist, then this script hasnt run before
    #if flag is true, then this script has run, so it's a new session, subsequent scripts including their configuration sections, can run
    #if flag is false, then subsequent scripts have run (ie this script has also run) this session and can continue to run, but configuration sections shouldnt run

    New-ItemProperty -Path $ppmsRegPath -name softwareTracker_ConfigFlag -Value "true" -Force | Out-Null 
    New-ItemProperty -Path $ppmsRegPath -name autoDeleteFiles_ConfigFlag -Value "true" -Force | Out-Null 
    New-ItemProperty -Path $ppmsRegPath -name validateUser_ConfigFlag -Value "true" -Force | Out-Null 

    #get network details
    Try{($OSversion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName -ErrorAction Stop).ProductName}
    Catch{$OSversion = ""}
    $OSversion

    $networkDetails = $ipAddress = $macAddress = ""
    if($OSversion -match "Windows 7"){
        $activeNetwork = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPenabled=true'
        $ipAddress = $activeNetwork.IPAddress[0]
        $macAddress = $activeNetwork.IPAddress[1]
    }else{
        $activeNetwork = (Get-NetIPConfiguration |
            Where-Object {
                $_.IPv4DefaultGateway -ne $null -and 
                $_.NetAdapter.status -ne 'Disconnected'
            }
        )
        $IpAddress = $activeNetwork.IPv4Address.IPAddress
        $macAddress = $activeNetwork.NetAdapter.MacAddress
    }
    New-ItemProperty -Path $LMRegPath -name ipAddress -Value $IpAddress -Force | Out-Null
    New-ItemProperty -Path $LMRegPath -name macAddress -Value $macAddress -Force | Out-Null
}

$logoffDetails = {

    #logoff script settings
    ######################################################
    #Delete old Registry items and create new ones
    #Remove-Item -Path "$ppmsRegPath" -Force -Recurse
    #Start-Sleep -Milliseconds 200
    #New-Item -Path $ppmsRegPath -name Default -Value "default value" -Force
    #Is ppms or a relay installed on the system?
    New-ItemProperty -Path $ppmsRegPath -name ppmsFlag -Value $ppmsFlag -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name relayFlag -Value $relayFlag -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name autoRestartFlag -Value $autoRestart -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name restartTime -Value $restartTime -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name relayWarning -Value $relayWarning -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name popupDuration -Value $popupDuration -Force | Out-Null
    #Logoff popup flags
    New-ItemProperty -Path $ppmsRegPath -name lastSessionFlag -Value $lastSessionFlag -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name lastSessionWarning -Value $lastSessionWarning -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name VMFlag -Value $VMFlag -Force | Out-Null
    #Timer values to adjust by admins, to alert a user how much time they have remaining
    New-ItemProperty -Path $ppmsRegPath -name Alert -Value $Alert -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name AlertLong -Value $AlertLong -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name Alert8 -Value $Alert8 -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name Alert3 -Value $Alert3 -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name Alert1 -Value $Alert1 -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name Timer -Value $Timer -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name maxGap -Value $maxGap -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name maxExtension -Value $maxExtension -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name extendComment -Value $extendComment -Force | Out-Null
    #Create screen resolution key to place control panel GUI in the correct position
    Start-Sleep -Milliseconds 200
    New-ItemProperty -Path $ppmsRegPath -name screenWidth -Value $screenWidth -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name screenHeight -Value $screenHeight -Force | Out-Null 
    #Flags for toggling modes (1=True/0=False)
    New-ItemProperty -Path $ppmsRegPath -name ignoreAdminFlag -Value $ignoreAdminFlag -Force | Out-Null 
    New-ItemProperty -Path $ppmsRegPath -name extendBookingFlag -Value $extendBookingFlag -Force | Out-Null 
    New-ItemProperty -Path $ppmsRegPath -name logoffUserFlag -Value $logoffUserFlag -Force | Out-Null 
    New-ItemProperty -Path $ppmsRegPath -name sameGroupFlag -Value $sameGroupFlag -Force | Out-Null 
    New-ItemProperty -Path $ppmsRegPath -name sameProjectFlag -Value $sameProjectFlag -Force | Out-Null 
    New-ItemProperty -Path $ppmsRegPath -name emailAdminFlag -Value $emailAdminFlag -Force | Out-Null 
    New-ItemProperty -Path $ppmsRegPath -name pesterGoodFlag -Value $pesterGoodFlag -Force | Out-Null 
    New-ItemProperty -Path $ppmsRegPath -name pesterBadFlag -Value $pesterBadFlag -Force | Out-Null 
    New-ItemProperty -Path $ppmsRegPath -name ignoreUserList -Value $ignoreUserList -Force | Out-Null
    #email particulars
    New-ItemProperty -Path $ppmsRegPath -name emailFrom -Value $emailFrom -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name secureEmailFlag -Value $secureEmailFlag -Force | Out-Null 
    New-ItemProperty -Path $ppmsRegPath -name emailUser -Value $emailUser -Force | Out-Null                                                 
    New-ItemProperty -Path $ppmsRegPath -name emailPass -Value $emailPass -Force | Out-Null 
    New-ItemProperty -Path $ppmsRegPath -name smtpClient -Value $smtpClient -Force | Out-Null 
    New-ItemProperty -Path $ppmsRegPath -name emailTimer -Value $emailTimer -Force | Out-Null 
    New-ItemProperty -Path $ppmsRegPath -name adminTimer -Value $adminTimer -Force | Out-Null 
    #Refresh Interval for popup
    New-ItemProperty -Path $ppmsRegPath -name popUpTimer -Value 59 -Force | Out-Null 
    #webBrowser
    New-ItemProperty -Path $ppmsRegPath -name browser -Value $browser -Force | Out-Null
    #Questionaire
    New-ItemProperty -Path $ppmsRegPath -name QuestionFlag -Value $QuestionFlag -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name QuestionRandom -Value $QuestionRandom -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name QuestionOccurence -Value $QuestionOccurence -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name QuestionDrive -Value $QuestionDrive -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name QuestionPath -Value $QuestionPath -Force | Out-Null
    #Acquisition Software Error Log Path
    New-ItemProperty -Path $ppmsRegPath -name errorLogFlag -Value $errorLogFlag -Force | Out-Null                                                   
    New-ItemProperty -Path $ppmsRegPath -name errorLogPath -Value $errorLogPath -Force | Out-Null 
    New-ItemProperty -Path $ppmsRegPath -name newErrorLogPath -Value $newErrorLogPath -Force | Out-Null  
    New-ItemProperty -Path $ppmsRegPath -name screenshotPath -Value $screenshotPath -Force | Out-Null                            
    #set refresh rate for control panel in milliseconds
    New-ItemProperty -Path $ppmsRegPath -name cpRefresh -Value $cpRefresh -Force | Out-Null
    #Stop Flashing Icon in Taskbar
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -name ForegroundFlashCount -Value 1 -Force | Out-Null 
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -name ForegroundLockTimeout -Value 0 -Force | Out-Null  
    Start-Sleep -Milliseconds 200
    #set refresh rate for control panel in milliseconds
    New-ItemProperty -Path $ppmsRegPath -name cpRefresh -Value $cpRefresh -Force | Out-Null 


    #Flags to Reset
    New-ItemProperty -Path $ppmsRegPath -name Counter -Value 0 -Force | Out-Null
    New-ItemProperty -Path $ppmsRegPath -name adminCounter -Value 0 -Force | Out-Null 
    New-ItemProperty -Path $ppmsRegPath -name okayGoodFlag -Value 0 -Force | Out-Null 
    New-ItemProperty -Path $ppmsRegPath -name okayBadFlag -Value 0 -Force | Out-Null 
    New-ItemProperty -Path $ppmsRegPath -name ppmsBugCounter -Value 0 -Force | Out-Null 
    New-ItemProperty -Path $ppmsRegPath -name Iteration -Value 0 -Force | Out-Null 
    New-ItemProperty -Path $ppmsRegPath -name firstRunFlag -Value 1 -Force | Out-Null 
    New-ItemProperty -Path $ppmsRegPath -name userEmailFlag -Value 0 -Force | Out-Null 

    #Create QuestionCount key which is used to track number of times a user has logged on but not been asked a question 
    $ppmsRegPathCount = $ppmsRegPath + "Count"
    If((Test-Path $ppmsRegPathCount) -eq $false) {New-Item -Path $ppmsRegPathCount -name Default -Value "default value" -Force | Out-Null}
    try {
        Get-ItemProperty -Path $ppmsRegPathCount -name QuestionCount -ErrorAction Stop | Out-Null
        #return $true
    }catch {
        New-ItemProperty -Path $ppmsRegPathCount -name QuestionCount -value 1 -Force | Out-Null
        #return $false
    }
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


### Custom code ###
#check autodelete web flag, since autodelete script runs as system and has no internet access.
. $userSelectCore
. $getPPMSInstrument
. $getConfigDateTime
. $getPPMSUserDetails
. $getGroupDetails
. $filterDetails
. $ppmsDetails
. $logoffDetails

. $getSettingsFromURL #get global script settings from web
if(!$settingsTable.DisableAll){
    $goFlag = goNogo $settingsTable.autoDelete #determine if the script should run
    New-ItemProperty -Path $LM_rootPath -name runAutoDeleteFlag -Value $($goFlag.runflag) -Force | Out-Null 
}else{
    New-ItemProperty -Path $LM_rootPath -name runAutoDeleteFlag -Value "false" -Force | Out-Null 
}


### End code ###
. $endScript #write end info to log
###############################################


