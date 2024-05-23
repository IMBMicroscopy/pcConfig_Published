### Wallpaper script
#script to install desktop wallpaper on local PC


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



### custom code ###
$myWallpaper = {
    #Check for existing wallpaper path in registry, else find image in script folder, otherwise check sub-folder for image or prompt user on first run
    try{$wallpaper= (Get-ItemPropertyValue -Path $wallpaperRegPath -name WallpaperPath -ErrorAction stop) }
    catch{$wallpaper= ""}

    if(![string]::IsNullOrEmpty($wallpaper)){
        logdata "check if wallpaper image exists at $wallpaper"
        if(Test-Path -Path $wallpaper -PathType Leaf){ #check if wallpaper jpg exists, 
            logdata "image exists in filesystem at $wallpaper"
            $wallpaperName = Split-Path $wallpaper -Leaf #get wallpaper filename
            logdata "scriptPath = $scriptPath"
            logdata "wallpaperName = $wallpaperName"
            if([string]::IsNullOrEmpty((Get-ChildItem -Path $scriptPath -Filter $wallpaperName -File).Name)){
                logdata "image isnt in scriptPath"
                try{
                    Copy-Item -Path $wallpaper -Destination $scriptPath -ErrorAction Stop 
                    start-sleep -Seconds 2
                    logdata "copied wallpaper from $wallpaper"               
                }catch{logdata  "no image copied"}
            }
            else{logdata "image is already in scriptPath"}
        }else{   
            logdata "wallpaper exists in registry, but isnt in filesystem"
            $wallpaper = ""
        }
    }
}

$Style = {
    #get wallpaper style
    if(!$forceStyle){
        try{
            $wallpaperStyle = (Get-ItemPropertyValue -Path $wallpaperRegPath -name wallpaperStyle -ErrorAction stop)
            logdata "get registry wallpaper style = $wallpaperStyle"
        }catch{$wallpaperStyle = ""}
    }
}

$StyleName = {
    if(!$forceStyle){
        try{
            $wallpaperStyleName = (Get-ItemPropertyValue -Path $wallpaperRegPath -name wallpaperStyleName -ErrorAction stop) 
            logdata "get registry wallpaper style name = $wallpaperStyleName"
        }catch{$wallpaperStyleName = ""}
    }
}

Function setWallPaper($image) {
    try{
        New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WallpaperStyle -PropertyType String -Value $wallpaperStyle -Force | Out-Null #value = 2 Stretch, 6 = Fit, 10 = Fill
        New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name TileWallpaper -PropertyType String -Value 0 -Force | Out-Null
    }catch{logdata "couldnt make registry entries for wallpaperStyle and TileWallpaper"}

    Add-Type -TypeDefinition @" 
    using System; 
    using System.Runtime.InteropServices;
  
    public class Params
    { 
        [DllImport("User32.dll",CharSet=CharSet.Unicode)] 
        public static extern int SystemParametersInfo (Int32 uAction, 
                                                       Int32 uParam, 
                                                       String lpvParam, 
                                                       Int32 fuWinIni);
    }
"@ 
  
    #$SPI_SETDESKWALLPAPER = 0x0014
    $SPI_SETDESKWALLPAPER = 20
    $UpdateIniFile = 0x01
    $SendChangeEvent = 0x02
  
    $fWinIni = $UpdateIniFile -bor $SendChangeEvent
  
    $ret = [Params]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $Image, $fWinIni)
}

$getWallpaper = {
    #find wallpaper image that matches pc name, otherwise ask user to select a wallpaper image 

    $imageList = Get-ChildItem -Path $ScriptPath -Filter *.jp* -Recurse #find all jpgs in script folder and subfolders
    try{$pcName = (Get-ItemPropertyValue -Path $ppmsRegPath -name pcName -ErrorAction stop) }
    catch{
        $pcName = $env:computername
        logdata "couldnt get pcName from registry, revert to local pc name = $pcName"
    }

    #search for a wallpaper image that matches the settings defined name
    if(![string]::IsNullOrEmpty($wallpaperName)){
        logdata "test against settings defined wallpaper name"
        foreach($image in $imageList){
            $imageName = ($image.Name) -replace(".jpg|.jpeg","")
            if($wallpaperName -eq $imageName){
                $imagePath = $image.FullName
                logdata "found perfect match for settings defined wallpaper image = $imagePath"
                break
            }
            elseif($wallpaperName -match $imageName){
                $imagePath = $image.FullName
                logdata "Settings defined $wallpaperName contains a partial match for image file $imagePath"
                break
            }
            elseif($imageName -match $wallpaperName){
                $imagePath = $image.FullName
                logdata "$imagePath contains a partial match for settings defined $wallpaperName"
                break
            }
            else{
                $imagePath = ""
            }
        }
    }

    if([string]::IsNullOrEmpty($imagePath)){
        logdata "search for a wallpaper image that matches the computer name"
        foreach($image in $imageList){
            $imageName = ($image.Name) -replace(".jpg|.jpeg","")
            if($pcName -eq $imageName){
                $imagePath = $image.FullName
                logdata "found perfect match for $pcName wallpaper image = $imagePath"
                break
            }
            elseif($pcName -match $imageName){
                $imagePath = $image.FullName
                logdata "found partial match for $pcName wallpaper image = $imagePath"
                break
            }
            else{
                $imagePath = ""
            }
        }
    }

    #ask user for wallpaper image if it cant be found automatically
    if([string]::IsNullOrEmpty($imagePath)){
        logdata "ask user for wallpaper image"
        $wallpaperPath = (Get-ChildItem -Path $scriptPath -Recurse -Filter "*wallpaper*" -Directory).FullName
        Add-Type -AssemblyName System.Windows.Forms
        $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ 
            InitialDirectory = $wallpaperPath 
        }
        $fileBrowser.Title = "Select Wallpaper (.jpg or .jpeg)"
        $null = $FileBrowser.ShowDialog()
        $imagePath = $FileBrowser.FileName
        $fileBrowser.Dispose()

    }

    #delete any jpgs in the script folder and copy in the new wallpaper image.
    $scriptPathImages = Get-ChildItem -Path $ScriptPath -Filter *.jp*
    foreach($image in $scriptPathImages){
        try{Get-ChildItem -Path $scriptPath -Filter *.jp* -File | Remove-Item -Force -ErrorAction SilentlyContinue}catch{logdata "couldnt remove old image"}
    }
    start-sleep -Seconds 2
    try{Copy-Item -Path $imagePath -Destination $scriptPath -ErrorAction SilentlyContinue }catch{logdata  "no image copied"}
    start-sleep -Seconds 2
    $imagePath = (Get-ChildItem -Path $scriptPath -Filter *.jp*).FullName
    logdata "copied wallpaper imagePath = $imagePath"
    
}

$userSelectType = {
    if(!$forceStyle){
        #ask user to select how to fit wallpaper to screen

        logdata "create wallpaper style question GUI"
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing

        $form = New-Object System.Windows.Forms.Form
        $form.Text = 'Select a WallPaper Fill Type'
        $form.Size = New-Object System.Drawing.Size(300,200)
        $form.StartPosition = 'CenterScreen'

        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Location = New-Object System.Drawing.Point(75,120)
        $okButton.Size = New-Object System.Drawing.Size(75,23)
        $okButton.Text = 'OK'
        $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.AcceptButton = $okButton
        $form.Controls.Add($okButton)

        $cancelButton = New-Object System.Windows.Forms.Button
        $cancelButton.Location = New-Object System.Drawing.Point(150,120)
        $cancelButton.Size = New-Object System.Drawing.Size(75,23)
        $cancelButton.Text = 'Cancel'
        $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.CancelButton = $cancelButton
        $form.Controls.Add($cancelButton)

        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(10,20)
        $label.Size = New-Object System.Drawing.Size(280,20)
        $label.Text = 'Please select a wallpaper style:'
        $form.Controls.Add($label)

        $listBox = New-Object System.Windows.Forms.ListBox
        $listBox.Location = New-Object System.Drawing.Point(10,40)
        $listBox.Size = New-Object System.Drawing.Size(260,20)
        $listBox.Height = 80

        [void] $listBox.Items.Add('Fit')
        [void] $listBox.Items.Add('Fill')
        [void] $listBox.Items.Add('Stretch')
        [void] $listBox.Items.Add('Center')
        [void] $listBox.Items.Add('Span')
        [void] $listBox.Items.Add('No Wallpaper')
        $listBox.SetSelected(1,1)

        [System.Media.SystemSounds]::Asterisk.Play()

        $form.Controls.Add($listBox)
        $form.Topmost = $true
        $result = $form.ShowDialog()

        if ($result -eq [System.Windows.Forms.DialogResult]::OK)
        {
            $wallpaperStyleName = $listBox.SelectedItem
            switch($wallpaperStyleName) {
                "Fit" {$wallpaperStyle = "6"}
                "Fill" {$wallpaperStyle = "10"}
                "Stretch" {$wallpaperStyle = "2"}
                "Center" {$wallpaperStyle = "0"}
                "Span" {$wallpaperStyle = "22"}
                "No Wallpaper" {$wallpaperStyle = "none"}
            }
        }else{
            $wallpaperStyle = "none"
            logdata "user cancelled wallpaper selection"
        }
        logdata "user selected wallpaperStyle = $wallpaperStyle"
    }
    else{
        logdata "forceStyle is true"
        if(![string]::IsNullOrEmpty($wallpaperStyleName)){
            $useWallpaper = "true"
            $goodWallpaper = $true
        }else{
            $useWallpaper = "false"
            $goodWallpaper = $true
        }
    }
}

$confirmType = {
    if(!$forceStyle){
        #ask user to confirm or retry wallpaper style
        logdata "confirm wallpaper style"
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing

        $form = New-Object System.Windows.Forms.Form
        $form.Text = 'Confirm the WallPaper Fill Type'
        $form.Size = New-Object System.Drawing.Size(325,200)
        $form.StartPosition = 'CenterScreen'

        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Location = New-Object System.Drawing.Point(25,120)
        $okButton.Size = New-Object System.Drawing.Size(75,23)
        $okButton.Text = 'Confirm'
        $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.AcceptButton = $okButton
        $form.Controls.Add($okButton)

        $retryButton = New-Object System.Windows.Forms.Button
        $retryButton.Location = New-Object System.Drawing.Point(125,120)
        $retryButton.Size = New-Object System.Drawing.Size(75,23)
        $retryButton.Text = 'Retry'
        $retryButton.DialogResult = [System.Windows.Forms.DialogResult]::Retry
        $form.AcceptButton = $retryButton
        $form.Controls.Add($retryButton)

        $cancelWallpaper = $false
        $cancelButton = New-Object System.Windows.Forms.Button
        $cancelButton.Location = New-Object System.Drawing.Point(225,120)
        $cancelButton.Size = New-Object System.Drawing.Size(75,23)
        $cancelButton.Text = 'Cancel'
        $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.CancelButton = $cancelButton
        $form.Controls.Add($cancelButton)

        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(10,20)
        $label.Size = New-Object System.Drawing.Size(305,50)
        $label.Text = 'Confirm or Try Another wallpaper style, Cancel to use a blank wallpaper'
        $form.Controls.Add($label)

        [System.Media.SystemSounds]::Asterisk.Play()

        $form.Topmost = $true
        $result = $form.ShowDialog()

        if ($result -eq [System.Windows.Forms.DialogResult]::OK){
            $goodWallpaper = $true
            logdata "happy with wallpaper style"
            $useWallpaper = "true"
        }
        if ($result -eq [System.Windows.Forms.DialogResult]::Retry){
            $goodWallpaper = $false
            $useWallpaper = "true"
            logdata "try another wallpaper style"
        }
        if ($result -eq [System.Windows.Forms.DialogResult]::Cancel){
            $goodWallpaper = $true
            $wallpaperStyle = "none"
            $useWallpaper = "false"
            logdata "Cancel wallpaper style"
        }
    }
}

$applyWallpaper = {
    #if no wallpaper is configured, then configure one
    If([string]::IsNullOrEmpty($wallpaper) -or [string]::IsNullOrEmpty($wallpaperStyle)){
        $goodWallpaper = $false
            logdata "run getwallpaper"
            . $getWallpaper #get wallpaper image
            if(![string]::IsNullOrEmpty($imagePath)){
                logdata "imagepath is $imagePath"
                while(!$goodWallpaper){
                    . $userSelectType #ask user to select how to fit the wallpaper to the screen
                    if(![string]::IsNullOrEmpty($imagePath) -and ($wallpaperStyle -ne "none")){
                        $wallpaper = (Get-ChildItem -Path $scriptPath -Filter *.jp*).FullName
                        logdata "set wallpaper path = $wallpaper"
                        setWallpaper $wallpaper
                        . $confirmType #check if user is happy with wallpaper fill type
                    }if($wallpaperStyle -eq "none"){
                        logdata "dont use a wallpaper"
                        setWallpaper
                        $useWallpaper = "false"
                        $goodWallpaper = $true
                    }
                }
            }
            else {
                logdata "couldnt find a wallpaper, imagePath is empty, dont use wallpaper"
                setWallpaper
                $useWallpaper = "false"
            }
    }else{
        $wallpaper= (Get-ChildItem -Path $scriptPath -Filter *.jp*).FullName
        setWallpaper $wallpaper
        logdata "wallpaper was already configured, use wallpaper $wallpaper"
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
. $getSettingsFromURL #get global script settings from web


###Custom code ###
if(!$settingsTable.DisableAll){
    $goFlag = goNogo $settingsTable.wallpaper #determine if the script should run
    logdata $goFlag.log
    if($goFlag.runFlag){
        try{$useWallpaper = (Get-ItemPropertyValue -Path $wallpaperRegPath -name useWallpaper -ErrorAction stop)}
        catch{$useWallpaper = ""}
        logdata "registry - useWallpaper = $useWallpaper"

        if($useWallpaper -ne "false"){
            . $myWallpaper #get wallpaper image
            . $style
            . $styleName
            makeKey -regPath $wallpaperRegPath
            . $applyWallpaper #if required find and set wallpaper

            logdata "use Wallpaper = $useWallpaper"
            logdata "wallpaper style = $wallpaperStyle"
            logdata "wallpaper style name = $wallpaperStyleName"
            logdata "wallpaper path = $wallpaper"

            #write wallpaper settings to registry after installation by admin, so users arent prompted when they login
            if($ranAsAdminFlag){
                try{
                    logdata "write to registry"
                    New-ItemProperty -Path $wallpaperRegPath -Name useWallpaper -PropertyType String -Value $useWallpaper -Force -ErrorAction Stop  | Out-Null #value = true or false
                    New-ItemProperty -Path $wallpaperRegPath -Name WallpaperStyle -PropertyType String -Value $wallpaperStyle -Force -ErrorAction Stop | Out-Null #value = 2 Stretch, 6 = Fit, 10 = Fill
                    New-ItemProperty -Path $wallpaperRegPath -Name WallpaperStyleName -PropertyType String -Value $wallpaperStyleName -Force -ErrorAction Stop | Out-Null #value = filepath
                    New-ItemProperty -Path $wallpaperRegPath -Name WallpaperPath -PropertyType String -Value $wallpaper -Force -ErrorAction Stop | Out-Null #value = filepath
                }catch{logdata "script isnt elevated to write to registry, regular user"}
            }
        }else{logdata "registry flag $wallpaperRegPath\useWallpaper is set to not use a wallpaper, delete this flag to reinstall"}
    }else{logdata "goFlag = false, didnt run script"}
}else{logdata "disableAll flag = true, didnt run script"}

###End code ###
. $endScript #write end info to log
###############################################
