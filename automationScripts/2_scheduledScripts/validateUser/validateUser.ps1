<#
    validateUser script

    Script to check if the currently logged in user is an admin or ppms registered user
    If not, a popup warning appears with a countdown timer to logoff the user
    An email will be sent with the users details to admin staff

    Required - validateUsers_Settings.ps1 - update included values for each instrument

    Admins can override the script using a pre-defined password by shift clicking on the "logoff now" button
        This wil also send an email to admins

    Users can also override the script using the current or next booking ID, 
        This will also send an email to admins

    If the PPMS server is unavailable the script will not logoff the user, but instead warn them of no internet access

    Usually run as the executable validateUser.exe, but can be run as this script within powershell 

    Installation requirements:
        Win7 will require .NET 4.5 or higher and then WPF5.1 to be installed first, these should be included in the installation folder, or download them from the links below: 
    	    https://www.microsoft.com/en-au/download/details.aspx?id=30653
    	    https://www.microsoft.com/en-us/download/details.aspx?id=54616
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

$userMessage = {
    #update popup window user message

    If($ppmsExists){
        $message = "This equipment is managed by the PPMS Management System"
        $message += "`r`n`r`nUnfortunately this user account is not registered in PPMS" 
        $message += "`r`n`r`nDo you have another user account you can try?"
        $message += "`r`n`r`nPlease contact IMB Microscopy staff for assistance`r`nMicroscopes@imb.uq.edu.au"
        $message += "`r`n`r`nYou will be logged off in $([math]::Round($logoffTime - $inValidUserStopwatch.Elapsed.TotalSeconds)) seconds"
        $inValidUserMessage.Text = $message 
        $inValidUserLogoffBtn.Content = " Click to Logoff Now "
    }Else{
        $message = "The PPMS Server is currently unreachable"
        $message += "`r`n`r`nUnfortunately this means that you may not have internet or RDM Collection access" 
        $message += "`r`n`r`nPlease save your data locally, and move it to your collection at another time"
        $message += "`r`n`r`nPlease contact IMB Microscopy staff for assistance`r`nMicroscopes@imb.uq.edu.au"
        $message += "`r`n`r`nThis window will close in $([math]::Round($logoffTime - $inValidUserStopwatch.Elapsed.TotalSeconds)) seconds"
        $inValidUserMessage.Text = $message
        $inValidUserLogoffBtn.Content = " Okay "
    }
}

$logoff = {
    #logoff user
    If($disableLogoff){log "logoff disabled in script"}
    Else{
        log "logoff user now"
        shutdown -l -f #logoff user after popup window closes
    }
}

$getID = {
    #get ppms booking info

    $currentBooking = Invoke-RestMethod -TimeoutSec 10 -uri $ppmsURL/pumapi/ -method post -body "action=getbooking&id=$ppmsID&code=$ppmscode" #get current booking details from PPMS server
    $nextBooking = Invoke-RestMethod -TimeoutSec 10 -uri $ppmsURL/pumapi/ -method post -body "action=nextbooking&id=$ppmsID&code=$ppmscode" #get next booking details from PPMS server
    #Format the PPMS booking information into something useable
    $currentBookingArray = $currentBooking -split "\r\n"
    $nextBookingArray = $nextBooking -split "\r\n"
    $nowUser = $currentBookingArray[0]
    $currentID = [string]$currentBookingArray[2]
    $nextID = [string]$nextBookingArray[2]
    $passArray = @($adminPassword)
    If(!([string]::IsNullOrEmpty($currentID))){$passArray += $currentID}
    If(!([string]::IsNullOrEmpty($nextID))){$passArray += $nextID}
    log "currentID = $currentID"
    log "nextID = $nextID"

    #test for special user types to ignore, ie: Trainings and Workshops etc
    $ignoreUserArray = $ignoreUserList -split "," #convert ignoreUserList to array
    if(![string]::IsNullOrEmpty($ignoreUserList) -and (($ignoreUserArray -contains $nowUser) -or ($ignoreUserArray -contains $user))){
        $ignoreUser = 1
        log "ignore user: $nowuser"
    }else{$ignoreUser = 0}
}

$makeMessage = {
        If(!$ppmsExists){$messageBody = "PPMS server connection issues at login"}
        ElseIf($global:userAbort){$messageBody = "An invalid User has bypassed the validateUser script with password = $global:myPassword"}
        ElseIf($global:adminAbort){$messageBody = "An invalid User has bypassed the validateUser script with the Administrator password"}
        Else{$messageBody = "An invalid User has been logged off by the validateUser script"}
        $messageBody = $messageBody + "`r`n" + "Username: $user"
        log $messageBody
}

$sendEmail = {
    #send email to facility staff

    If($emailFlag){
        log "send email"
        $secpasswd = ConvertTo-SecureString $emailPass -AsPlainText -Force #convert plain text email password to hashed password
        $credentials = New-Object System.Management.Automation.PSCredential ("$emailUser", $secpasswd) #generate a hashed credential for secure email server
        $emailSubject = "Attention - $PCname"
        $emailBody = $messageBody

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
        Catch{"oops, emails not working"}
    }
}

$sendSlack = {
    If($slackFlag){
        log "send slack message"
        $author = $PCname
        $body = ConvertTo-Json @{
            username = $author
            pretext = $Title
            text = $messageBody
            channel = $channel
            icon_emoji = $icon
            color = $color
        }

        try {
            Invoke-RestMethod -uri $uriSlack -Method Post -body $body -ContentType 'application/json' | Out-Null
        } catch {
            Write-Error (Get-Date) ": Update to Slack went wrong..."
        }
    }
}

$sendTeams = {
    If($TeamsFlag){
        log "send Teams message"
        #Teams message
        $script =  "Validate User script"
        $message = $messageBody.Replace("`r`n","<br/>")
        $text = $script + "<br/>" + $message

        try {
            $body = '{"title": ' + "'" + $PCname + "'" + ',"text": ' + "'" + $text + "'" + '}'
            Invoke-RestMethod -Method post -ContentType 'Application/Json' -Body $body -Uri $webHook | Out-Null
        } catch {
            Write-Error (Get-Date) ": Update to Teams went wrong..."
        }
    }
}

$popupWindow = {
    #display popup window

    #get current screen dimensions
    Add-Type -AssemblyName System.Windows.Forms
    $screenWidth = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width 
    $screenHeight = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height 

    #display popup window to notify user they dont have a valid PPMS account, and will be logged off in 30s
    Add-Type -AssemblyName PresentationFramework
   
    # Create a stopwatch and a timer object
    $inValidUserStopwatch = New-Object System.Diagnostics.Stopwatch #create stopwatch
    $inValidUserTimer= New-Object System.Windows.Forms.Timer #create Timer
    $inValidUserTimer.Interval = 1000
    $inValidUserStopwatch.Reset() 
    $inValidUserStopwatch.Start() 
    $inValidUserTimer.Enabled = $true 

    #generate popup window using visual studio XAML code
    [xml]$guiStyle = @"  
    <Window 
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    x:Name="Window" Title="invalidUser" SizeToContent="Manual" Width="$($screenWidth)" Height="$($screenHeight)" WindowStartupLocation="CenterScreen" WindowStyle="None" ResizeMode="NoResize" AllowsTransparency="True" Background="Transparent" Opacity="1" Topmost="True" ShowInTaskbar="False">
        <Border x:Name="MainBorder" Margin="10" CornerRadius="8" BorderThickness="0" BorderBrush="Black" Padding="0" >
            <Border.Effect>
                <DropShadowEffect x:Name="DSE" Color="Black" Direction="270" BlurRadius="20" ShadowDepth="3" Opacity="0.6" />
            </Border.Effect>
            <Border.Triggers>
                <EventTrigger RoutedEvent="Window.Loaded">
                    <BeginStoryboard>
                        <Storyboard>
                            <DoubleAnimation Storyboard.TargetName="DSE" Storyboard.TargetProperty="ShadowDepth" From="0" To="3" Duration="0:0:1" AutoReverse="False" />
                            <DoubleAnimation Storyboard.TargetName="DSE" Storyboard.TargetProperty="BlurRadius" From="0" To="20" Duration="0:0:1" AutoReverse="False" />
                        </Storyboard>
                    </BeginStoryboard>
                </EventTrigger>
            </Border.Triggers>
            <Grid>
                <Border Name="Mask" CornerRadius="8" Background="White" />
                <Grid x:Name="Grid" Background="White">
                <Grid.OpacityMask>
                    <VisualBrush Visual="{Binding ElementName=Mask}"/>
                </Grid.OpacityMask>
                    <StackPanel Name="StackPanel">
                        <Label Name="inValidUserTitle" Content="Attention" FontWeight="normal" Background="red" Foreground="White" Width="Auto" FontSize ="$($fontSize)" HorizontalContentAlignment="Center"/>
                        <TextBox Name="Message" HorizontalAlignment="Center" VerticalAlignment="Center" Height="auto" Margin="20,20,20,20" TextWrapping="Wrap"  HorizontalContentAlignment="Center" VerticalContentAlignment="Center" SelectionBrush="{x:Null}" BorderBrush="{x:Null}" Background="{x:Null}" IsReadOnly="True" IsUndoEnabled="False"/>
                        <Button Name="Logoff" Width="Auto" Height="Auto" Margin="20,20,20,20" HorizontalAlignment="Center" VerticalAlignment="Bottom" Background="LightGray"/>
                        <PasswordBox Name="Pass" HorizontalAlignment="Center" Margin="20,20,20,20" Background="Transparent" BorderBrush="Black" BorderThickness="1" Width="400"/>
                        <Button Name="Cancel" Content="Enter Password to Cancel" Width="Auto" Height="Auto" Margin="20,20,20,20" HorizontalAlignment="Center" VerticalAlignment="Bottom" Background="LightGray"/>

                    </StackPanel>
                </Grid>
            </Grid>
        </Border>
    </Window>
"@ #make sure this line doesnt have an indent or it will break the code

    #Create GUI
    $inValidUserXAML=(New-Object System.Xml.XmlNodeReader $guiStyle)
    $inValidUserWindow =[Windows.Markup.XamlReader]::Load($inValidUserXAML)
    $inValidUserMessage = $inValidUserWindow.FindName("Message")
    $inValidUserLogoffBtn = $inValidUserWindow.FindName("Logoff")
    $inValidUserCancelBtn = $inValidUserWindow.FindName("Cancel")

    $inValidUserPassword = $inValidUserWindow.FindName("Pass")
    $inValidUserWindow.FontSize = $fontSize
    $inValidUserMessage.FontWeight = "Bold"
    $inValidUserMessage.Foreground = "Black"
    
    & $userMessage #update user message
  
    #If user clicks the logoff button, close the window and logoff immediately
    $inValidUserLogoffBtn.Add_Click({
        <#
        if([System.Windows.Input.Keyboard]::IsKeyDown("LeftShift") -or [System.Windows.Input.Keyboard]::IsKeyDown("RightShift")) {
            $inValidUserPassword.IsEnabled="true" 
            $inValidUserPassword.ForceCursor="True"
            $inValidUserPassword.Focus()
            $inValidUserPassword.borderBrush="black"
            $inValidUserPassword.borderThickness="1"
            $inValidUserPassword.width = "400"
        }Else{ #>
            $global:logoffFlag = $true
            $global:sendEmailFlag = $true
            $global:userAbort = $false
            $global:adminAbort = $false
            log "user clicked logoff button"
            $inValidUserWindow.Close()
        #}
    })

    #check password
    $inValidUserCancelBtn.Add_Click({
        #if password is correct, send email and close window
        If($passArray -contains $inValidUserPassword.Password){
            log "password box contains a matching password"
            $global:myPassword = $inValidUserPassword.Password
            If($global:myPassword -eq $adminPassword){
                log "password matches admin password"
                $global:adminAbort = $true
            }Else{
                $global:userAbort = $true
                log "password matches session ID"
            }
            $global:logoffFlag = $false
            $global:sendEmailFlag = $true
            $inValidUserWindow.Close()
        }
    })

    #At each Timer interval
    $inValidUserTimer.Add_Tick({ 

        #if timer ends, logoff
        If($inValidUserStopwatch.Elapsed.TotalSeconds -ge $logoffTime){
            $global:sendEmailFlag = $true
            $global:userAbort = $false
            $global:adminAbort = $false
            $global:logoffFlag = $true
            log "timer triggered logoff"
            $inValidUserWindow.Close()
        }
        
        #update user message in popup window
        & $userMessage
    })

    [System.Media.SystemSounds]::Exclamation.Play()

    #show dialog window, wrapped in an async variable to handle errors
    $warningAsync = $inValidUserWindow.Dispatcher.InvokeAsync({
        $inValidUserWindow.ShowDialog() | Out-Null
    })
    $warningAsync.Wait() | Out-Null
}

$getLogonTime = {
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
    Log "logonDateTime = $logonDateTimeString"
}

$valScript = {
    #keep trying until config script has ran
    #reset variables
    $breakFlag = $false 
    $attempts = 0
    while($attempts -le $retries){
        log "attempt $($attempts + 1) at $([string]((Get-Date).DateTime)) "

        #determine when the ppmsConfig script last ran
        try{
            $configDateTime = [datetime]::Parse((Get-ItemPropertyValue -Path $ppmsRegPath -name configDateTime -ErrorAction Stop), $AUSCulture)
            $configDateTimeString = $configDateTime.ToString("dd/MM/yyy HH:mm:ss")
            log "configDateTime = $configDateTimeString"
        }
        catch{
            $configDateTime = $configDateTimeString = ""
            log "couldnt get configDateTime from registry"
        }


        #get current time
        $nowDateTime = [datetime]::Parse((Get-Date -Format ("dd/MM/yyyy HH:mm:ss")), $AUSCulture) #datestamp on PC
        $nowDateTimeString = $nowDateTime.ToString("dd/MM/yyyy HH:mm:ss")


        #prevent this script from running before config.ps1
        try{$configRan = $configDateTime.AddSeconds(0)}catch{$configRan = $nowDateTime}


        #get flag to use to only run script once
        try{$validateUser_ConfigFlag = Get-ItemPropertyValue -Path $ppmsRegPath -name validateUser_ConfigFlag -ErrorAction stop}catch{$validateUser_ConfigFlag = ""}


        #run main script if config script has run
        if(($configDateTime -gt $logonDateTime) -and ($validateUser_ConfigFlag -match "true")){
            log "config script has run, run main script"

            #get ppms values
            $PCname = (Get-ItemPropertyValue -Path $ppmsRegPath -name PCname) #Equipment name
            $ppmsURL = (Get-ItemPropertyValue -Path $ppmsRegPath -name ppmsURL) #PPMS URL
            $ppmsPF = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name ppmsPF) #PPMS Platform ID or PF number, Appears in the URL
            $ppmsID = (Get-ItemPropertyValue -Path $ppmsRegPath -name ppmsID) #PPMS equipment ID 
            $ppmsCode = (Get-ItemPropertyValue -Path $ppmsRegPath -name ppmsCode) #PPMS equipment code
            $pumapiKey = (Get-ItemPropertyValue -Path $ppmsRegPath -name pumapiKey) #PUMAPI key, must have user management turned on
            $apiKey = (Get-ItemPropertyValue -Path $ppmsRegPath -name apiKey) #API key, must have write mode turned on
            $ignoreUserList = (Get-ItemPropertyValue -Path $ppmsRegPath -name ignoreUserList) #Dont show alert window popups or auto-logoff if there's a booking from anyone in this list, this will still track logged in users, separate ppms usernames with commas - useful for running workshops on analysis VMs etc

            #Get user rights
            $user = $env:USERNAME #get logged in users username
            $adminFlag = (net localgroup administrators | Where {$_ -eq $user}) -ne $null #is user a local PC admin?

            if($debug){
                "debug = $debug"
                #adjust for debugging as required
                $adminFlag = $adminFlag_debug
                $user = $user_debug
            }
           
            #Main script
            If(!$adminFlag) { #if user isnt a local admin or a training session is in progress
                log "user isnt an admin, run validation"
                #keep trying to contact PPMS server for a couple of minutes
                $ppmsExists = $false
                $ppmsTries = 0
                While($ppmsTries -le 0){ 
                    #get user details from PPMS server
                    try{
                        $getUser = Invoke-RestMethod -TimeOutSec 10 -uri $ppmsURL/pumapi/ -method post -body "apikey=$pumapiKey&action=getuser&login=$user&withuserid=true&format=json" -ErrorAction stop
                        $ppmsExists = $true
                        break
                    }catch{
                        $ppmsExists = $false
                        Start-Sleep -Seconds 10
                    }
                    $ppmsTries++
                }
                #If PPMS is found, check if user is valid
                If($ppmsExists){ 
                    #If the logged in user isnt a registered PPMS user, logoff?
                    If($getUser.login -notmatch $user) { 
                        "getIDs"
                        . $getID #get booking IDs
                        if($ignoreUser -eq 0){
                        "show popup"
                            . $popupWindow #display popup window to user
                        }
                        If($global:sendEmailFlag){
                            "send email"
                            . $makeMessage #generate message
                            . $sendEmail #send email message
                            . $sendSlack #send slack message
                            . $sendTeams #send Teams message
                        } 
                        if($global:logoffFlag){
                            #& $logoff
                            $attempts = $retries 
                            #break
                        } #logoff user
                        Log "$user is not a valid PPMS user"
                    }Else{log "valid ppms user"}#valid user
                }Else{ #display popup window to user warning of lost internet
                    
                    #. $popupWindow
                    . $makeMessage
                    . $sendEmail
                    . $sendSlack
                    . $sendTeams #send Teams message
                    Log "$user had PPMS server connection issues at login"
                } 
            }else{log "user is an admin, no need to validate user"}
            $validateUser_ConfigFlag = "false"
            New-ItemProperty -Path $ppmsRegPath -name validateUser_ConfigFlag -Value $validateUser_ConfigFlag -Force | Out-Null #reset flag so that softwareTracker will run a configuration script
            $breakFlag = $true
        }else{ Log "config script hasnt run yet or validateUser_ConfigFlag = false" }
    

        $log = ""
        $attempts++
        if($breakFlag){break}
        else{ start-sleep -Seconds $waitTime}
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


### Custom Code ###
if(!$settingsTable.DisableAll){
    $goFlag = goNogo $settingsTable.validateUser #determine if the script should run
    logdata $goFlag.log
    if($goFlag.runFlag){
        #reset variables
        $global:logoffFlag = $global:sendEmailFlag = $ppmsExists = $false
        $global:myPassword = $message = $getUser = $log = ""
        $disableLogoff = $false
        $debug = $false                                                         #debug mode on/off

        if($debug){
            $adminFlag_debug = $false                                               #when in debug mode, manually select whether user is an admin or not
            $user_debug = "asasdf"                                                  #override user name
            $disableLogoff = $false                                                 #enable/disable logoff of user
        }

        . $getLogonTime
        . $valScript
        if($global:logoffFlag){& $logoff}
    }else{logdata "goFlag = false, script didnt run"}
}else{logdata "disableAll flag = true, didnt run script"}

### end code ###
. $endScript #write end info to log
###############################################


