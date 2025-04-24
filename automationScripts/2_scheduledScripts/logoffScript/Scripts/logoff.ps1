$debug = $false

$lastSessionFlag = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name lastSessionFlag) #Show popup to warn current user if they are the last user on the system today, 1=Yes, 0=No
$lastSessionWarning = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name lastSessionWarning) #How long in minutes before end of session will the popup appear to warn a user to shutdown the sytem since theres no other user booked today 
$VMFlag = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name VMFlag) #If value = 1 (True) then dont allow shutdown of PC

#Is the user an admin
$pcUser = $env:UserName
$isAdmin = net localgroup administrators | Where {$_ -eq $pcUser}

$CRLF = "&#x0a;"  #Used in the popup message to create a new line of text

####################################################
If($debug){
    $VMFlag = 0               #Is this a VM?
    $lastSessionFlag = 0      #Should script check for next user?
    $lastSessionWarning = 60  #how long script should look into future for next session
    $isAdmin = 0              #is logged in user an admin?
    $nextMins = 0             #minutes until next session
    $nextUser = "j.bloggs"    #next users login details
}
####################################################

#Load code for custom popup form
. "$PSScriptRoot\logoffForm.ps1"

#configure the custom popup form parameters
$logoffParams = @{
    Title = 'Logoff?'
    TitleFontSize = 20
    TitleBackground = 'Red'
    TitleTextForeground = 'White'
    ButtonType = 'None'
    Sound = 'Windows Exclamation'
    ContentFontSize = 18
}

#Custom button text
$logoffButton = "Logoff"
$restartButton = "Restart"
$shutdownButton = "Shutdown"
$cancelButton = "Cancel"

#Configure buttons for popup
$logoffButtons = @($logoffButton) 
If($VMFlag -eq 0) {$logoffButtons += @($restartButton, $shutdownButton)}
If(($VMFlag -eq 1) -and ($isAdmin)){$logoffButtons += $restartButton}
$logoffButtons += $cancelButton
$logoffButtons

If(($lastSessionFlag -eq 1) -and ($VMFlag -eq 0)){
    #is there a next user within $nextUserWarning, if not, is there a next user before midnight?
    If($lastSessionWarning -lt 0){$lastSessionWarning = ([datetime]::Today.AddDays(1) - [datetime]::Now).TotalMinutes}
    If(($nextMins -ge $lastSessionWarning) -or (($nextMins -eq 0) -and ($nextUser -eq ""))) {$logoffText = "Please Ensure All Equipment Including Lasers Is Turned Off$CRLF$CRLF"+"Then Make Your Selection Below$CRLF"}
    Else {$logoffText = "$nextUser Is Booked After You$CRLF$CRLF"+"Please Ensure The Equipment Is Left Running$CRLF$CRLF"+"Then Make Your Selection Below$CRLF"}
}Else {$logoffText = "Are You Sure You Wish To Logoff?$CRLF$CRLF"}

#Show popup window
logoffBox @logoffParams -Content $logoffText -CustomButton $logoffButtons -Timeout 59

#Do stuff if button clicked
If ($logoffOutput -eq "Logoff") {
    $logoffNow = "Yes"
    Get-Process | Where {$_.ProcessName -eq "ppmsCP"} | Stop-Process -Force
    #$session = ((quser /server:$server | ? { $_ -match $pcUser }) -split ' +')[1]
    #logoff  $session
    shutdown /l /f
} 
If ($logoffOutput -eq "Shutdown") {
    $logoffNow = "Yes"
    Clear-Host
    Stop-Computer
}
If ($logoffOutput -eq "Restart") {
    $logoffNow = "Yes"
    Clear-Host
    Restart-Computer
}
Else {$logoffNow = "No"}
$logoffNow
