[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 #set TLS1.2 for communications with ppms server

#Get PPMS Booking Information
Try{
    logdata "userEmails - attempting to contact ppms server"
    $currentBooking = Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "action=getbooking&id=$ppmsID&code=$ppmsCode" #get current booking details from PPMS server
} Catch {
    $currentBooking = @()
    logdata "askQuestion - couldnt contact ppms server"
}

$CRLF = "&#x0a;"  #Used in the popup message to create a new line of text

$currentBookingArray = $currentBooking -split "\r\n"
$sessionID = $currentBookingArray[2]
If(($sessionID -ne "") -and ($sessionID -ne $null)){
    logdata "Ask user if they want to receive email reminders"
    . "$PSScriptRoot\CustomForm.ps1"
    $Params = @{
                Title = "Email Preferences"
                TitleFontSize = 20
                TitleBackground = 'Red'
                TitleTextForeground = 'White'
                ButtonType = 'Yes-No'
                Sound = 'Windows Exclamation'
                ContentFontSize = 18
    }
    $out = New-WPFMessageBox @Params -Content " Do You Wish To Receive Reminder Emails? $CRLF $CRLF Emails are sent with $AlertLong, $alert8, $alert3,$alert1 mins remaining" -Timeout 30 
    [string]$note = Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "apikey=$pumapiKey&action=getsessionnote&resid=$sessionID" #set session note for booking
    If(($note -match "\w") -eq $true -and $($note[$note.Length+1] -ne ",")) {$comma = ","}Else{$comma = ""}
    $time = (Get-Date).ToString("HH:mm")
    If($WPFMessageBoxOutput -eq "Yes") {
        $userEmailFlag = 1
        $note = $note + "$comma$time=Yes-Emails"    
    }  
    Else {
        $userEmailFlag = 0
        $note = $note + "$comma$time=No-Emails"
    }
    $firstRunFlag = 0
    New-ItemProperty -Path $ppmsRegPath -name userEmailFlag -Value $userEmailFlag -Force > $null
    New-ItemProperty -Path $ppmsRegPath -name firstRunFlag -Value $firstRunFlag -Force > $null
    Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "apikey=$pumapiKey&action=setsessionnote&resid=$sessionID&note=$note" #set session note for booking
    logdata "userEmail - set email flag = $userEmailFlag"
} Else {"userEmail - No Current Session, Dont set email flag"}