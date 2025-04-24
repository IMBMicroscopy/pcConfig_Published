
$scriptStart = (Get-Date)
$scriptStart

try { Add-Type -AssemblyName PresentationFramework,System.Windows.Forms} 
catch { throw "Failed to load Windows Presentation Framework assemblies." }

#Calculate Window Position
$width = 250
$height = 50
$screen = [Windows.Forms.Screen]::PrimaryScreen.WorkingArea
$Left = [string]($screen.Width - $width - 100)
$Top = [string]($screen.Height - $height - 100)

#get the logged in users details and determine if they have an admin account
Function wait {
    Start-Sleep -Milliseconds 50  #delay for reading/writing to registry etc
}

$cpMessage = ""
$hideWindow = $sameGroup = 0
$pcUser = $env:UserName
$ppmsPF = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name PF) #PPMS Platform ID or PF number, Appears in the URL
$PCname = (Get-ItemPropertyValue -Path $ppmsRegPath -name PCname) #Equipment name
$ppmsURL = (Get-ItemPropertyValue -Path $ppmsRegPath -name URL) #PPMS URL
$ppmsCode = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name code) #PPMS equipment code
$ppmsID = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name ID) #PPMS equipment ID 
$pumapiKey = (Get-ItemPropertyValue -Path $ppmsRegPath -name pumapiKey) #PUMAPI key, must have user management turned on
$sameGroupFlag = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name sameGroupFlag) #Enable(1)/Disable(0) Allow users from the same group to share bookings
$browser = (Get-ItemPropertyValue -Path $ppmsRegPath -name browser) #web browser to open PPMS
$ppmsTimeout = (Get-ItemPropertyValue -Path $ppmsRegPath -name ppmsTimeout) #ppms communications timeout

#Check which group a user belongs to
Function getUserInfo([string]$userInput) {
    $getUser = Invoke-RestMethod -uri -TimeoutSec $ppmsTimeout $ppmsURL/pumapi/ -method post -body "apikey=$pumapiKey&action=getuser&login=$userInput&withuserid=true&format=json" #get user details from PPMS server
    wait
    return $a = [PSCustomObject] @{
        userName = $getUser.unitlogin
        userEmail = $getUser.email
        userID = $getUser.userid
    }
}

#Get PPMS Booking Information
$currentBooking = Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "action=getbooking&id=$ppmsID&code=$ppmsCode" #get current booking details from PPMS server
wait
$nextBooking = Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "action=nextbooking&id=$ppmsID&code=$ppmsCode" #get next booking details from PPMS server
wait

#Format the PPMS booking information into something useable
$currentBookingArray = $currentBooking -split "\r\n"
$nextBookingArray = $nextBooking -split "\r\n"
$nowUser = $currentBookingArray[0]
$nextUser = $nextBookingArray[0]
$nowMins = [int]$currentBookingArray[1]
$nextMins = [int]$nextBookingArray[1]
$currentBookingArray = $currentBooking -split "\r\n"
$CRLF = "&#x0a;"  #Used in the popup message to create a new line of text

If ($sameGroupFlag -eq 1) {
    $winGroup = (getUserInfo $pcUser)[0]
    $nowGroup = (getUserInfo $nowUser)[0]
    "Logged in users group = $winGroup"
    "Booked users group = $nowGroup"
    If ($winGroup -eq $nowGroup) {
        $sameGroup = 1
        "Windows user belongs to the same group as the booked user"
    }
    Else {
        $sameGroup = 0
        "Windows user belongs to a different group to the booked user"
    }
} 
Else {
    $sameGroup = 0
    "Strict user booking policy applies"
}

If(($nowUser -eq $pcUser) -or($sameGroup -eq 1)){
    If($nowMins -ne ""){$cpMessage = "$pcUser, You Have $nowMins Min/s Remaining"}
    If($nextMins -ne ""){$cpMessage = $cpMessage +"$CRLF$nextUser's Booking Starts in $nextMins Min/s"
    $hideWindow = 0}
}
Else {$hideWindow = 1}

$popUpTimer = 60
$cpBook = "Book"
$cpLogoff = "Logoff"
$cpIncident = "Incident"
$cpEmail = "Email"

If ($cpBookFlag -eq 1) {
    $cpButtons = @($cpBook, $cpLogoff)
}
Elseif ($cpLogoffFlag -eq 1){
    $cpButtons = @($cpLogoff)
}
Else {$cpButtons = @($cpBook, $cpLogoff, $cpIncident, $cpEmail)
}

$popup = {

    #Custom Button Popup Window code
    . "$PSScriptRoot\cpForm.ps1" 

    $Params3 = @{
        TitleFontSize = 14
        TitleBackground = 'Purple'
        TitleTextForeground = 'White'
        Timeout = 60
        ButtonType = 'none'
        ContentFontSize = 16
        Width = $width
        Height = $height
        Left = $Left
        Top = $Top

    }

    If($hideWindow -eq 0) {
        New-WPFMessageBox @Params3 -Content $cpMessage -Title "PPMS Control Panel" -CustomButtons $cpButtons
    }
    $scriptEnd = (Get-Date)
    $scriptTime = (($scriptEnd - $scriptStart).TotalMilliseconds)
    If ($scriptTime -ge 60000) {.$endCP}
    If ($WPFMessageBoxOutput -eq "Book"){[system.Diagnostics.Process]::Start($browser,"$ppmsURL/planning/?pf=$ppmsPF&item=$ppmsID")}
    If ($WPFMessageBoxOutput -eq "Logoff"){. "$PSScriptRoot\logoff"}
    If ($WPFMessageBoxOutput -eq "Incident"){. "$PSScriptRoot\reportIncident"}
    If ($WPFMessageBoxOutput -eq "Email") {. "$PSScriptRoot\userEmails"}
    If ($scriptTime -lt 60000) {.$popup}
}
&$popup
$endCP = {
    Write-Host "endCP"
    $pcUSer  
}
&$endCP


