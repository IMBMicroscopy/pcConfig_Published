#init Variables
$sessions = $runsheet = $myNowUser = $myNextUser = ""
$ppmsBug = $myNowMins = $myNextMins = $null
$ppmsTimeout = (Get-ItemPropertyValue -Path $ppmsRegPath -name ppmsTimeout) #ppms communications timeout
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 #set TLS1.2 for communications with ppms server

#get day and time
$day = (Get-Date).tostring("yyyy-MM-dd")
$time = [DateTime]::Parse((Get-Date).tostring("HH:mm"))
$time = [DateTime]::Parse((Get-Date).tostring("08:30")) #debugging

#get users surname
$path = $PSScriptRoot
. "$path\getUserInfo.ps1"
$pcUser = $env:USERNAME
$surname = (getUserInfo $pcUser).lname

#get todays runsheet for all systems
Try{
    $runsheet = Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "action=getrunningsheet&apikey=$pumapiKey&plateformid=$ppmsPF&day=$day&format=csv&noheaders=true" 
}Catch {"Couldnt get runsheet"}

If($runsheet -ne "") {
    #Filter runsheet for this system
    $sessions = $runsheet -split "`r`n"
    $sessions = $sessions -match ($ppmsSystem)
    $sessions = $sessions -split ","
    If($sessions -ne "") {$sessions = $sessions.Trim('"')}

    #Create 2d array for sorting
    $j=0
    $2dArray = @()
    $now = $next = $type = ""
    $2dArray = for ($i = 0; $i -lt $($sessions.count); $i+=7){
        $start = [DateTime]::Parse($sessions[$i+1])
        $end = [DateTime]::Parse($sessions[$i+2])

        [PSCustomObject] @{
            Index = ""
            ID = $j
            start = $start
            end = $end
            name = $sessions[$i+4]
        }
        $j++
    }
  
    $2dSorted = $2dArray | sort-object -Property Start
   
    $bookingArray = @()
    For($i=0;$i -lt $(($2dSorted.Start).Count);$i++){
        $2dSorted[$i].Index = $i
        If(($time -ge $2dSorted.Start[$i]) -and ($time -le $2dSorted.End[$i])){
            "current booking found at Session = $($2dSorted.ID[$i]), Index = $i"
            $bookingArray += $2dSorted[$i]
        }
    }
    $bookingArray

    #current time is between two bookings
    If($bookingArray.Count -eq 2){
        "two sessions"
        $myNowMins = ($bookingArray[0].end - $time).TotalMinutes
        $myNowUser = $bookingArray[0].name
        $myNextMins = ($bookingArray[1].start - $time).totalMinutes
        $myNextUser = $bookingArray[1].name
        If(($myNowUser -eq $myNextUser) -and ($myNowUser -match $surname)){$ppmsBug = 1}
    }
    If($bookingArray.Count -eq 1){
        "one session"
        $myNowMins = ($bookingArray[0].end - $time).TotalMinutes
        $myNowUser = $bookingArray[0].name
        $nextBooking = Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "action=nextbooking&id=$ppmsID&code=$ppmsCode" #get next booking details from PPMS server
        $nextBookingArray = $nextBooking -split "\r\n"
        $myNextUser = $nextBookingArray[0]
        $myNextMins = [int]$nextBookingArray[1]

    }
    "myNowMins = $myNowMins : myNowUser = $myNowUser"
    "myNextMins = $myNextMins : myNextUser = $myNextUser"
}
Else{$ppmsBug = 0}

If($ppmsBug -eq 1){"ppmsBug found"} Else {"No ppmsBug found"}

