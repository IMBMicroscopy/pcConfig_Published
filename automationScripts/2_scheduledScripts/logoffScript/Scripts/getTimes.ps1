<#
PPMS has a "Feature" whereby if booking "B" starts immediately after booking "A", 
we see strange results in the "getBooking" and "nextBooking" API calls

nowMins = minutes remaining on current booking
nowUser = current booked user
nextMins = minutes until next booking
nextUser = next booked user

example 1:
    Booking A = 7am-8am user = j.springfield
    Booking B = 8am-9am user = n.condon
    If the current time is 8am
    Then: nowMins = 0, nowUser = "", nextMins = 0, nextUser = ""
    The correct output should be
    nowMins = 0, nowUser = "j.springfield", nextMins = 0, nextUser = "n.condon"

example 2:
    Booking A = 7am-8am user = j.springfield
    Booking B = 8am-9am user = n.condon
    Booking C = 10am-11am user = j.bloggs
    Then: nowMins = 0, nowUSer = "", nextMins = 120, nextUser = "j.bloggs"
    The correct output shoulod be
    nowMins = 0 nowUSer = "j.springfield", nextMins = 0, nextUser = "n.condon"

The following code allows me to fix this issue, however i need a way to convert the runsheet users full name to the user login
Ideally stratocore would fix the results returned in the "getBooking" and "nextBooking" API calls
Alternatively add the users login details to the "runsheet" API call
And/or allow the ability to search by "fname" and "lname" in the "getUser" API call, which would be useful for other applications as well
#>

#init variables
$sessions = $runsheet = $nowUser = $nextUser = ""
$ppmsBug = $nowMins = $nextMins = $null
$ppmsTimeout = (Get-ItemPropertyValue -Path $ppmsRegPath -name ppmsTimeout) #ppms communications timeout

#PPMS values
$ppmsURL = 
$pumapiKey = 
$ppmsPF = 
$ppmsID = 
$ppmsCode = 

#get day and time
$day = (Get-Date).tostring("yyyy-MM-dd")
$time = [DateTime]::Parse((Get-Date).tostring("HH:mm"))

#get todays runsheet for all systems
Try{
    $runsheet = Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "action=getrunningsheet&apikey=$pumapiKey&plateformid=$ppmsPF&day=$day&format=csv&noheaders=true" 
}Catch {"Couldnt get runsheet"}

#If there are bookings today, calculate current and next bookings
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

    Switch($bookingArray.Count){
        2 {#current time is between two bookings
            "two bookings"
            $nowMins = ($bookingArray[0].end - $time).TotalMinutes
            $nowUser = $bookingArray[0].name
            $nowUser 
            $nextMins = ($bookingArray[1].start - $time).totalMinutes
            $nextUser = $bookingArray[1].name
        }
        1 {#current time is in one booking
            "one booking"
            $nowMins = ($bookingArray[0].end - $time).TotalMinutes
            $nowUser = $bookingArray[0].name
            $nextBooking = Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "action=nextbooking&id=$ppmsID&code=$ppmsCode" #get next booking details from PPMS server
            $nextBookingArray = $nextBooking -split "\r\n"
            $nextUser = $nextBookingArray[0]
            $nextMins = [int]$nextBookingArray[1]
        }
    }
    "nowMins = $nowMins : nowUser = $nowUser"
    "nextMins = $nextMins : nextUser = $nextUser"
}


