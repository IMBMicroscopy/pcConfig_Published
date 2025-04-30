Function extendBooking {
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 #set TLS1.2 for communications with ppms server

    $sessions = ""
    $intervention = ""
    $systems = ""
    $start1 = $start2 = $end1 = $end2 = ""
    $startExtension = $endExtension = ""
    $ppmsTimeout = (Get-ItemPropertyValue -Path $ppmsRegPath -name ppmsTimeout) #ppms communications timeout
    #$ppmsPF = (Get-ItemPropertyValue -Path $ppmsRegPath -name ppmsPF)   


    $day = (Get-Date).tostring("yyyy-MM-dd")
    $formatString = "yyyy-MM-dd"+"T"+"HH"+"\%"+"3A"+"mm"+"\%"+"3A00"

    $extendArray = $extendArray1 = $extendArray2 = [PSCustomObject] @{
        Start = ""
        End = ""
        extendFlag = ""
        nextBookingFlag = ""
        currentFlag = ""
        comment = ""
    }

    #get runsheet for all systems
    $runsheet = Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "action=getrunningsheet&apikey=$pumapiKey&plateformid=$ppmsPF&day=$day&format=csv&noheaders=true" 
    start-sleep -Milliseconds 100
    $sessions = $runsheet -split "`r`n"
    
    #get system bookings and format
    $sessions = $sessions -match ($ppmsSystem)
    $sessions = $sessions -split "," 
    $sessions = $sessions -match '\d\d:\d\d'
    If($sessions -ne "") {$sessions = $sessions.Trim('"')}
    
    #get interventions and format
    $interventions = Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "action=getInt&apikey=$pumapiKey&id=$ppmsID&format=csv&noheaders=true" #get intervention details from PPMS server
    $interventions = $interventions -split '\r\n'
    $interventions = $interventions -replace "/","-"
    $interventions = $interventions -replace '"([^"]*)","([^"]*)",'
    $interventions = $interventions -replace '"',''
    $interventions = $interventions -split ','
    If($interventions -ne "") {$interventions = $interventions.Trim('"')}

    Function roundDown([float] $value, [int] $increment){    
        if($value -ge 1){[Math]::Floor($value / $increment) * $increment}
        else {[math]::Floor($value)} 
    }

    Function detectSessions($rawSessions, $type) {
        $count = 0
        $i = 0
        $extendFlag = 0
        $NextBookingFlag = 0
        $currentFlag = 0
        $startExtension = $endExtension = $null

        #get system date and format to match intervention format
        $now = Get-Date
        $today = (Get-Date).tostring("yyyy-MM-dd")
        $tomorrow = (get-date).AddDays(1).ToString("yyyy-MM-dd")
        $midnight = [DateTime]::Today.AddHours(24)
        $zerotime = [DateTime]::Today.AddHours(0)

        $endSession = $now.AddMilliseconds(-($now.Millisecond))
        $endSession = $endSession.AddSeconds(-($now.Second))
        $endSession = $endSession.addMinutes($nowMins)

        $startArray = @()
        $endArray = @()

        If($rawSessions -ne "") {
            #create arrays for start and end times of sessions
            for($i=0;$i -lt ($($rawSessions.count)-1);$i+=2) {
                If($rawSessions[$i] -eq "00:00") {$rawSessions[$i] = $zerotime}
                If($rawSessions[$i+1] -eq "00:00") {$rawSessions[$i+1] = $midnight}
                $startArray += [datetime]::Parse($rawSessions[$i])
                $endArray += [datetime]::Parse($rawSessions[$i+1])
            }

            #create 2d array to combine the two arrays
            $2dArray = New-Object 'object[,]' $($startArray.count),2
            $2dArray.Clear()

            for($i = 0;$i -lt $startArray.Count; $i++){
                $2dArray[$i,0] = $startArray[$i]
                $2dArray[$i,1] = $endArray[$i]
            }

            #remove sessions that ended before today or dont start until tomorrow
            $filteredArray = @()
            For ($i=0;$i -lt $startArray.Count; $i++) {
                #interventions that start before and end after today
                If((($2dArray[$i,0]) -lt $zerotime) -and (($2dArray[$i,1]) -gt $midnight)) {
                    $filteredArray += $2dArray[$i,0]
                    $filteredArray += $2dArray[$i,1] 
                    }
                #interventions that start before and end today
                If((($2dArray[$i,0]) -lt $zerotime) -and (($2dArray[$i,1]) -gt $zerotime) -and (($2dArray[$i,1]) -le $midnight)) {
                    $filteredArray += $2dArray[$i,0]
                    $filteredArray += $2dArray[$i,1] 
                }
                #interventions that start today and end today
                If((($2dArray[$i,0]) -ge $zerotime) -and (($2dArray[$i,1]) -le $midnight)) {
                    $filteredArray += $2dArray[$i,0]
                    $filteredArray += $2dArray[$i,1]
                } 
                #interventions that start today and end after today
                If((($2dArray[$i,0]) -ge $zerotime) -and (($2dArray[$i,1]) -gt $midnight)) {
                    $filteredArray += $2dArray[$i,0]
                    $filteredArray += $2dArray[$i,1] 
                }
            }

            $startFiltered = @()
            $endFiltered = @()
            for ($i=0;$i -lt $($filteredArray.count);$i+=2) {$startFiltered += $filteredArray[$i]}
            for ($i=1;$i -lt $($filteredArray.count);$i+=2) {$endFiltered += $filteredArray[$i]}
            
            $2dFiltered = New-Object 'object[,]' $($startFiltered.count),6
            $2dFiltered.Clear()
            for($i = 0;$i -lt $startFiltered.Count; $i++){
                $2dFiltered[$i,0] = $i
                $2dFiltered[$i,1] = $startFiltered[$i]
                $2dFiltered[$i,2] = $endFiltered[$i]
            }

            #adjust long sessions to current day"
            For ($i=0;$i -lt $startFiltered.Count; $i++) {
                If (($2dfiltered[$i,1]) -lt $zerotime) {
                    $2dfiltered[$i,1] = $zerotime
                }
                If (($2dfiltered[$i,2]) -gt $midnight) {
                    $2dfiltered[$i,2] = $midnight
                }
            }

            #Calculate Delta 
            For ($i=0;$i -lt $2dFiltered.getlength(0); $i++) {
                $2dFiltered[$i,3] = (($2dfiltered[$i,1]) - $endSession).TotalMinutes
                $2dFiltered[$i,4] = (($2dfiltered[$i,2]) - $endSession).TotalMinutes
            }

            #Determine which sessions conflict and mark as Delta 0
            For ($i=0;$i -lt $2dFiltered.getlength(0); $i++) {
                If(($endSession -ge ($2dfiltered[$i,2])) -or ($endSession -lt ($2dfiltered[$i,1]))) {
                    $2dFiltered[$i,5] = $((($2dfiltered[$i,1]) - $endSession).TotalMinutes)
                } Else {$2dFiltered[$i,5] = 0}
            }
        
            #Create 2d array for sorting
            $2dsorted = for ($i = 0; $i -lt $2dFiltered.getlength(0); $i++){
                [PSCustomObject] @{
                    session = $i
                    Start = $2dFiltered[$i,1]
                    End = $2dFiltered[$i,2]
                    startDelta = $2dFiltered[$i,3]
                    endDelta = $2dFiltered[$i,4]
                    Extension = $2dFiltered[$i,5]
                    }
            }
        
            $2dsortedCount = ($2dsorted | Measure-Object -Property session).Count
            $2dSorted = $2dSorted | sort-object -Property Extension
            #Write-Host "2dSorted =" $2dSorted

            If($2dsortedCount -gt 0) {
                $sessionFlag = 1
                For($i=0;$i -lt $2dsortedCount;$i++) {
                    If($2dsorted.Extension[$i] -eq 0) {
                        #Write-Host "You dont have a booking and someone else does, or conflicting intervention detected"
                        $extendFlag = 0
                        Break
                    }
                    Elseif ($2dsorted.Extension[$i] -gt 0) {
                        #Write-Host "No Conflict, but there is an upcoming booking"
                        $extendFlag = 1
                        $NextBookingFlag = 1
                        Break
                    }
                    Elseif (($2dsorted.endDelta[$i] -le 0) -and ($2dsorted.endDelta[$i] -gt -1)) {
                        #Write-Host "Current booking detected, use End time of current booking as startExtension"
                        $extendFlag = 1
                        $currentFlag = 1
                        Break
                    }
                    Else {
                        #Write-Host "No Conflict detected, No next booking"
                        $extendFlag = 1
                        $NextBookingFlag = 0    
                    }
                }
            }
            Else {
                #Write-Host "No Sessions Today, No Conflict, No next booking"
                $extendFlag = 1
                $NextBookingFlag = 0
            }
        }
        Else {
            #Write-Host "No Sessions Today, book up to maxExtension"
            $extendFlag = 1
            $NextBookingFlag = 0
        }

        If($extendFlag -eq 1) {
            #Write-Host "Round start time to nearest 15 minutes"
            If(($nowMins -eq 0) -or ($type -eq "intervention")) {
                #Write-Host "No current booking, so round down to nearest 15 minutes"
                $roundTime = roundDown $now.Minute 15
                $startExtension = $now.AddMilliseconds(-($now.Millisecond))
                $startExtension = $startExtension.AddSeconds(-($now.Second))
                $startExtension = $startExtension.addMinutes($roundTime -($now.Minute))
                #If there are sessions today
                If($nextBookingFlag -gt 0) {
                    $endExtension = $2dsorted.start | Select-Object -Index $i
                }Else {$endExtension = $midnight}
            }
            Else {
                #Write-Host "Current booking, so use the endSession time as your startExtension time"
                $startExtension = $2dSorted.End | Select-Object -Index $i
                If(($2dsorted.start | Select-Object -Index $($i+1)) -ne $null) {
                    $endExtension = $2dsorted.start | Select-Object -Index $($i+1)
                }Else {$endExtension = $midnight}
            }
        }
        Else {
            #Write-Host "cant extend"
            $extendFlag = 0
            $startExtension = $now
        }

        $extendArray += [PSCustomObject] @{
                Start = $startExtension
                End = $endExtension
                extendFlag = $extendFlag
                nextBookingFlag = $NextBookingFlag
                currentFlag = $currentFlag
                sessionIndex = $i
                comment = $comment
        }
        return $extendArray
    }

    #Write-Host "Detect possible booking slot using runsheet"
    $extendArray1 = detectSessions $sessions "booking"
    #Write-Host "extendArray1"
    $start1 = $extendArray1.Start
    $end1 = $extendArray1.end
    #Write-Host "start1 =" $start1
    #Write-Host "end1 =" $end1

    #Write-Host "Detect possible booking slot using Interventions"
    $extendArray2 = detectSessions $Interventions "intervention"
    #Write-Host "extendArray2"
    $start2 = $extendArray2.Start
    $end2 = $extendArray2.end

    #Write-Host "start1 = " $start1
    #Write-Host "end1 = "$end1

    #determine appropriate start booking time
    If($start1 -le $start2) {
        #"Start1 is less than Start2"
        $startExtension = $start2
    }
    Else {
        #"Start1 is greater than Start2"
        $startExtension = $start1
    }

    #determine appropriate end booking time
    If($end1 -le $end2) {
        #"End1 is less than End2"
        $endExtension = $end1
    }
    Else {
        "End1 is greater than End2"
        $endExtension = $end2
    }
    #Write-Host "startExtension"
    #Write-Host $startExtension
    #Write-Host $endExtension

    #Write-Host "Shorten Extension if required"
    If ($endExtension -gt $($startExtension.AddMinutes($maxExtension))) {
        $endExtension = $startExtension.AddMinutes($maxExtension)
    }
    Write-Host "Extend From: $startExtension to $endExtension"

    #"Converted Extensions to Long formatted strings"
    $startExtensionString = ([datetime]$startExtension).ToString("yyyy-MM-dd HH:mm:ss")
    $endExtensionString = ([datetime]$endExtension).ToString("yyyy-MM-dd HH:mm:ss")

    #"Converted Extensions to API formatted strings"
    $startExtensionStringPPMS = $startExtension.ToString($formatString)
    $endExtensionStringPPMS = $endExtension.ToString($formatString)
    #$startExtensionStringPPMS
    #$endExtensionStringPPMS

    $extensionOutput = @{}
    $extensionOutput = [PSCustomObject] @{
        extendStartStringPPMS = $startExtensionStringPPMS
        extendEndStringPPMS = $endExtensionStringPPMS
        extendStartString = $startExtensionString
        extendEndString = $endExtensionString
        extendStart = $startExtension
        extendEnd = $endExtension
        extendEndShortString = ([datetime]$endExtension).ToString("hh:mm tt")
        extendLength = ([math]::Round(($endExtension - $startExtension).TotalMinutes))
        extendFlag = $extendArray1.extendFlag -and $extendArray2.extendFlag
    }
    #Write-Host "end extension time = " ($extensionOutput.extendEnd).ToString("HH:mm:ss")
    return $extensionOutput
}

