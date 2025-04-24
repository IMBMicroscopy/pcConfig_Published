#Convert minutes to something meaningful
Function formatMinutes([int]$minutes) {
        Try{
            $ts = new-timespan -minutes $minutes
            $tsDay = $ts.Days
            $tsHour = $ts.Hours
            $tsMin = $ts.Minutes
            $tsTime = ""
            If($tsDay -gt 0){
                If($tsDay -gt 1){$tsTime = "$tsDay Days "} 
                    Else {$tsTime = "$tsDay Day "}
            }
            If($tsHour -gt 0){
                If($tsHour -gt 1){$tsTime = $tsTime + "$tsHour Hours "}
                    Else {$tsTime = $tsTime + "$tsHour Hour "}
            }
            If($tsMin -gt 0){
                If($tsMin -gt 1){$tsTime = $tsTime + "$tsMin Mins "}
                    Else {$tsTime = $tsTime + "$tsMin Min "}
            }
            If($minutes -eq 0){$tsTime = "0 Min "}

            return $tsTime
        }Catch{
           logdata "couldnt format minutes"
        }
    }
