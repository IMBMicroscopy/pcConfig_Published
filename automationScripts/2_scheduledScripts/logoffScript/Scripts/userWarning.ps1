#If no other user session today, popup warning, asking user to shutdown scope at end of session
If($sync.lastSessionFlag -eq 1){
    If((($nowMins -le $lastSessionWarning) -and ($lastNowMins -gt $lastSessionWarning)) -or ($firstRun -eq $true)) {
        $dayRemaining = [datetime]::Today.AddDays(1) - [datetime]::Now
        If(($nextMins -ge $dayRemaining.TotalMinutes) -or ($nextMins -eq 0) -or($nowMins -eq 0)) {
            . "$Path\UserWarningRunspace.ps1"
            $lastUserWarning = $true
        }
    }
}