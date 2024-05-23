$QuestionFlag = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name QuestionFlag) #Questionaire enabled if true

If($QuestionFlag -eq 1) {
    
    $ppmsRegPathCount = "$($ppmsRegPath)Count"
    $ppmsURL = (Get-ItemPropertyValue -Path $ppmsRegPath -name URL) #PPMS URL
    $ppmsCode = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name code) #PPMS equipment code
    $pumapiKey = (Get-ItemPropertyValue -Path $ppmsRegPath -name pumapiKey) #PUMAPI key, must have user management turned on
    $ppmsID = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name ID) #PPMS equipment ID 
    $QuestionRandom = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name QuestionRandom) #Randomise how often the questions are asked if true
    $QuestionOccurence = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name QuestionOccurence) #Questionaire appears every nth login, If Random is false
    $QuestionCount = [int](Get-ItemPropertyValue -Path $ppmsRegPathCount -name QuestionCount) #how many times has the user logged on
    $QuestionDrive = (Get-ItemPropertyValue -Path $ppmsRegPath -name QuestionDrive) #network drive location
    $QuestionPath = (Get-ItemPropertyValue -Path $ppmsRegPath -name QuestionPath) #Path to Question
    $ppmsTimeout = (Get-ItemPropertyValue -Path $ppmsRegPath -name ppmsTimeout) #ppms communications timeout

    $QuestionMount = $QuestionDrive -split '\\'
    $QuestionMount = $QuestionMount[$QuestionMount.Count-1]
    
    #Get PPMS Booking Information
    Try{
        logdata "askQuestion - attempting to contact ppms server"
        $currentBooking = Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "action=getbooking&id=$ppmsID&code=$ppmsCode" #get current booking details from PPMS server
    }Catch {
        logdata "askQuestion - Couldnt contact ppms Server"
        $currentBooking = @()
    }
    $currentBookingArray = $currentBooking -split "\r\n"
    $nowUser = $currentBookingArray[0]
    $sessionID = $currentBookingArray[2]

    If(($currentBooking -ne "") -and ($currentBooking -ne $null)){
        If($QuestionFlag -eq 1) {
            If($QuestionRandom -eq 0) {
                If($QuestionCount -ge $QuestionOccurence ) {
                    $askQuestion = 1
                    $QuestionCount = 1    
                }
                Else{
                    $askQuestion = 0
                    $QuestionCount++
                }
            }
            Else {
                $random = Get-Random -Maximum $QuestionOccurence
                If ($random -eq 0) {
                    $askQuestion = 1
                    $QuestionCount = 1
                }
                Else {
                    $askQuestion = 0
                    $QuestionCount++    
                }
            }
        }

        #$askQuestion = 1 #debug
        If($askQuestion -eq 1) {
            ."$PSScriptRoot\mountDrive.ps1"
            If($driveMounted -eq $true){
                logdata "askQuestion - ask questions"
                Do{. "$PSScriptRoot\Questionaire.ps1" 
                } While (($answer -eq $null) -and ($noQuestions = 0)) 

                If($answer -ne $null){
                    logdata "askQuestion - question answered"
                    $time = (Get-Date).ToString("HH:mm")
                    [string]$note = Invoke-RestMethod -timeoutsec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "apikey=$pumapiKey&action=getsessionnote&resid=$sessionID" #set session note for booking
                    If(($note -match "\w") -eq $true -and $($note[$note.Length+1] -ne ",")) {$comma = ","}Else{$comma = ""}
                    $note = $note + "$comma$time=$answerNumber$answer"
                    Invoke-RestMethod -timeoutsec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "apikey=$pumapiKey&action=setsessionnote&resid=$sessionID&note=$note" #set session note for booking
                }
            } Else {logdata "askQuestion - Drive not mounted, no questions asked"}
        }
        Else {
            logdata "askQuestion - Question not asked this time"
        }
        New-ItemProperty -Path $ppmsRegPathCount -name QuestionCount -Value $QuestionCount -Force | Out-Null
    } 
    Else{logdata "askQuestion - No Booking, Question not asked"}
}else{logdata "QuestionFlag = 0"}