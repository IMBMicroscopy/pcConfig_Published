Do{
    #Call IncidentLevel script, this allows powershell to repeatedly popup the message rather than causing errors if you embed IncidentLevel code in this script
    . "$PSScriptRoot\IncidentLevel.ps1" 
    #If($WPFMessageBoxOutput -eq "Cancel"){Break}
} While ((($Severity -ne $null) -and ($incidentDescription -eq "")) -or (($Severity -eq $null) -and ($incidentDescription -ne "")))  

If(($Severity -ne $null) -and ($incidentDescription -ne "")){
    $pcUser = $env:UserName

    $incidentDescription = $pcUser + " - " + $incidentDescription
    $incidentDescription = $($incidentDescription).replace(" ","+") #replace spaces in textbox output with + to enable spaces in Invoke-webrequest.  need to remove these + for emails etc
    $incidentDescription = $($incidentDescription).replace("`r","%0D") #replace carriage return with URL safe equivalent
    $incidentDescription = $($incidentDescription).replace("`n","%0A") #replace line feed with URL safe equivalent

    $ppmsID = (Get-ItemPropertyValue -Path $ppmsRegPath -name ppmsID) #PPMS equipment ID 
    $ppmsTimeout = (Get-ItemPropertyValue -Path $ppmsRegPath -name ppmsTimeout) #ppms communications timeout
    $ppmsURL = (Get-ItemPropertyValue -Path $ppmsRegPath -name ppmsURL) #PPMS URL
    $pumapiKey = (Get-ItemPropertyValue -Path $ppmsRegPath -name pumapiKey) #PUMAPI key, must have user management turned on

    Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "action=createinc&apikey=$pumapiKey&id=$ppmsID&severity=$severityNumber&descr=$incidentDescription"
}