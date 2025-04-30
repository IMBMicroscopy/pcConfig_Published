Function getUserInfo([string]$userInput) {
    $ppmsTimeout = (Get-ItemPropertyValue -Path $ppmsRegPath -name ppmsTimeout) #ppms communications timeout
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 #set TLS1.2 for communications with ppms server

    $userDetails = ""
    #get user details from PPMS server
    Try{
        logdata "getUserInfo : $userInput - Attempting PPMS server connection"
        $getUser = Invoke-RestMethod -TimeOutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "apikey=$pumapiKey&action=getuser&login=$userInput&withuserid=true&format=json" #get user details from PPMS server
        wait 50
        return $userDetails = [PSCustomObject] @{
            login = $getUser.login
            lname = $getUser.lname
            fname = $getUser.fname
            group = $getUser.unitlogin
            phone = $getUser.phone
            userEmail = $getUser.email
            userID = $getUser.userid
        }
    }Catch{
        logdata "getUserInfo - couldnt get user contact info from ppms server"
        return $userDetails = ""
    }
}

