Function findUser([string]$userInput) {
    $ppmsTimeout = (Get-ItemPropertyValue -Path HKCU:\Software\PPMSscript -name ppmsTimeout) #ppms communications timeout

    $userDetails = ""
    Try{
        logdata "getUserInfo : $userInput - Attempting PPMS server connection"
        $findUser = Invoke-RestMethod -TimeOutSec $ppmsTimeout -uri $ppmsURL/pumapi/ -method post -body "apikey=$pumapiKey&action=getuser&login=$userInput&withuserid=true&format=json" #get user details from PPMS server
        wait 50
        return $userDetails = [PSCustomObject] @{
            login = $findUser.login
            lname = $findUser.lname
            fname = $findUser.fname
            group = $findUser.unitlogin
            phone = $findUser.phone
            userEmail = $findUser.email
            userID = $findUser.userid
        }
    }Catch{
        logdata "getUserInfo - couldnt get user contact info from ppms server"
        return $userDetails = ""
    }
}
