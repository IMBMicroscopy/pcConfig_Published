#function to get either an active users list of active projects/bcodes using their ppms login, 
#or get the project and bcode for a specific session using the session ID

function getProjects{

    param(
        [parameter(Mandatory=$true,
        ParameterSetName="session")]
        [String]
        $session,

        [parameter(Mandatory=$true,
        ParameterSetName="login")]
        [String]
        $login
    ) 

    $ppmsTimeout = (Get-ItemPropertyValue -Path $ppmsRegPath -name ppmsTimeout) #ppms communications timeout
    $ppmsURL = (Get-ItemPropertyValue -Path $ppmsRegPath -name ppmsURL) #PPMS URL
    $apiKey = (Get-ItemPropertyValue -Path $ppmsRegPath -name apiKey) #apiKey key, must have user management turned on
    $ppmsPF = [int](Get-ItemPropertyValue -Path $ppmsRegPath -name ppmsPF) #PPMS Platform ID or PF number, Appears in the URL
    $projectsForUserReport = (Get-ItemPropertyValue -Path $ppmsRegPath -name projectsForUserReport) #report to get list of projects for user

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 #force TLS1.2 communications with ppms server
   
    $body="action=report$projectsForUserReport&dateformat=print&outformat=json&apikey=$apikey&coreid=$ppmsPF"
    If ([string]::IsNullOrEmpty($session) -and [string]::IsNullOrEmpty($login)){
        return "Error - invalid number of parameters"
    }
    ElseIf ([string]::IsNullOrEmpty($session)){
        #"session is empty, check $login - get list of projects"
        $body=$body+"&session=0&login=$login"
    }
    ElseIf ([string]::IsNullOrEmpty($login)){
        #"login is empty, check $session - get details for session"
        $body=$body +"&session=$session&login=''"
    }Else{
        #return "Error - Too many parameters"
    }

    $response = ""
    $response = Invoke-RestMethod -TimeoutSec $ppmsTimeout -uri $ppmsURL/API2/ -Method 'POST' -Body $body #API call

    #filter out results
    $Projects = $ProjectsName = $ProjectsID = @()
    foreach($project in $response){
        $Projects += New-Object PSObject -Property @{
                user = $project.User
                id = $project.ProjectID
                name = $project.Project
                bcode = $project.bcode
                group = $project.groupId
                fullName = $project.Project + " - " + $project.bcode
        }
    }

    #sort objects by property type
    $Projects = $Projects | Sort-Object -Property name 
    $Projects = $Projects | Sort-Object -Unique name
    return $Projects
}


#getProjects -session 156709 #get the project used for session ID
#"......."
#getProjects -login jbloggs #test for user login

#$list = getProjects -login uqjspri1 #generate a list of projects/bcodes for a user
#$list.bcode #generates a list of bcodes for the user
#$list.name #generates a list of project names for the user
#$list.id #generates a list of project IDs for the user


