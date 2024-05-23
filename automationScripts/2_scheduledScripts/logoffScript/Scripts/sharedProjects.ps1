#determine if two users share any projects to allow them to share a booking

Function sharedProjects{

    Param
        (
             [Parameter()]
             [string] $user1,
             [Parameter()]
             [string] $user2
        )
   
    . "$PSScriptRoot\getProjects.ps1"

    $user1ProjectList = $user2ProjectList = $null
    $user1ProjectList = getProjects -login $user1 #generate a list of projects/bcodes for a user
    $user1ProjectCount = $user1ProjectList.id.count
    wait $sync.ppmsTimeout
    $user2ProjectList = getProjects -login $user2 #generate a list of projects/bcodes for a user
    $user2ProjectCount = $user2ProjectList.id.count

    if(($user1ProjectCount -gt 0) -and ($user2ProjectCount -gt 0)){
        if(((Compare-Object -ReferenceObject $($user1ProjectList.id) -DifferenceObject $($user2ProjectList.id) -ExcludeDifferent -IncludeEqual).count) -gt 0){$sharedProject = $true}else{$sharedProject = $false}
        return $sharedProject
    }else{return $false}
}

#sharedProjects -user1 nick -user2 mary
