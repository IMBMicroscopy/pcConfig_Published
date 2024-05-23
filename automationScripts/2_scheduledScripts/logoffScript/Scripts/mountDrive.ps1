$mounted = $driveMounted = $false

$driveList = [System.IO.DriveInfo]::GetDrives()

#Search drive list for drive
For($i=0;$i -lt $driveList.Count;$i++) {
    $mounted = $driveList[$i].VolumeLabel -contains $QuestionMount
    If ($mounted -eq $true){
        "Drive mounted on $(($driveList.GetValue($i)).Name)"
        $driveMounted = $true
        break
    }
}

If($mounted -eq $false) {
    If(Test-path "$QuestionDrive$QuestionPath$PCname.txt"){
        Try{
            #"Assign Letter that's not already in use and mount Drive"
            for($j=67;gdr($drive=[char]++$j)2>0){}
            "Drive mounted on $(New-PSDrive -Name $drive -PSProvider FileSystem -Root $QuestionDrive -Persist):\"
            $driveMounted = $true
        } Catch {
            "Couldnt mount drive"
            $driveMounted = $false
        }
    }Else{
        "Couldnt find drive"
        $driveMounted = $false
    }
}

return $driveMounted



