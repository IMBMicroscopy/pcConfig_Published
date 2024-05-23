#script to uninstall task scheduler task and registry entries for ppmsConfig.ps1

#Define a ps2exe compiler compatible script path variable
 if ($MyInvocation.MyCommand.CommandType -eq "ExternalScript"){
    $ScriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition 
}else{
    $ScriptPath = Split-Path -Parent -Path ([Environment]::GetCommandLineArgs()[0]) 
    if (!$ScriptPath){ $ScriptPath = "." } 
}

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy unrestricted  -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    exit;
}

Write-Host "Please wait whilst the scripts are removed...."

$taskPath = "Microscopy"
$logRoot = "c:\scriptLogs"
$ppmsRegPath = "HKCU:\Software\Microscopy"  
$LM_rootPath = "HKLM:\Software\Microscopy"

$tasks = (Get-ScheduledTask -TaskPath "*$taskPath*" -TaskName "*")
$deleteFolderFlag = $false

#remove tasks
if(($tasks.TaskName).count -gt 0){
    foreach($task in $tasks){
        $taskName = $task.TaskName
        try{
            Unregister-ScheduledTask -TaskName $taskName -TaskPath "*$taskPath*" -Confirm:$false | Out-Null
            "Deleted task: $taskName"
            $deleteFolderFlag = $true
        }catch{"couldnt delete task: $taskName"}
       
    }
}

#remove empty task scheduler folder
if((((Get-ScheduledTask -TaskPath "*$taskPath*" -TaskName "*").TaskName).count -eq 0) -and $deleteFolderFlag -eq $true){
    $scheduleObject = New-Object -ComObject Schedule.Service
    $scheduleObject.connect()
    $rootFolder = $scheduleObject.GetFolder("\")
    try{
        $out = $rootFolder.DeleteFolder($taskPath,$null) | Out-Null
        Write-Host "deleted empty task folder: $taskPath"    
    }
    catch{Write-Host "couldnt delete task folder: $taskPath"}
}

#kill ppmsCP.exe process
try{
    Stop-Process -Name "ppmsCP" -Force -ErrorAction Stop | Out-Null
    Write-Host "Control Panel killed"
}catch{"ppmsCP not found"}

#remove wallpaper
$wallpaperpath = $ScriptPath + "/2_scheduledScripts/2_wallpaper/"
try{
    Get-ChildItem -Path $wallpaperpath -Filter *.jp* -File | Remove-Item -Force -ErrorAction SilentlyContinue | out-null
    Write-Host "removed old wallpaper images"
}catch{Write-Host "couldnt remove old images"}

Start-Sleep -Seconds 1

#remove empty registry folder
try{$length = (Get-Item -Path $ppmsregPath -ErrorAction Stop).Length}catch{$length = 0}
if($length -gt 0){
    try{
        Remove-Item -Path $ppmsregPath -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        write-Host "removed empty registry path: $ppmsRegPath"
    }catch{Write-Host "couldnt remove $ppmsRegPath"}
}

#remove empty registry folder
try{$length = (Get-Item -Path $LM_rootPath -ErrorAction Stop).Length}catch{$length = 0}
if($length -gt 0){
    try{
        Remove-Item -Path $LM_rootPath -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        Write-Host "removed empty registry path: $LM_rootPath"
    }
    catch{"couldnt remove $LM_rootPath"}
}

#remove log folder
try{
    Remove-Item -Path $logRoot -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    Write-Host "removed log folder: $logRoot" 
}
catch{"couldnt remove log folder: $logRoot"}

Read-Host "uninstaller script has finished, press ENTER to continue..."
