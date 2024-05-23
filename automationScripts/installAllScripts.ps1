#elevate to Administrator to run script
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy unrestricted  -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    exit;
}

$LM_rootPath = "HKLM:\Software\Microscopy"                                #local machine reg path for shared settings

Write-Host "Please wait whilst the PC is configured and scripts are installed...."

function makeKey {
    param(
        [Parameter(Position=0,mandatory=$true)]
        [string] $regPath,
        [Parameter(Position=1)]
        [string] $name,
        [Parameter(Position=2)]
        [ValidateSet('String','ExpandString','Dword','Binary','MultiString','Qword','Unknown')]
        [string] $propertyType = "string",
        [Parameter(Position=3)]
        $value
    )

    #does registry root path exist
    try{Get-Item -Path $regPath -ErrorAction stop | out-null}
    catch{ 
        try{New-Item -Path $regPath -name Default -Value "default value" -Force }
        catch{ "couldnt make registry path: $regPath"}
    }
    if( (![string]::IsNullOrEmpty($name)) -and (![string]::IsNullOrEmpty($value)) ) {
        #create key and value
        try{
            New-ItemProperty -Path $regPath -Name $name -PropertyType string -Value $value -Force -ErrorAction Stop  | Out-Null 
             "created registry key: $name"
        }catch{ "couldnt make registry key: $name"}
    }
}

function setRegPermissions ($inputReg) {
    #set registry access permissions for all users
    try{
        $acl = Get-Acl $($inputReg)
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule ("BUILTIN\Users","FullControl","ContainerInherit, ObjectInherit", "None", "Allow")
        $acl.SetAccessRule($rule)
        $acl |Set-Acl -Path $inputReg
         "permissions set for registry $inputReg" 
    }catch{ "couldnt set registry permissions for $inputReg" }
}

$makeHKLMroot = {
    if($makeLMFlag){
        #create root regpath if required
        try{
            New-Item -Path $LM_rootPath -Force -ErrorAction Stop | out-null
            "registry path: $LM_rootPath created" 
        }
        catch{ "couldnt create registry path: $LM_rootPath" }

        setRegPermissions $LM_rootPath
    }
}

#Define a ps2exe compiler compatible script path variable
if ($MyInvocation.MyCommand.CommandType -eq "ExternalScript"){
    $ScriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition 
}else{
    $ScriptPath = Split-Path -Parent -Path ([Environment]::GetCommandLineArgs()[0]) 
    if (!$ScriptPath){ $ScriptPath = "." } 
}

#enable script execution
try{
    Set-ExecutionPolicy -ExecutionPolicy unrestricted -Scope LocalMachine -Force -ErrorAction Stop
    "Set Exection Policy for PC"    
}
catch{"couldnt update execution policy"}

$vbsList = @()
$list = Get-ChildItem -Path $ScriptPath -Recurse -Exclude $ScriptPath
foreach($file in $list){
    if($file.Name -like "runMe.vbs"){
        $vbsList += $file.FullName
    }
}
$listOfVBS = $vbsList | Sort-Object 


$makeLMFlag = $true
. $makeHKLMroot #create registry path if required
New-ItemProperty -Path $LM_rootPath -name installedScripts -Value 0 -Force | Out-Null 


foreach($file in $listOfVBS){
    try{$lastScriptNumber = [int](Get-ItemPropertyValue $LM_rootPath -Name installedScripts -ErrorAction SilentlyContinue)}catch{$lastScriptNumber = [int]0}
    "$lastScriptNumber : installing $file"
     . $file
     while(([int](Get-ItemPropertyValue $LM_rootPath -Name installedScripts) -le $lastScriptNumber) -and (([int](Get-ItemPropertyValue $LM_rootPath -Name installedScripts) -le ($listOfVBS.count -1)))) {
        start-sleep -Milliseconds 200
    }
}
#end script
read-host "Setup has completed, press ENTER to continue...";

