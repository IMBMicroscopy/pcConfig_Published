#Configuration settings for ppms Tracker script

<#Powershell script to track the current logged in user to ppms
Installation requirements:
    Set the folder and contents permissions for the folder to provide full read/write permissions to "Users"
    
You must enable powershell script execution before running this script
    Press the Windows Start button and type Powershell ISE, right click and "Run as Administrator"
    Copy the following line into the console then press Enter (You may choose to use Bypass or per script policies instead of Unrestricted)
    Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy Unrestricted -Force
    
    Copy the following line into the console then press Enter to install the following module
    Import-Module -name UMN-Google

PS2EXE has been used to compile the PPMStracker.ps1 script into an executable "PPMStracker.exe" which allows windows task scheduler to run the script with minimal fuss.
    Anti-Virus software may or will block this executable from running

Task Scheduler
    Create a task scheduler task which runs "PPMStracker.exe" on a schedule every minute under the "User" user account with highest priveleges.
    You may wish to tweak the "Settings" tab to "run task on demand" 

#>

## ppms Tracker Script Settings ######################################################################################
$enableSoftwareTracker = 1                                                #enable software tracking section of the script? 1=Yes, 0=No
$maxDelay = 500                                                           #random delay up to $maxDelay in milliseconds after script run
######################################################
$reportToPPMS = 1                                                         #report user session to PPMS
######################################################
#logging
$logRoot = "C:\scriptLogs"                                                #root path to store log files
$logToFile = 1                                                            #enable/disable (1/0) logging to file
$logToConsole = 1                                                         #enable/disable (1/0) logging to console
######################################################
#settings URL for global flag location
$getSettingsFromURLFlag = 1                                              #Enable/Disable Query URL table for global script settings
$settingsURL = "https://imb.uq.edu.au/research/research-facilities/microscopy/script-settings" #URL for script settings
$settingsTableName = "Global Script Settings"                            #Table to query for global enable/disable flags
$fallbackFlag = $true                                                    #If website or setting isnt found, fallback to these values
######################################################
#registry path
$softwareRegPath = "HKCU:\Software\Microscopy\softwareTracker"            #path to save registry files for use by googlesoftwaretracker.ps1
$ppmsRegPath = "HKCU:\Software\Microscopy\ppmsScript"                     #path to load registry files from ppmsConfig.ps1
$LMRegPath = "HKLM:\Software\Microscopy\PPMSscript"                       #local machine reg path
$LM_rootPath = "HKLM:\Software\Microscopy"                                #local machine reg path for shared settings
######################################################
$taskname = "ppmsTracker"                                                 #name of task to create
$taskPath = "Microscopy"                                                  #task sub-folder to create
$scriptToRun = "runMe.vbs"
$atLogon = $false                                                         #run task once at user logon if true, else run every minute if false
$asSystem = $false                                                        #if $true, run task as system, else run as Users
$asAdmin = $false                                                         #if $true, run task with highest priveleges but as regular user
######################################################


