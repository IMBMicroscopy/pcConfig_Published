#Configuration settings for googleSoftwareTracker script
#script to report multiple individual software usage to ppms server every minute
#also report user logon to ppms server if configured

<#Powershell script to track the current logged in user and report their usage to Google Sheets
Installation requirements:
    Set the folder and contents permissions for the folder to provide full read/write permissions to "Users"
    #follow instructions in .pdf stored with this file to setup the google sheets API
    #the script needs the .p12 certificate file to be generated from the google sheets website
    
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

Configuration      
    if configuring new software to track, run the software on the PC, and then copy and past this code into the blue console pane below and press "return/enter"
    copy and past => (Get-Process).Name

    find the name of the process related to your software to track and copy it
    paste this process name into the website table listed below, and into the cpSettings.ps1 $softwareList

#>

## google Tracker Script Settings ######################################################################################
$enableSoftwareTracker = 1                                                #enable software tracking section of the script? 1=Yes, 0=No
$sameSessionDelta = 5                                                     #number of minutes between successive logins of the same user to track as the same session
$maxDelay = 2000                                                          #random delay up to $maxDelay in milliseconds
######################################################
$reportToPPMS = 1                                                         #report GUID to PPMS
######################################################
#software list location
$softwareURL = ""                                                         #URL for software list table
$softwareTableName = "Software Tracker"                                   #Table to query for software processes, IDs and Codes
######################################################
#Spreadsheet Details
$sheetTitle = 'Microscopy Facility Usage'                                 #name of google spreadsheet
$userAccount = ""                                                         #google user account with read/write permissions
$maxCells = 9998000                                                       #create a new spreadsheet when the number of cells reaches this number (google sheet limit is 10mil cells)
######################################################
# Google API Authozation
$googleScope = "https://www.googleapis.com/auth/spreadsheets https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/drive.file"
$iss = ''
$certPswd = ''
######################################################
#logging
$logRoot = "C:\scriptLogs"                                               #root path to store log files
$logToFile = 1                                                            #enable/disable (1/0) logging to file
$logToConsole = 1                                                         #enable/disable (1/0) logging to console
######################################################
#settings URL for global flag location
$getSettingsFromURLFlag = 1                                              #Enable/Disable Query URL table for global script settings
$settingsURL = ""                                                        #URL for script settings table
$settingsTableName = "Global Script Settings"                            #Table to query for global enable/disable flags
$fallbackFlag = $true                                                    #If website or setting isnt found, fallback to these values
######################################################
#registry path
$softwareRegPath = "HKCU:\Software\Microscopy\softwareTracker"            #path to save registry files for use by googlesoftwaretracker.ps1
$ppmsRegPath = "HKCU:\Software\Microscopy\ppmsScript"                     #path to load registry files from ppmsConfig.ps1
$LMRegPath = "HKLM:\Software\Microscopy\PPMSscript"                       #local machine reg path
$LM_rootPath = "HKLM:\Software\Microscopy"                               #local machine reg path for shared settings
######################################################
$taskname = "softwareTracker"                                             #name of task to create
$taskPath = "Microscopy"                                                  #task sub-folder to create
$scriptToRun = "runMe.vbs"
$atLogon = $false #run task once at user logon if true, else run every minute if false
$asSystem = $false #if $true, run task as system, else run as Users
$asAdmin = $false                                                         #if $true, run task with highest priveleges but as regular user
######################################################
#debugging
$debug = 0                                                                #debugging mode, dont write to spreadsheet etc if true


