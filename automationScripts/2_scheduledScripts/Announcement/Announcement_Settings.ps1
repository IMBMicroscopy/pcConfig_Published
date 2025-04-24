###########################################################################################################################
$enableAnnouncements = 1                                               #enable/disable (1/0) running this script to show announcements
$softwareURL = ""                                                      #URL for announcement table/s
$softwareTableName = "Announcements"                                   #Table to query for Announcements
$URLTimeout = 10                                                       #maximum time to query website for announcements
$popUpTimer = 60                                                       #duration of announcement popup in seconds
$maxRandom = 5                                                         #pick a random number between 1 and maxRandom to show the popup, if Random is enabled
######################################################
$ppmsRegPath = "HKCU:\Software\Microscopy\ppmsScript"                  #path to load registry files from ppmsConfig.ps1
$announceRegPath = "HKCU:\Software\Microscopy\announce"                #path to load registry files from announcements.ps1
$LM_rootPath = "HKLM:\Software\Microscopy"                             #local machine reg path for shared settings
######################################################
$logRoot = "C:\scriptLogs"                                             #root path to store log files
$logToFile = 1                                                         #enable/disable (1/0) logging to file
$logToConsole = 1                                                      #enable/disable (1/0) logging to console
######################################################
#settings URL for global flag location
$getSettingsFromURLFlag = 1                                            #Enable/Disable Query URL table for global script settings
$settingsURL = ""                                                      #URL for script settings table
$settingsTableName = "Global Script Settings"                          #Table to query for global enable/disable flags
$fallbackFlag = $false                                                 #If website or setting isnt found, fallback to these values
######################################################
$taskName = "Announcements"                                            #name of task to create
$taskPath = "Microscopy"                                               #task sub-folder to create                                                  
$scriptToRun = "runMe.vbs"                                             #launch vbs script required for easy task scheduler opening of powershell files
$atLogon = $true                                                       #run task once at user logon if true, else run every minute if false
$asSystem = $false                                                     #run task as system if true, else run as Users
$asAdmin = $false                                                      #if $true, run task with highest priveleges but as regular user
######################################################
