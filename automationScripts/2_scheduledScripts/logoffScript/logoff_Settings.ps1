#Configuration settings for logoff script

######################################################
#logging
$logRoot = "C:\scriptLogs"                                                #root path to store log files
$logToFile = 1                                                            #enable/disable (1/0) logging to file
$logToConsole = 1                                                         #enable/disable (1/0) logging to console
######################################################
#settings URL for global flag location
$getSettingsFromURLFlag = 1                                              #Enable/Disable Query URL table for global script settings
$settingsURL = ""                                                        #URL for script settings table
$settingsTableName = "Global Script Settings"                            #Table to query for global enable/disable flags
$fallbackFlag = $false                                                   #If website or setting isnt found, fallback to these values
######################################################
#Slack particulars
$SlackFlag = 0                                                           #should the script send a message to slack?
$uriSlack = ""
######################################################
#send messages to a Teams channel via a webhook
$TeamsFlag = 1
$webHook = ""
######################################################
$ppmsRegPath = "HKCU:\Software\Microscopy\PPMSscript"                     #path to registry values generated in ppmsConfig.ps1
$LMRegPath = "HKLM:\Software\Microscopy\PPMSscript"                       #local machine reg path
$LM_rootPath = "HKLM:\Software\Microscopy"                                #local machine reg path for shared settings
######################################################
$taskname = "ppmsLogoff"                                                  #name of task to create
$taskPath = "Microscopy"                                                  #task sub-folder to create
$scriptToRun = "runMe.vbs"                                                #launch vbs script required for easy task scheduler opening of powershell files
$atLogon = $false                                                         #run task once at user logon if true, else run every minute if false
$asSystem = $false                                                        #if $true, run task as system, else run as Users
$asAdmin = $false                                                         #if $true, run task with highest priveleges but as regular user
######################################################
