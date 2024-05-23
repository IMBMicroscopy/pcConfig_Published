#Configuration settings for control Panel

######################################################
#logging
$logroot = "C:\scriptLogs"
$logToFile = 1                                                            #enable/disable (1/0) logging to file
$logToConsole = 1                                                         #enable/disable (1/0) logging to console
######################################################
#settings URL for global flag location
$getSettingsFromURLFlag = 0                                              #Enable/Disable Query URL table for global script settings
$settingsURL = ""                                                        #URL for script settings
$settingsTableName = ""                                                  #Table to query for global enable/disable flags
$fallbackFlag = $false                                                   #If website or setting isnt found, fallback to these values
######################################################
#Slack particulars
$SlackFlag = 0                                                           #should the script send a message to slack?
$uriSlack = ""
######################################################
#send messages to a Teams channel via a webhook
$TeamsFlag = 1                                                           #should the script send a message to slack?
$webHook = ""
######################################################
$ppmsRegPath = "HKCU:\Software\Microscopy\PPMSscript"                     #current user reg path
$LM_rootPath = "HKLM:\Software\Microscopy"
######################################################
$taskName = "controlPanel"                                                #name of task to create
$taskPath = "Microscopy"                                                  #task sub-folder to create
$scriptToRun = "runMe.vbs"                                                #launch vbs script required for easy task scheduler opening of powershell files
$atLogon = $true                                                          #run task once at user logon if true, else run every minute if false
$asSystem = $false                                                        #if $true, run task as system, else run as Users
$asAdmin = $false                                                         #if $true, run task with highest priveleges but as regular user
######################################################
