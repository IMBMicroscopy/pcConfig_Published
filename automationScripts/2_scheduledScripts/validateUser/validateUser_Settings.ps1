#script must be run as admin the first time after first download of code to install some features
#click on start menu, type "powershell" and right click on the "powershell ISE" app and "run as administrator"

######################################################
#email particulars
$emailFlag = 0                                                           #Send email notifications?                                                    
$emailToAdmin = ''                                                       #Define email account to send Incident reports to
$emailFrom = ''                                                          #Define email account in From address 
$emailSig = "Kind Regards,`r`n"+"Microscopy`r`n"                         #Define email signature
$secureEmailFlag = 1                                                     #Does email server require a username and password?
$emailUser = ''                                                          #Username for smtp account
$emailPass = ''                                                          #Password for smtp account
$smtpClient = ""                                                         #Define alternative email client
$emailPort = ""                                                          #Define port for email client
######################################################
#Slack particulars
$SlackFlag = 0                                                           #should the script send a message to slack?                                                        
$uriSlack = ""
$Title =  "Validate User script"
$channel = "equipment"
$icon = ":microscope:" 
$color = "#FFA500"  #orange
######################################################
#send messages to a Teams channel via a webhook
$TeamsFlag = 0                                                           #should the script send a message to Teams?
$webHook = ""
#####################################################
$LogoffTime = 60                                                         #How long in seconds should the popup windows stay on screen before logging off the user
$FontSize = 36                                                           #set font size of popup window
$adminPassword = ""                                                      #override password to prevent logoff, shift click on the logoff now button to display the password box
######################################################
$ppmsRegPath = "HKCU:\Software\Microscopy\PPMSscript"                    #path to registry values generated in ppmsConfig.ps1
$LM_rootPath = "HKLM:\Software\Microscopy"                               #local machine reg path for shared settings
######################################################
$taskname = "validateUser"                                               #name of task to create
$taskPath = "Microscopy"                                                 #task sub-folder to create
$scriptToRun = "runMe.vbs"                                               #launch vbs script required for easy task scheduler opening of powershell files
$atLogon = $true                                                         #run task once at user logon if true, else run every minute if false
$asSystem = $false                                                       #if $true, run task as system, else run as Users
$asAdmin = $false                                                         #if $true, run task with highest priveleges but as regular user
######################################################
#Enable/Disable logging
$logRoot = "C:\scriptLogs"                                               #root path to store log files
$logToFile = $true                                                       #enable/disable logging script output to file
$logToConsole = $true                                                    #enable/disable logging to console
######################################################
#settings URL for global flag location
$getSettingsFromURLFlag = 0                                              #Enable/Disable Query URL table for global script settings
$settingsURL = ""                                                        #URL for script settings
$settingsTableName = ""                                                  #Table to query for global enable/disable flags
$fallbackFlag = $true                                                    #If website or setting isnt found, fallback to these values
######################################################
$retries = 6                                                             #number of retries to check if ppmsConfig has run
$waitTime = 10                                                           #wait time in seconds between retries
######################################################
