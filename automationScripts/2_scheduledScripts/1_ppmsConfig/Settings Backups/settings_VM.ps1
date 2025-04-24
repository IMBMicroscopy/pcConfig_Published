#Configuration settings to obtain system and user details from ppms Server


## System Details  #########################################################################################
$autoDetect = 1                                                           #If enabled (1) find the name of the local PC and use it to search PPMS for name of instrument, otherwise ask the user to select from a list of ppms instruments
$ignore = ""                                                          #if the autodetected local PC name includes this string at the start of the name, remove it before searching ppms for the instrument name
######################################################
#PPMS Server details
$ppmsURL = ""                                                             #PPMS Server URL
$PF = "  "                                                                #Default PPMS Core ID.  Comment out or leave empty if you want to show a popup to select the Core.
$pumapiKey = ""                                                           #PUMAPI key, must have user management turned on, You will need to create this in PPMS
$apiKey = ""                                                              #API key, must have write mode turned on, You will need to create this in PPMS
$ppmsTimeout = 10                                                         #set timeout for ppms communications
$unbookedLoginReport =                                                    #report # to get current unbooked sessions on this system
$systemReport =                                                           #report # to get current list of ppms systems and their ID and Codes
$projectsForUserReport =                                                  #Define the report number to retrieve list of projects for user or sessionID
######################################################
#logging
$logRoot = "C:\scriptLogs"                                                #root path to store log files
$logToFile = 1                                                            #enable/disable (1/0) logging to file
$logToConsole = 1                                                         #enable/disable (1/0) logging to console
######################################################
#settings URL for global flag location
$getSettingsFromURLFlag = 1                                               #Enable/Disable Query URL table for global script settings
$settingsURL = ""                                                         #URL for script settings table
$settingsTableName = "Global Script Settings"                             #Table name to query for global enable/disable flags
$fallbackFlag = $true                                                     #If website or setting isnt found, fallback to these values
######################################################
$ppmsRegPath = "HKCU:\Software\Microscopy\PPMSscript"                     #current user reg path
$LMRegPath = "HKLM:\Software\Microscopy\PPMSscript"                       #local machine reg path
$LM_rootPath = "HKLM:\Software\Microscopy"                                #local machine reg path for shared settings
######################################################
$taskname = "ppmsConfig"                                                  #name of task to create
$taskPath = "Microscopy"                                                  #task sub-folder to create
$scriptToRun = "runMe.vbs"                                                #launch vbs script required for easy task scheduler opening of powershell files
$atLogon = $true                                                          #run task once at user logon if true, else run every minute if false
$asSystem = $false                                                        #run task as system if true, else run as Users
$asAdmin = $false                                                         #if $true, run task with highest priveleges but as regular user
######################################################




############################################################################################################
#Logoff Script settings
$ppmsFlag = 1                                                            #Is PPMS installed on the system? 1=Yes, 0=No
######################################################
$lastSessionFlag = 1                                                     #Show popup to warn current user if they are the last user on the system today, 1=Yes, 0=No, Only works if VMFlag = 0
$lastSessionWarning = 60                                                 #How long in minutes after current session to check if theres a next session, if value = "-1", then check until midnight, modify logoff popup as required
$VMFlag = 1                                                              #If value = 1 (True) then dont allow shutdown of PC
$logoffUserFlag = 1                                                      #If enabled automatic Logoff of the user will occur, if disabled, the popup will indicate how long past the users booking they have remained logged in
######################################################
#All PPMS Timer values in minutes
$AlertLong = 240                                                         #Value must be positive (-1 to disable). For bookings longer than 8hours, specify how many minutes before the end of their booking the dialog box appears to warn a user their booking is running out
$Alert8 = 60                                                             #Value must be positive (-1 to disable). For bookings less than or equal to 8hours, specify how many minutes before the end of their booking the dialog box appears to warn a user their booking is running out
$Alert3 = 30                                                             #Value must be positive (-1 to disable). For bookings less than or equal to 3hours, specify how many minutes before the end of their booking the dialog box appears to warn a user their booking is running out
$Alert1 = 15                                                             #Value must be positive (-1 to disable). For bookings less than or equal to 1hour, specify how many minutes before the end of their booking the dialog box appears to warn a user their booking is running out
$Timer = 10                                                              #Value must be positive. Specify how many minutes after the booking ends that the user is automatically logged off, also affects how long before a booking the user can stay logged in.
$maxGap = 15                                                             #Value must be positive. Specify the maximum gap between a single users two bookings so they arent logged off $Timer minutes after the first booking ends, probably just leave it at 15mins, which is the minimum booking in PPMS
$maxExtension = 60                                                       #Value must be positive. Specify the maximum number of minutes a user can extend/make a booking with the scripts extend booking button
$emailTimer = -15                                                        #Value must be less than $Timer and can be negative. Define when an email will be sent to the windows user, negative numbers indicate the email will be sent after the booking ends
$adminTimer = 480                                                        #Value must be positive. Define when an email will be sent to to the logged in Admin user to warn them they are still logged in.
$extendComment = "Extended Booking"                                      #Comment shown in PPMS when booking is extended 
#####################################################
#PPMS Flags for toggling modes (1=True/0=False)
$ignoreAdminFlag = 1                                                     #If enabled dont show popup or logoff admin user
$extendBookingFlag = 1                                                   #If enabled users have the ability to extend bookings from the script using the extend button, the button dissappears when disabled
$sameGroupFlag = 1                                                       #If enabled allow users from the same group to share bookings
$sameProjectFlag = 1                                                     #If enabled allow users who share a project to share bookings
$emailAdminFlag = 1                                                      #If enabled allow emails to Admins when they are logged in for more than $adminTimer, resends the email on multiples of $adminTimer
$pesterGoodFlag = 1                                                      #If enabled show the "Stop pestering me" button during a booking to allow users to prevent popups
$pesterBadFlag = 0                                                       #If enabled show the "Stop pestering me" button outside of a booking to allow users to prevent popups
$ignoreUserList = "Training,Workshop"                                    #Dont show alert window popups or auto-logoff if there's a booking from anyone in this list, this will still track logged in users, separate ppms usernames with commas - useful for running workshops on analysis VMs etc
######################################################
#web browser installed on windows Client PC                              #Select installed web browser
#$browser = "chrome"
$browser = "Firefox"
######################################################
#email particulars
$emailFrom = '                         '                                 #Define email account in From address 
$secureEmailFlag = 1                                                     #Does email server require a username and password?
$emailUser = ''                                                          #Username for smtp account
$emailPass = ''                                                          #Password for smtp account
$smtpClient = ""
######################################################
#PPMS Questionaire                                                       #Questionaire appears when users login
$QuestionFlag = 0                                                        #Questionaire enabled if true
$QuestionRandom = 1                                                      #Randomise how often the questions are asked if true
$QuestionOccurence = 2                                                   #Questionaire appears every nth login, If Random is false, If Random is true, a random number between 0 and $QuestionOccurence is generated and compared to Zero.
$QuestionDrive = ""                                                      #Network Drive to mount for Questionaire
$QuestionPath = ""                                                       #Path to Questionaire
######################################################
$cpRefresh = 60000                                                       #set refresh rate for control panel in milliseconds
######################################################
$screenWidth  = 500
$screenHeight = 500
######################################################
