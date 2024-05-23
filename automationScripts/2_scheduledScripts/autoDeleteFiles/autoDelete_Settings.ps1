<#
autoDeleteFiles configuration file

Installation requirements:
    Win7 will require .NET 4.5 or higher and then WPF5.1 to be installed first, these should be included in the installation folder, or download them from the links below: 
    	https://www.microsoft.com/en-au/download/details.aspx?id=30653
    	https://www.microsoft.com/en-us/download/details.aspx?id=54616
#>


#Define the amount of free HDD space required in % (0% = no free space, 100% = empty drive)
#There must be a drive low and highTide key and value for each drive listed in $driveTable, however you dont need to comment out the low and high values
#if freeHDD is less than lowTide, begin deletion until freeHDD is greater than highTide
$lowTideTable = [ordered]@{
    C = 10
    D = 20
    E = 20
    F = 20
}

#must be equal to or larger than lowTide
$highTideTable = [ordered]@{
    C = 50
    D = 75
    E = 75
    F = 75
}

#Define the Drive/s and Root folder/s to Scan, #comment out unnecessary drives
$driveTable = [ordered]@{
    C = @("C:\Users\*\Desktop","C:\Users\*\Documents","C:\Users\*\Downloads","C:\Data") #Define the top level folder/s of the defined drive to scan for old files, Add as many comma separated values as required
    D = @("D:\") #Define the top level folder/s of the defined drive to scan for old files, Add as many comma separated values as required
    E = @("E:\") 
    F = @("F:\") 
}

#define name of drives to ignore (USB security keys typically), exact matches only
$excludeDriveNames = @("CODEMETER", "FLASH", "USB", "ALADDIN", "Sentinel HL") 


$enableDeletion = $true  #If enabled, files will be deleted, otherwise the script will log the files to delete, but not delete them

#Define the ordered Age and File size criteria for deletion
$ageThresholdArray = @(30,21,14,7,5) #Define the file age/s in days (> than this value will be deleted) for each successive deletion in order to reach $lowTide.  Add as many comma separated values as required
$sizeThresholdArray = @(500,100,10,1,0.1,0.01,0.001,0) #Define the file size/s in GB (> than this value will be deleted) for each successive deletion in order to reach $lowTide.

#Define the file types to delete
$deleteFilesFlag = $true #Enable/Disable the use of the $deleteTypes criteria, If enabled the script will only delete these file types below, if disabled the script will delete all files that arent defined in excludeFiles
$deleteTypes = @("*.ims*", "*.lif", "*.xllf", "*.xlef", "*.lof", "*.nd2", "*.czi", "*.tif*", "*.png", "*.jpg", "*.jpeg", "*.avi", "*.mov", "*.dv", "*.xls*","*.mp4", "*.txt", "*.sis", "*.sld", "*.oif", "*.oib", "*.oir", "*.vsi") #Define file types to delete, Add as many comma separated values as required 

#Define the file names and types to exclude from deletion
$excludeFilesFlag = $true #Enable/Disable the use of the $excludeFiles criteria
$excludeFiles = @("*.pdf", "*.ini", "*.dat*", "*.shm*") #If a file contains the defined strings it will not be deleted, Add as many comma separated values as required

#Define top level Paths to exclude from deletion
$excludePathFlag = $true #Enable/Disable the use of the $excludePaths criteria
$excludePaths = @("C:\Logs", "C:\scriptLogs", "c:\scopeConfig", "c:\Zen", "c:\Program Files", "C:\Program Files (x86)", "C:\Fiji.app", "c:\windows", "D:\Backups", "D:\Zeiss", "D:\Service", "D:\WindowsImageBackup") #Dont scan the valid real paths listed, ie: @("C:\Logs", "D:\Backups")  -dont use wildcards such as * in the path), Add as many comma separated values as required

######################################################
#Enable/Disable logging
$logRoot = "C:\scriptLogs"                                               #root path to store log files
$logtoFile = $true                                                       #enable/disable logging script output to file
$logToConsole = $true                                                    #enable/disable logging to console
######################################################
#settings URL for global flag location
$getSettingsFromURLFlag = 0                                              #Enable/Disable Query URL table for global script settings
$settingsURL = ""                                                        #URL for script settings
$settingsTableName = ""                                                  #Table to query for global enable/disable flags
$fallbackFlag = $false                                                   #If website or setting isnt found, fallback to these values
######################################################
#email particulars
$emailFlag = 0                                                           #should the script send a message via email?
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
######################################################
#send messages to a Teams channel via a webhook
$TeamsFlag = 0                                                           #should the script send a message to Teams?
$webHook = ""
######################################################
$ppmsRegPath = "HKCU:\Software\Microscopy\PPMSscript"                    #current user reg path
$autoDeleteRegPath = "HKLM:\Software\Microscopy\autoDelete"              #script specific reg path
$LM_rootPath = "HKLM:\Software\Microscopy"                               #local machine reg path for shared settings
######################################################
$taskname = "autoDeleteFiles" #name of task to create
$taskPath = "Microscopy" #task sub-folder to create
$scriptToRun = "runMe.vbs"                                                #launch vbs script required for easy task scheduler opening of powershell files
$atLogon = $true                                                          #run task once at user logon if true, else run every minute if false
$asSystem = $true                                                         #if $true, run task as system, else run as Users
$asAdmin = $false                                                         #if $true, run task with highest priveleges but as regular user