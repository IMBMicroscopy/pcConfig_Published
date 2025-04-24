#Configuration settings for wallpaper script

######################################################
$wallpaperName = "ScopePCs"                                               #if not empty, then search and use this image if it exists, else try the PCname, else ask the user for a suitable image.
$forceStyle = 1                                                           #dont prompt user to choose a wallpaper style if true, ie: fit, fill, stretch etc.
$wallpaperStyle = 10                                                      #if $forceStyle = true, apply this style and dont show popup to user.
$wallpaperStyleName = "Fill"                                              #name of wallpaper style to match number
<#
    "Fit" {$wallpaperStyle = "6"}
    "Fill" {$wallpaperStyle = "10"}
    "Stretch" {$wallpaperStyle = "2"}
    "Center" {$wallpaperStyle = "0"}
    "Span" {$wallpaperStyle = "22"}
    "No Wallpaper" {$wallpaperStyle = "none"}
#>
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
$fallbackFlag = $true                                                    #If website or setting isnt found, fallback to these values
######################################################
$ppmsRegPath = "HKCU:\Software\Microscopy\PPMSscript"                     #current user reg path
$wallpaperRegPath = "HKLM:\Software\Microscopy\wallpaper"                 #script specific reg path
$LM_rootPath = "HKLM:\Software\Microscopy"                                #local machine reg path for shared settings
######################################################
$taskname = "wallpaper"                                                   #name of task to create
$taskPath = "Microscopy"                                                  #task sub-folder to create
$scriptToRun = "runMe.vbs"                                                #launch vbs script required for easy task scheduler opening of powershell files
$atLogon = $true                                                          #run task once at user logon if true, else run every minute if false
$asSystem = $false                                                        #run task as system if true, else run as Users
$asAdmin = $false                                                         #if $true, run task with highest priveleges but as regular user
######################################################
