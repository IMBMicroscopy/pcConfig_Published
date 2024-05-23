#Configuration settings for PCconfig script

$rootName = "pcConfig"                                                    #root folder for all automation scripts, ie: c:/windows/pcConfig would be pcConfig
######################################################
#logging
$logRoot = "C:\scriptLogs"                                                #root path to store log files
$logToFile = 1                                                            #enable/disable (1/0) logging to file
$logToConsole = 1                                                         #enable/disable (1/0) logging to console
######################################################
$ppmsRegPath = "HKCU:\Software\Microscopy\PPMSscript"                     #current user reg path
$LM_rootPath = "HKLM:\Software\Microscopy"                                #local machine reg path for shared settings
######################################################