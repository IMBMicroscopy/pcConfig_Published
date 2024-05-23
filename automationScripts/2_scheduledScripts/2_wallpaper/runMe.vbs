' Enter the filename of the script to launch'
fileName = "installWallpaper.ps1"

Dim strPath, objFSO, objFile, strFolder, filePath, command, shell

'Determine full path of the script to launch'
strPath = Wscript.ScriptFullName

Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objFile = objFSO.GetFile(strPath)

strFolder = objFSO.GetParentFolderName(objFile) 
filePath = strFolder & "\" & fileName

'launch script'
command = "powershell.exe -windowstyle hidden -executionpolicy bypass -noninteractive -File " & chr(34) & filePath & chr(34)
Set shell = CreateObject("WScript.Shell")
shell.Run command,0