<#
freeHDD

Scan all logical drives attached to this PC and determine their available free space

Installation requirements:
    Win7 will require .NET 4.5 or higher and then WPF5.1 to be installed first, these should be included in the installation folder, or download them from the links below: 
    	https://www.microsoft.com/en-au/download/details.aspx?id=30653
    	https://www.microsoft.com/en-us/download/details.aspx?id=54616

You must enable Powershell script execution before running this script
    Press the Windows Start button and type Powershell_ISE, right click and "Run as Administrator"
    Copy the following line into the console then press Enter (You may choose to use Bypass or per script policies instead of Unrestricted)
    
	Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy Unrestricted -Force

#>

#$drives = Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed'}
$drives = Get-WmiObject Win32_LogicalDisk -Filter "DriveType='3'"
Foreach($drive in $drives){
    $used = $drive.size - $drive.freeSpace
    $freeSpace = [long]([long]$drive.FreeSpace/[long]$drive.Size*100) #calculate the disk free space in %
    write-output "$($drive.DeviceID) $([Math]::Round(($used/1GB),2))GB used of $([Math]::Round(($drive.Size/1GB),2))GB Capacity HDD = $freeSpace% free space available"
}
