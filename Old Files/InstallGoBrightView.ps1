# #Check PowerShell Version
# $psversion = $PSVersionTable.PSVersion
# if ($psversion.Major -lt 5) 
# { 
#     Write-Output 'The PowerShell version must be at least Major 5, press any button to download the installer'
#     start 'https://www.microsoft.com/en-us/download/details.aspx?id=54616'
# 	Read-Host 'Press ENTER to exit'
#     exit
# }

# #Check is 64bit and stop if it is not
# if (-not [Environment]::Is64BitOperatingSystem)
# {
#     Write-Output 'GoBright View only supports 64-bit Windows, this Windows PC is not 64-bit and therefore not supported'
# 	Read-Host 'Press ENTER to exit'
# 	exit;
# }

# #Check windows version and change node enviroment variable when Windows 7 is found
# $osversion = [System.Environment]::OSVersion.Version
# if ($osversion.Major -lt 8) 
# {
#     Write-Host 'Setting environment variable for Node.js to run on Windows 7'
#     [System.Environment]::SetEnvironmentVariable('NODE_SKIP_PLATFORM_CHECK', 1, [System.EnvironmentVariableTarget]::Machine)
# }

# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
# $ErrorActionPreference="SilentlyContinue"
# Stop-Transcript | out-null
# $ErrorActionPreference = "Continue"
# Start-Transcript -path .\output.txt -append

# Write-Output 'Get destkop and startup folder'
# $startupFolder = [Environment]::GetFolderPath('Startup')
# $DesktopPath = [Environment]::GetFolderPath("Desktop")

Write-Output 'Install .NET Framework'
Enable-WindowsOptionalFeature -Online -FeatureName "NetFx3"
Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-NetFx3-OC-Package"
Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-NetFx3-WCF-OC-Package"
Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-NetFx4-US-OC-Package"
Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-NetFx4-WCF-US-OC-Package"

Write-Output 'Install Chrome'
$Path = $env:TEMP; $Installer = "chrome_installer.exe"; Invoke-WebRequest "http://dl.google.com/chrome/install/375.126/chrome_installer.exe" -OutFile $Path\$Installer; Start-Process -FilePath $Path\$Installer -Args "/silent /install" -Verb RunAs -Wait; Remove-Item $Path\$Installer

Write-Output 'Create the folders C:\gobright-view\temp and C:\gobright-view\bootstrapper'
New-Item -ItemType Directory -Force -Path C:\gobright-view\bootstrapper
New-Item -ItemType Directory -Force -Path C:\gobright-view\temp

# $installfolder = 'C:\gobright-view'
# $bootstrapperFolder = 'C:\gobright-view\bootstrapper'
# $tempFolder = 'C:\gobright-view\temp'

Write-Output 'Download the latest update and put it in the install folder'
$Url = 'http://install.gobright.cloud/view/windows/latest'
Invoke-WebRequest -Uri $Url -OutFile "C:\gobright-view\update.zip"

Write-Output 'Get the zipfile with all content'
$zipFile = $installfolder | Get-ChildItem | Where-Object Name -Match "update.zip"

Write-Output 'Extract zipfile to temp folder'
Expand-Archive -Path $zipfile.Fullname -DestinationPath $tempFolder

Write-Output 'Get bootstrapper zipfile'
$bootstrapperZipfile = $tempFolder | Get-ChildItem | Where-Object Name -Match "^bootstrapper.*"

Write-Output 'Extract zipfile in bootstrapper folder'
Expand-Archive -Path $bootstrapperZipfile.Fullname -DestinationPath $bootstrapperFolder

Write-Output 'Remove temp folder'
Remove-Item -LiteralPath $tempFolder -Force -Recurse





# Twee keer uitgevoerd worden. 1 keer op lokaal account en 1 keer admin account.
Write-Output 'Create shortcut in startup folder'
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($startupFolder + "\GoBright View.lnk")
$Shortcut.TargetPath = "C:\gobright-view\bootstrapper\GoBright.Signage.Player.Bootstrapper.exe"
$Shortcut.WorkingDirectory = $bootstrapperFolder
$Shortcut.Save()

Write-Output 'Copy shortcut to desktop'
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($DesktopPath + "\GoBright View.lnk")
$Shortcut.TargetPath = "C:\gobright-view\bootstrapper\GoBright.Signage.Player.Bootstrapper.exe"
$Shortcut.WorkingDirectory = $bootstrapperFolder
$Shortcut.Save()

Write-Output 'Starting GoBright View'
Start-Process -WorkingDirectory "C:\gobright-view\bootstrapper\" -FilePath "GoBright.Signage.Player.Bootstrapper.exe"

Write-Output 'GoBright View succesfully installed'
Read-Host 'Press any button to exit this script'
Stop-Transcript
exit