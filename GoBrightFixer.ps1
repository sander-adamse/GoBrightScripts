#Checking if Powershell version is 5 or greater
if ($PSVersionTable.PSVersion.Major -ge 5) {
    # Display a message if the condition is true
    $currentVersion = $PSVersionTable.PSVersion.Major
    Write-Output "Required PowerShell version is 5. Current version is $currentVersion"
}

else {
    # Display a message if Powershell version is not equal or greater than 5.
    Write-Output "The PowerShell version must be at least version 5. Click here to download the supported version: https://www.microsoft.com/en-us/download/details.aspx?id=54616"

    # Open a URL in the default web browser to download Windows Management Framework 5.1.
    Start-Process "https://www.microsoft.com/en-us/download/details.aspx?id=54616"

    # Prompt the user to press Enter to exit the script
    Read-Host "Press ENTER to exit"

    # Exit the script
    Exit
}

# Check if the operating system is 64-bit; proceed if true
if ([Environment]::Is64BitOperatingSystem) {
    # Display a message if the condition is true
    Write-Output "GoBright View supports 64-bit Windows. The script will proceed."
}
else {
    # Display a message if the condition is false
    Write-Output 'GoBright View requires 64-bit Windows. This Windows PC is not 64-bit and is not supported.'
    
    # Prompt the user to press Enter to exit the script
    Read-Host 'Press ENTER to exit'
    
    # Exit the script
    exit
}

# Retrieve the operating system version
$osVersion = [System.Environment]::OSVersion.Version

# Check if the operating system is Windows 10 or higher
if ($osVersion.Major -ge 10) {
    # Output a message indicating that the current version is Windows 10 or 11
    Write-Host "Current version of Windows is Windows $($osVersion.Major). Continuing with the script."
}
else {
    # Inform the user about setting an environment variable for Node.js on Windows 7
    Write-Host 'Configuring Node.js for compatibility with Windows 7'

    # Set the environment variable 'NODE_SKIP_PLATFORM_CHECK' to 1 for Node.js
    [System.Environment]::SetEnvironmentVariable('NODE_SKIP_PLATFORM_CHECK', 1, [System.EnvironmentVariableTarget]::Machine)

    # Provide feedback to the user
    Write-Host 'Environment variable set successfully. Node.js can now run on Windows 7.'
}

try {
    # Set the execution policy for PowerShell scripts on the local machine to "RemoteSigned"
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -ErrorAction Stop
}
catch {
    Write-Error "Failed to set execution policy. Please run this script as an administrator."
    exit 1
}

# Temporarily suppress error messages during script execution
$ErrorActionPreference = "SilentlyContinue"

# Restore the default behavior of displaying error messages
$ErrorActionPreference = "Continue"

function Install-GoBright {
    # Start a new transcript, appending to an output file named "output.txt"
    Start-Transcript -Path .\output.txt -Append

    # Define installation and temporary folders
    $installfolder = 'C:\gobright-view'
    $bootstrapperFolder = 'C:\gobright-view\bootstrapper'
    $tempFolder = 'C:\gobright-view\temp'
    $startupFolder = [Environment]::GetFolderPath('Startup')
    $DesktopPath = [Environment]::GetFolderPath("Desktop")

    # Install .NET Framework features
    Write-Output 'Installing .NET Framework'
    try {
        Enable-WindowsOptionalFeature -Online -FeatureName "NetFx3"
        Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-NetFx3-OC-Package"
        Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-NetFx3-WCF-OC-Package"
        Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-NetFx4-US-OC-Package"
        Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-NetFx4-WCF-US-OC-Package"
    }
    catch {
        Write-Output "An error occurred during the installation of .NET Framework."
    }
    
    # Install Chrome
    Write-Output 'Install Chrome'
    $Path = $env:TEMP; $Installer = "chrome_installer.exe"; Invoke-WebRequest "http://dl.google.com/chrome/install/375.126/chrome_installer.exe" -OutFile $Path\$Installer; Start-Process -FilePath $Path\$Installer -Args "/silent /install" -Verb RunAs -Wait; Remove-Item $Path\$Installer

    # Create necessary folders
    Write-Output 'Create the folders C:\gobright-view\temp and C:\gobright-view\bootstrapper'
    New-Item -ItemType Directory -Force -Path C:\gobright-view\bootstrapper
    New-Item -ItemType Directory -Force -Path C:\gobright-view\temp
    
    # Download the latest update from GoBright
    Write-Output 'Download the latest update and put it in the install folder'
    #URL to GoBright Installer | https://install.gobright.cloud/view/windows/?mode=download&version=5.8.9 ---> Current version used
    $Url = 'http://install.gobright.cloud/view/windows/latest'
    Invoke-WebRequest -Uri $Url -OutFile "C:\gobright-view\update.zip"
    
    # Extract the update to the temporary folder
    Write-Output 'Get the zipfile with all content'
    $zipFile = $installfolder | Get-ChildItem | Where-Object Name -Match "update.zip"
    Write-Output 'Extract zipfile to temp folder'
    Expand-Archive -Path $zipfile.Fullname -DestinationPath $tempFolder

    # Get and extract the bootstrapper zipfile
    Write-Output 'Get bootstrapper zipfile'
    $bootstrapperZipfile = $tempFolder | Get-ChildItem | Where-Object Name -Match "^bootstrapper.*"
    Write-Output 'Extract zipfile in bootstrapper folder'
    Expand-Archive -Path $bootstrapperZipfile.Fullname -DestinationPath $bootstrapperFolder

    # Remove the temporary folder
    Write-Output 'Remove temp folder'
    Remove-Item -LiteralPath $tempFolder -Force -Recurse

    # Create shortcut in startup folder
    Write-Output 'Create shortcut in startup folder'
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($startupFolder + "\GoBright View.lnk")
    $Shortcut.TargetPath = "C:\gobright-view\bootstrapper\GoBright.Signage.Player.Bootstrapper.exe"
    $Shortcut.WorkingDirectory = $bootstrapperFolder
    $Shortcut.Save()

    # Copy shortcut to desktop
    Write-Output 'Copy shortcut to desktop'
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($DesktopPath + "\GoBright View.lnk")
    $Shortcut.TargetPath = "C:\gobright-view\bootstrapper\GoBright.Signage.Player.Bootstrapper.exe"
    $Shortcut.WorkingDirectory = $bootstrapperFolder
    $Shortcut.Save()

    # Start GoBright View
    Write-Output 'Starting GoBright View'
    Start-Process -WorkingDirectory "C:\gobright-view\bootstrapper\" -FilePath "GoBright.Signage.Player.Bootstrapper.exe"

    # Stop the transcript logging, discarding the output
    Stop-Transcript | Out-Null
}
function NewLocalUser {
    # Start a new transcript, appending to an output file named "output.txt"
    Start-Transcript -Path .\output.txt -Append
    
    $password = GetRandomCharacters -length 20 -characters 'abcdefghiklmnoprstuvwxyzABCDEFGHKLMNOPRSTUVWXYZ1234567890!"$%&/()=?}][{@#*+'
    "$password `n" | Out-File .\password.txt -Append

    $SecurePassword = $password | ConvertTo-SecureString -AsPlainText -Force
    Set-LocalUser "NC-KioskUser" -Password $SecurePassword -AccountNeverExpires -PasswordNeverExpires 1 -Description "NC-KioskUser - $password"
    New-LocalUser "NC-KioskUser" -Password $SecurePassword -FullName "NC-KioskUser" -Description "NC-KioskUser - $password" -UserMayNotChangePassword -AccountNeverExpires -PasswordNeverExpires
    Add-LocalGroupMember -Group "Gebruikers" -Member "NC-KioskUser"

    ##Gezet via GPP## Set-Itemproperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 1
    ##Gezet via GPP## New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 1 -PropertyType "String"
    ##Gezet via GPP## Set-Itemproperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -Value "NC-KioskUser"
    ##Gezet via GPP## New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -Value "NC-KioskUser" -PropertyType "String"
    Set-Itemproperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -value $password
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Value $password -PropertyType "String"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultDomainName"

    # Stop the transcript logging, discarding the output
    Stop-Transcript | Out-Null
}

function CreateStartupFolder {
    # Start a new transcript, appending to an output file named "output.txt"
    Start-Transcript -Path .\output.txt -Append

    # Prompt the user for elevated privileges
    $elevatedInput = Read-Host 'Are you running this with Administrator/Elevated privileges? (yes/no)'

    # Check user's response
    if ($elevatedInput -eq 'yes') {
        Write-Output 'Script ended. Please run this function WITHOUT Administrator/Elevated privileges'
        return
    }
    elseif ($elevatedInput -eq 'no') {
        Write-Output 'Continuing with the script.'
    }
    else {
        Write-Output 'Invalid input. Please enter "yes" or "no". Script ended.'
        return
    }

    # Rest of your code
    Write-Output 'Create shortcut in startup folder'
    $startupFolder = [Environment]::GetFolderPath('Startup')
    $bootstrapperFolder = 'C:\gobright-view\bootstrapper'
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($startupFolder + "\GoBright View.lnk")
    $Shortcut.TargetPath = "C:\gobright-view\bootstrapper\GoBright.Signage.Player.Bootstrapper.exe"
    $Shortcut.WorkingDirectory = $bootstrapperFolder
    $Shortcut.Save()

    # Stop the transcript logging, discarding the output
    Stop-Transcript | Out-Null
}

function UpdateGoBright {
    # Start a new transcript, appending to an output file named "output.txt"
    Start-Transcript -Path .\output.txt -Append

    try {
        # Try to get the process named "GoBright"; if not found, throw a terminating error
        $process = Get-Process -Name "GoBright" -ErrorAction Stop
        # If the process is found, stop it forcefully
        $process | Stop-Process -Force
    }
    catch [Microsoft.PowerShell.Commands.ProcessCommandException] {
        # Catch the specific exception when the process is not found
        Write-Host "$process not found"
    }
    catch {
        # Catch any other exceptions that may occur
        Write-Host "An error occurred: $($_.Exception.Message)"
    }
    
    # Download the latest update from GoBright
    Write-Output 'Download the latest update and put it in the install folder'
        
    #URL to GoBright Installer | https://install.gobright.cloud/view/windows/?mode=download&version=5.8.9 ---> Current version used
    $Url = 'http://install.gobright.cloud/view/windows/latest'
    
    # Download the update and save it as "download.zip" in the specified folder
    Invoke-WebRequest -Uri $Url -OutFile "C:\gobright-view\download.zip"
    
    # Rename the downloaded file to "update.zip"
    Rename-Item -Path "C:\gobright-view\download.zip" -NewName "C:\gobright-view\update.zip"

    # Start Bootstrapper process
    Start-Process -FilePath "GoBright Bootstrap" -WorkingDirectory "C:\gobright-view\bootstrapper"

    # Stop the transcript logging, discarding the output
    Stop-Transcript | Out-Null

    # Prompt the user to restart the computer
    do {
        $restartChoice = Read-Host "Restart your computer now? (Y/N)"
        switch ($restartChoice.ToLower()) {
            'y' {
                Restart-Computer -Force
                break
            }
            'n' {
                Write-Host "No restart. Please restart manually if needed."
                break
            }
            default {
                Write-Host "Invalid choice. Please select Y or N."
            }
        }
    } while ($restartChoice -notin @('y', 'n'))

    
}


# WIP WIP WIP 
function FixGoBright {
    # Start a new transcript, appending to an output file named "output.txt"
    Start-Transcript -Path .\output.txt -Append
    
    try {
        # Try to get the process named "GoBright"; if not found, throw a terminating error
        $process = Get-Process -Name "GoBright" -ErrorAction Stop
        # If the process is found, stop it forcefully
        $process | Stop-Process -Force
    }
    catch [Microsoft.PowerShell.Commands.ProcessCommandException] {
        # Catch the specific exception when the process is not found
        Write-Host "$process not found"
    }
    catch {
        # Catch any other exceptions that may occur
        Write-Host "An error occurred: $($_.Exception.Message)"
    }

    # Change permissions of parent folder
    # Delete binary folder
    # Start process

    # Stop the transcript logging, discarding the output
    Stop-Transcript | Out-Null

    # Restart computer
}

# Display the menu
do {
    Clear-Host
    Write-Host "=== Installer Menu ==="
    Write-Host "Option 1. Create Local-User"
    Write-Host "Option 2. Install Go-Bright View"
    Write-Host "Option 3. Create Startup Folder"
    Write-Host ""
    Write-Host "=== Updater Menu ==="
    Write-Host "Option 4. Update GoBright Installation"
    Write-Host "Option 5. Fix GoBright Installation"
    Write-Host ""
    Write-Host "Q. Quit"

    # Prompt the user for input
    $choice = Read-Host "Enter the number or 'Q' to quit"

    # Process the user's choice
    switch ($choice) {
        '1' { NewLocalUser }
        '2' { Install-GoBright }
        '3' { CreateStartupFolder }
        '4' { UpdateGoBright }
        '5' { FixGoBright }
        'Q' { break } # Exit the loop if 'Q' is selected
        default { Write-Host "Invalid choice. Please try again." }
    }

    # Pause to allow the user to read the output
    if ($choice -ne 'Q') {
        Read-Host "Press Enter to continue..."
    }

} while ($choice -ne 'Q')





