function Startup {
    if ($PSVersionTable.PSVersion.Major -ge 5) {
        $currentVersion = $PSVersionTable.PSVersion.Major
        Write-Output "Required PowerShell version is 5. Current version is $currentVersion"
    }
    else {
        Write-Output "The PowerShell version must be at least version 5. Click here to download the supported version: https://www.microsoft.com/en-us/download/details.aspx?id=54616"
        Start-Process "https://www.microsoft.com/en-us/download/details.aspx?id=54616"
        Read-Host "Press ENTER to exit"
        Exit
    }

    if ([Environment]::Is64BitOperatingSystem) {
        Write-Output "GoBright View supports 64-bit Windows. The script will proceed."
    }
    else {
        Write-Output 'GoBright View requires 64-bit Windows. This Windows PC is not 64-bit and is not supported.'
        Read-Host 'Press ENTER to exit'
        exit
    }

    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -ge 10) {
        Write-Host "Current version of Windows is Windows $($osVersion.Major). Continuing with the script."
    }
    else {
        Write-Host 'Configuring Node.js for compatibility with Windows 7'
        [System.Environment]::SetEnvironmentVariable('NODE_SKIP_PLATFORM_CHECK', 1, [System.EnvironmentVariableTarget]::Machine)
        Write-Host 'Environment variable set successfully. Node.js can now run on Windows 7.'
    }

    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -ErrorAction Stop
    $ErrorActionPreference = "SilentlyContinue"
    $ErrorActionPreference = "Continue"
}

function Install-GoBright {
    $installfolder = 'C:\gobright-view'
    $bootstrapperFolder = 'C:\gobright-view\bootstrapper'
    $tempFolder = 'C:\gobright-view\temp'
    $startupFolder = [Environment]::GetFolderPath('Startup')
    $DesktopPath = [Environment]::GetFolderPath("Desktop")

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
    
    Write-Output 'Install Chrome'
    $Path = $env:TEMP; $Installer = "chrome_installer.exe"; Invoke-WebRequest "http://dl.google.com/chrome/install/375.126/chrome_installer.exe" -OutFile $Path\$Installer; Start-Process -FilePath $Path\$Installer -Args "/silent /install" -Verb RunAs -Wait; Remove-Item $Path\$Installer

    Write-Output 'Create the folders C:\gobright-view\temp and C:\gobright-view\bootstrapper'
    New-Item -ItemType Directory -Force -Path C:\gobright-view\bootstrapper
    New-Item -ItemType Directory -Force -Path C:\gobright-view\temp
    
    Write-Output 'Download the latest update and put it in the install folder'
    #URL to GoBright Installer | https://install.gobright.cloud/view/windows/?mode=download&version=5.8.9 ---> Current version used
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
}

function CreateRandomCharacters($length, $characters) {
    $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
    $private:ofs = ""
    return [String]$characters[$random]
}
 
function ScrambleString([string]$inputString) {     
    $characterArray = $inputString.ToCharArray()   
    $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length     
    $outputString = -join $scrambledStringArray
    return $outputString 
}
function NewLocalUser {
    $password = CreateRandomCharacters -length 5 -characters 'abcdefghiklmnoprstuvwxyz'
    $password += CreateRandomCharacters -length 5 -characters 'ABCDEFGHKLMNOPRSTUVWXYZ'
    $password += CreateRandomCharacters -length 5 -characters '1234567890'
    $password += CreateRandomCharacters -length 5 -characters '!"$%&/()=?}][{@#+'
    $password = ScrambleString $password
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
}

function CreateStartupFolder {
    $elevatedInput = Read-Host 'Are you running this with Administrator/Elevated privileges? (yes/no)'

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

    Write-Output 'Create shortcut in startup folder'
    $startupFolder = [Environment]::GetFolderPath('Startup')
    $bootstrapperFolder = 'C:\gobright-view\bootstrapper'
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($startupFolder + "\GoBright View.lnk")
    $Shortcut.TargetPath = "C:\gobright-view\bootstrapper\GoBright.Signage.Player.Bootstrapper.exe"
    $Shortcut.WorkingDirectory = $bootstrapperFolder
    $Shortcut.Save()
}

function UpdateGoBright {
    $sessionInfo = quser | Where-Object { $_ -match 'NC-KioskUser' }
    if ($sessionInfo) {
        $sessionId = $sessionInfo -split '\s+' | Select-Object -Index 2
        logoff $sessionId
    }
    else {
        Write-Host "User 'NC-KioskUser' not found."
    }

    try {
        $process = Get-Process -Name "GoBright.Signage.Player" -ErrorAction Stop
        $process | Stop-Process -Force

        $process = Get-Process -Name "GoBright.Signage.Player.Bootstrapper" -ErrorAction Stop
        $process | Stop-Process -Force
    }
    catch [Microsoft.PowerShell.Commands.ProcessCommandException] {
        Write-Host "$process not found" 
    }
    catch {
        Write-Host "An error occurred: $($_.Exception.Message)"
    }
    
    try {
        Start-Process powershell -Verb RunAs -ArgumentList "-Command Remove-Item -Path 'C:\Users\sande\Downloads\test' -Recurse -Force"
    }
    catch {
        Write-Output "An error occurred during the deletion of the folder '_dotnetbrowser-binaries'."
    }

    try {
        Import-Module -Name Microsoft.PowerShell.Security
    
        $folderPath = "C:\gobright-view\"
        $acl = Get-Acl -Path $folderPath
        $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule("Gebruikers", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.SetAccessRule($rule)
        Set-Acl -Path $folderPath -AclObject $acl
    }
    catch {
        Write-Output "An error occured while setting permissions on the folder 'C:\gobright-view\'"
    }

    Write-Output 'Downloading the latest update and put it in the install folder'
        
    #URL to GoBright Installer | https://install.gobright.cloud/view/windows/?mode=download&version=5.8.9 ---> Current version used
    $Url = 'http://install.gobright.cloud/view/windows/latest'
    
    Invoke-WebRequest -Uri $Url -OutFile "C:\gobright-view\download.zip"
    Rename-Item -Path "C:\gobright-view\download.zip" -NewName "C:\gobright-view\update.zip"
    Start-Process -WorkingDirectory "C:\gobright-view\bootstrapper\" -FilePath "GoBright.Signage.Player.Bootstrapper.exe"

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

Startup

do {
    Clear-Host
    Write-Host "=== Installer Menu ==="
    Write-Host "Option 1. Create Local-User"
    Write-Host "Option 2. Install Go-Bright View"
    Write-Host "Option 3. Create Startup Folder"
    Write-Host ""
    Write-Host "=== Updater Menu ==="
    Write-Host "Option 4. Update/Fix GoBright Installation"
    Write-Host ""
    Write-Host "Q. Quit"

    $choice = Read-Host "Enter the number or 'Q' to quit"

    switch ($choice) {
        '1' { NewLocalUser }
        '2' { Install-GoBright }
        '3' { CreateStartupFolder }
        '4' { UpdateGoBright }
        'Q' { break } # Exit the loop if 'Q' is selected
        default { Write-Host "Invalid choice. Please try again." }
    }

    if ($choice -ne 'Q') {
        Read-Host "Press Enter to continue..."
    }

} while ($choice -ne 'Q')