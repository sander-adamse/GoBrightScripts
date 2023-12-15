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

function doRestart($delay) {
    Write-Host "Restarting computer in $delay seconds..."
    try {
        Start-Sleep -Seconds $delay
        Restart-Computer -Force
    }
    catch {
        Write-Error "An error occurred while restarting the computer."
    }  
}

function CreateRandomPassword($length) {
    $characters = 'abcdefghiklmnoprstuvwxyzABCDEFGHKLMNOPRSTUVWXYZ1234567890!"$%&/()=?}][{@#+'
    $randomPassword = 1..$length | ForEach-Object { Get-Random -Maximum $characters.Length }
    $private:ofs = ""
    return [String]$characters[$randomPassword]
}

function NewLocalUser {    
    $password = CreateRandomPassword -length 20
    Write-Output "NC-KioskUser Password: $password"
    
    if (!(Test-Path -Path 'C:\gobright-view')) {
        try {
            New-Item -ItemType Directory -Path 'C:\gobright-view' | Out-Null
            "$password `n" | Out-File 'C:\gobright-view\password.txt' -Append
            Write-Output "Password saved to 'C:\gobright-view\password.txt'."
        }
        catch {
            Write-Error "An error occurred while creating the folder 'C:\gobright-view'."
        }
    }
    else {
        "$password `n" | Out-File 'C:\gobright-view\password.txt' -Append
        Write-Output "Password saved to 'C:\gobright-view\password.txt'."
    }
    
    $SecurePassword = $password | ConvertTo-SecureString -AsPlainText -Force
    $username = "NC-KioskUser"
    $usergroup = "Gebruikers"
    
    $checkUser = (Get-Localuser).name -contains $username -as [bool]
    if (!$checkUser) {
        try {
            New-LocalUser $username -Password $SecurePassword -FullName $username -Description "$username - $password" -UserMayNotChangePassword -AccountNeverExpires -PasswordNeverExpires
            Write-Output "User '$username' created."
        }
        catch {
            Write-Error "An error occurred while creating the user '$username'."
        }
    }
    else {
        try {
            Set-LocalUser $username -Password $SecurePassword -AccountNeverExpires -PasswordNeverExpires 1 -Description "$username - $password"
            Write-Output "Password for user '$username' set."
        }
        catch {
            Write-Error "An error occurred while setting the password for the user '$username'."
        }
    }
    
    $checkMembership = Get-LocalGroupMember -Group $usergroup | Where-Object { $_.Name -eq $env:computername + "\$username" }
    if (!$checkMembership) {
        try {
            Add-LocalGroupMember -Group $usergroup -Member $username
            Write-Output "User '$username' added to the group $usergroup."
        }
        catch {
            Write-Error "An error occurred while adding the user '$username' to the group $usergroup."
        }
        
    }
    
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    
    if (Test-Path -Path "$registryPath\AutoAdminLogon") {
        try {
            New-ItemProperty -Path $registryPath -Name "AutoAdminLogon" -Value 1 -PropertyType "DWord"
            Write-Output "Registry value 'AutoAdminLogon' created."
        }
        catch {
            Write-Error "An error occurred while creating the registry value 'AutoAdminLogon'."
        }
    }
    else {
        try {
            Set-ItemProperty -Path $registryPath -Name "AutoAdminLogon" -Value 1
            Write-Output "Registry value 'AutoAdminLogon' set."
        }
        catch {
            Write-Error "An error occurred while setting the registry value 'AutoAdminLogon'."
        }
    }
    
    if (Test-Path -Path "$registryPath\DefaultUserName") {
        try {
            New-ItemProperty -Path $registryPath -Name "DefaultUserName" -Value $username -PropertyType "String"
            Write-Output "Registry value 'DefaultUserName' created."
        }
        catch {
            Write-Error "An error occurred while creating the registry value 'DefaultUserName'."
        }
    }
    else {
        try {
            Set-ItemProperty -Path $registryPath -Name "DefaultUserName" -Value $username
            Write-Output "Registry value 'DefaultUserName' set."
        }
        catch {
            Write-Error "An error occurred while setting the registry value 'DefaultUserName'."
        }
    }
    
    if (Test-Path -Path "$registryPath\DefaultPassword") {
        try {
            New-ItemProperty -Path $registryPath -Name "DefaultPassword" -Value $password -PropertyType "String"
            Write-Output "Registry value 'DefaultPassword' created."
        }
        catch {
            Write-Error "An error occurred while creating the registry value 'DefaultPassword'."
        }
    }
    else {
        try {
            Set-ItemProperty -Path $registryPath -Name "DefaultPassword" -Value $password
            Write-Output "Registry value 'DefaultPassword' set."
        }
        catch {
            Write-Error "An error occurred while setting the registry value 'DefaultPassword'."
        }
    }
    
    # DefaultDomainName
    if (Test-Path -Path "$registryPath\DefaultDomainName") {
        try {
            Remove-ItemProperty -Path $registryPath -Name "DefaultDomainName"
            Write-Output "Registry value 'DefaultDomainName' removed."
        }
        catch {
            Write-Error "An error occurred while removing the registry value 'DefaultDomainName'."
        }
    }
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
        Write-Error "An error occurred during the installation of .NET Framework."
    }
    
    Write-Output 'Install Chrome'
    $Path = $env:TEMP; $Installer = "chrome_installer.exe"; Invoke-WebRequest "http://dl.google.com/chrome/install/375.126/chrome_installer.exe" -OutFile $Path\$Installer; Start-Process -FilePath $Path\$Installer -Args "/silent /install" -Verb RunAs -Wait; Remove-Item $Path\$Installer

    Write-Output 'Create the folders C:\gobright-view\temp and C:\gobright-view\bootstrapper'
    New-Item -ItemType Directory -Force -Path C:\gobright-view\bootstrapper
    New-Item -ItemType Directory -Force -Path C:\gobright-view\temp
    
    Write-Output "Downloading the latest update and installing in $installfolder"
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

function UpdateGoBright {
    Import-Module -Name Microsoft.PowerShell.Security

    Write-Output "Checking if the user 'NC-KioskUser' is logged in..."
    $sessionInfo = quser | Where-Object { $_ -match 'NC-KioskUser' }
    if ($sessionInfo) {
        try {
            $sessionId = $sessionInfo -split '\s+' | Select-Object -Index 2
            logoff $sessionId
            Write-Output "User 'NC-KioskUser' logged off."
        }
        catch {
            Write-Error "An error occurred while logging off the user 'NC-KioskUser'."
        }
    }
    else {
        Write-Host "User 'NC-KioskUser' not found."
    }
    
    Write-Output "Checking if the processes 'GoBright.Signage.Player' and 'GoBright.Signage.Player.Bootstrapper' are running..."
    $processes = "GoBright.Signage.Player", "GoBright.Signage.Player.Bootstrapper"
    if ($processes) {
        foreach ($process in $processes) {
            try { 
                Get-Process -Name $process -ErrorAction Stop | Stop-Process -Force
                Write-Output "Process '$process' stopped." 
            }
            catch [Microsoft.PowerShell.Commands.ProcessCommandException] { 
                Write-Error "$process not found" 
            } 
            catch { Write-Error "An error occurred: $($_.Exception.Message)" }
        }
    }
    
    Write-Output "Checking if the folder '_dotnetbrowser-binaries' exists..."
    $folderPath = "C:\gobright-view\_dotnetbrowser-binaries"
    if (Test-Path -Path $folderPath) {
        try {
            Start-Process powershell -Verb RunAs -ArgumentList "-Command Remove-Item -Path '$folderPath' -Recurse -Force"
            Write-Output "Folder '$folderPath' deleted."
        }
        catch {
            Write-Error "An error occurred during the deletion of the folder '_dotnetbrowser-binaries'."
        }
    }
    else {
        Write-Host "Folder '$folderPath' does not exist."
    }
    
    Write-Output "Checking if the folder 'C:\gobright-view\' exists..."
    $folderPath = "C:\gobright-view\"
    if (Test-Path -Path $folderPath) {
        try {
            $acl = Get-Acl -Path $folderPath
            $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule("Gebruikers", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $acl.SetAccessRule($rule)
            Set-Acl -Path $folderPath -AclObject $acl
            Write-Output "Permissions set on folder '$folderPath'."
        }
        catch {
            Write-Error "An error occured while setting permissions on the folder 'C:\gobright-view\'"
        }
    }
    else {
        Write-Host "Folder '$folderPath' does not exist."
    }
    
    $HTTP_Request = [System.Net.WebRequest]::Create('http://install.gobright.cloud/view/windows/latest')
    $HTTP_Response = $HTTP_Request.GetResponse()
    $HTTP_Status = [int]$HTTP_Response.StatusCode
    
    if ($HTTP_Status -eq 200) {
        #URL to GoBright Installer | https://install.gobright.cloud/view/windows/?mode=download&version=5.8.9 ---> Current version used
        Write-Output 'Downloading the latest update and put it in the install folder' 
        $Url = 'http://install.gobright.cloud/view/windows/latest'
        Invoke-WebRequest -Uri $Url -OutFile "C:\gobright-view\download.zip"
        Rename-Item -Path "C:\gobright-view\download.zip" -NewName "C:\gobright-view\update.zip"
    
        If ($HTTP_Response -eq $null) { } 
        Else { $HTTP_Response.Close() }
    }
    else {
        Write-Error "The Site may be down, please check."
    }
    
    $filePath = "C:\gobright-view\bootstrapper\GoBright.Signage.Player.Bootstrapper.exe"
    if (Test-Path -Path $filePath) {
        Write-Output "Starting the GoBright.Signage.Player.Bootstrapper.exe..."
        Start-Process -WorkingDirectory "C:\gobright-view\bootstrapper\" -FilePath "GoBright.Signage.Player.Bootstrapper.exe"
    }
    else {
        Write-Error "File '$filePath' does not exist."
    }
    
    $delayInSeconds = 300  # 5 minutes in seconds
    Write-Host "Restarting computer in $delayInSeconds seconds..."
    try {
        Start-Sleep -Seconds $delayInSeconds
        Restart-Computer -Force
    }
    catch {
        Write-Error "An error occurred while restarting the computer."
    }    
}

function RestartNUC {
    doRestart -delay 1
}

Startup

do {
    Clear-Host
    Write-Host "=== Installer Menu ==="
    Write-Host "Option 1. Create Local-User"
    Write-Host "Option 2. Install Go-Bright View"
    Write-Host "Option 3. Create Startup Folder"
    Write-Host "Option 4. Restart Computer"
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
        '5' { RestartNUC }
        'Q' { break } # Exit the loop if 'Q' is selected
        default { Write-Host "Invalid choice. Please try again." }
    }

    if ($choice -ne 'Q') {
        Read-Host "Press Enter to continue..."
    }

} while ($choice -ne 'Q')