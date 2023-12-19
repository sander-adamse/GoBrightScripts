function CreateRandomPassword($length) {
    $characters = 'abcdefghiklmnoprstuvwxyzABCDEFGHKLMNOPRSTUVWXYZ1234567890!"$%&/()=?}][{@#+'
    $randomPassword = 1..$length | ForEach-Object { Get-Random -Maximum $characters.Length }
    $private:ofs = ""
    return [String]$characters[$randomPassword]
}

$password = CreateRandomPassword -length 20
Write-Output "NC-KioskUser Password: $password"

if (!(Test-Path -Path 'C:\gobright-view')) {
    try {
        New-Item -ItemType Directory -Path 'C:\gobright-view' | Out-Null
        "$password `n" | Out-File 'C:\gobright-view\password.txt' -Append
        Write-Output "Password saved to 'C:\gobright-view\password.txt'."
    }
    catch {
        Write-Output "An error occurred while creating the folder 'C:\gobright-view'."
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
        Write-Output "An error occurred while creating the user '$username'."
    }
}
else {
    try {
        Set-LocalUser $username -Password $SecurePassword -AccountNeverExpires -PasswordNeverExpires 1 -Description "$username - $password"
        Write-Output "Password for user '$username' set."
    }
    catch {
        Write-Output "An error occurred while setting the password for the user '$username'."
    }
}

$checkMembership = Get-LocalGroupMember -Group $usergroup | Where-Object { $_.Name -eq $env:computername + "\$username" }
if (!$checkMembership) {
    try {
        Add-LocalGroupMember -Group $usergroup -Member $username
        Write-Output "User '$username' added to the group $usergroup."
    }
    catch {
        Write-Output "An error occurred while adding the user '$username' to the group $usergroup."
    }
    
}

$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

if (Test-Path -Path "$registryPath\AutoAdminLogon") {
    try {
        New-ItemProperty -Path $registryPath -Name "AutoAdminLogon" -Value 1 -PropertyType "DWord"
        Write-Output "Registry value 'AutoAdminLogon' created."
    }
    catch {
        Write-Output "An error occurred while creating the registry value 'AutoAdminLogon'."
    }
}
else {
    try {
        Set-ItemProperty -Path $registryPath -Name "AutoAdminLogon" -Value 1
        Write-Output "Registry value 'AutoAdminLogon' set."
    }
    catch {
        Write-Output "An error occurred while setting the registry value 'AutoAdminLogon'."
    }
}

if (Test-Path -Path "$registryPath\DefaultUserName") {
    try {
        New-ItemProperty -Path $registryPath -Name "DefaultUserName" -Value $username -PropertyType "String"
        Write-Output "Registry value 'DefaultUserName' created."
    }
    catch {
        Write-Output "An error occurred while creating the registry value 'DefaultUserName'."
    }
}
else {
    try {
        Set-ItemProperty -Path $registryPath -Name "DefaultUserName" -Value $username
        Write-Output "Registry value 'DefaultUserName' set."
    }
    catch {
        Write-Output "An error occurred while setting the registry value 'DefaultUserName'."
    }
}

if (Test-Path -Path "$registryPath\DefaultPassword") {
    try {
        New-ItemProperty -Path $registryPath -Name "DefaultPassword" -Value $password -PropertyType "String"
        Write-Output "Registry value 'DefaultPassword' created."
    }
    catch {
        Write-Output "An error occurred while creating the registry value 'DefaultPassword'."
    }
}
else {
    try {
        Set-ItemProperty -Path $registryPath -Name "DefaultPassword" -Value $password
        Write-Output "Registry value 'DefaultPassword' set."
    }
    catch {
        Write-Output "An error occurred while setting the registry value 'DefaultPassword'."
    }
}

# DefaultDomainName
if (Test-Path -Path "$registryPath\DefaultDomainName") {
    try {
        Remove-ItemProperty -Path $registryPath -Name "DefaultDomainName"
        Write-Output "Registry value 'DefaultDomainName' removed."
    }
    catch {
        Write-Output "An error occurred while removing the registry value 'DefaultDomainName'."
    }
}

$delayInSeconds = 60  # 1 minutes in seconds
Write-Host "Restarting computer in $delayInSeconds seconds..."
try {
    Start-Sleep -Seconds $delayInSeconds
    Restart-Computer -Force
}
catch {
    Write-Output "An error occurred while restarting the computer."
}
