function CreateRandomPassword($length) {
    $characters = 'abcdefghiklmnoprstuvwxyzABCDEFGHKLMNOPRSTUVWXYZ1234567890!"$%&/()=?}][{@#+'
    $randomPassword = 1..$length | ForEach-Object { Get-Random -Maximum $characters.Length }
    $private:ofs = ""
    return [String]$characters[$randomPassword]
}

$password = CreateRandomPassword -length 20
Write-Output $password

if (!(Test-Path -Path 'C:\gobright-view')) {
    try {
        New-Item -ItemType Directory -Path 'C:\gobright-view' | Out-Null
        "$password `n" | Out-File 'C:\gobright-view\password.txt' -Append
    }
    catch {
        Write-Error "An error occurred while creating the folder 'C:\gobright-view'."
    }
}
else {
    "$password `n" | Out-File 'C:\gobright-view\password.txt' -Append
}

$SecurePassword = $password | ConvertTo-SecureString -AsPlainText -Force
$username = "NC-KioskUser"
$usergroup = "Gebruikers"

$checkUser = (Get-Localuser).name -contains $username -as [bool]
if (!$checkUser) {
    try {
        New-LocalUser $username -Password $SecurePassword -FullName $username -Description "$username - $password" -UserMayNotChangePassword -AccountNeverExpires -PasswordNeverExpires
    }
    catch {
        Write-Error "An error occurred while creating the user '$username'."
    }
}
else {
    try {
        Set-LocalUser $username -Password $SecurePassword -AccountNeverExpires -PasswordNeverExpires 1 -Description "$username - $password"
    }
    catch {
        Write-Error "An error occurred while setting the password for the user '$username'."
    }
}

$checkMembership = Get-LocalGroupMember -Group $usergroup | Where-Object { $_.Name -eq $env:computername + "\$username" }
if (!$checkMembership) {
    try {
        Add-LocalGroupMember -Group $usergroup -Member $username
    }
    catch {
        Write-Error "An error occurred while adding the user '$username' to the group $usergroup."
    }
    
}

$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

if (Test-Path -Path "$registryPath\AutoAdminLogon") {
    try {
        New-ItemProperty -Path $registryPath -Name "AutoAdminLogon" -Value 1 -PropertyType "DWord"
    }
    catch {
        Write-Error "An error occurred while creating the registry value 'AutoAdminLogon'."
    }
}
else {
    try {
        Set-ItemProperty -Path $registryPath -Name "AutoAdminLogon" -Value 1
    }
    catch {
        Write-Error "An error occurred while setting the registry value 'AutoAdminLogon'."
    }
}

if (Test-Path -Path "$registryPath\DefaultUserName") {
    try {
        New-ItemProperty -Path $registryPath -Name "DefaultUserName" -Value $username -PropertyType "String"
    }
    catch {
        Write-Error "An error occurred while creating the registry value 'DefaultUserName'."
    }
}
else {
    try {
        Set-ItemProperty -Path $registryPath -Name "DefaultUserName" -Value $username
    }
    catch {
        Write-Error "An error occurred while setting the registry value 'DefaultUserName'."
    }
}

if (Test-Path -Path "$registryPath\DefaultPassword") {
    try {
        New-ItemProperty -Path $registryPath -Name "DefaultPassword" -Value $password -PropertyType "String"
    }
    catch {
        Write-Error "An error occurred while creating the registry value 'DefaultPassword'."
    }
}
else {
    try {
        Set-ItemProperty -Path $registryPath -Name "DefaultPassword" -Value $password
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
