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

$delayInSeconds = 300  # 5 minutes in seconds
Write-Host "Restarting computer in $delayInSeconds seconds..."
Start-Sleep -Seconds $delayInSeconds
Restart-Computer -Force