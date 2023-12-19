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
        Write-Output "An error occurred while logging off the user 'NC-KioskUser'."
    }
}
else {
    Write-Host "User 'NC-KioskUser' not found."
}

## Error > GoBright.Signage.Player not found 



Write-Output "Checking if the processes 'GoBright.Signage.Player' and 'GoBright.Signage.Player.Bootstrapper' are running..."
$processes = "GoBright.Signage.Player", "GoBright.Signage.Player.Bootstrapper"
if ($processes) {
    foreach ($process in $processes) {
        try { 
            Get-Process -Name $process -ErrorAction Stop | Stop-Process -Force
            Write-Output "Process '$process' stopped." 
        }
        catch [Microsoft.PowerShell.Commands.ProcessCommandException] { 
            Write-Output "$process not found" 
        } 
        catch { Write-Output "An error occurred: $($_.Exception.Message)" }
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
        Write-Output "An error occurred during the deletion of the folder '_dotnetbrowser-binaries'."
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
        Write-Output "An error occured while setting permissions on the folder 'C:\gobright-view\'"
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
    Write-Output "The Site may be down, please check."
}

$filePath = "C:\gobright-view\bootstrapper\GoBright.Signage.Player.Bootstrapper.exe"
if (Test-Path -Path $filePath) {
    Write-Output "Starting the GoBright.Signage.Player.Bootstrapper.exe..."
    Start-Process -WorkingDirectory "C:\gobright-view\bootstrapper\" -FilePath "GoBright.Signage.Player.Bootstrapper.exe"
}
else {
    Write-Output "File '$filePath' does not exist."
}

$delayInSeconds = 300  # 5 minutes in seconds
Write-Host "Restarting computer in $delayInSeconds seconds..."
try {
    Start-Sleep -Seconds $delayInSeconds
    Restart-Computer -Force
}
catch {
    Write-Output "An error occurred while restarting the computer."
}


