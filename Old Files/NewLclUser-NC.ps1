## Genereren Random Password + Aanmaken Autologon Account NarrowCasting
## Vullen registerwaarden Autologon NarrowCasting

function Get-RandomCharacters($length, $characters) {
    $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
    $private:ofs=""
    return [String]$characters[$random]
}
 
function Scramble-String([string]$inputString){     
    $characterArray = $inputString.ToCharArray()   
    $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length     
    $outputString = -join $scrambledStringArray
    return $outputString 
}
 
$password = Get-RandomCharacters -length 5 -characters 'abcdefghiklmnoprstuvwxyz'
$password += Get-RandomCharacters -length 5 -characters 'ABCDEFGHKLMNOPRSTUVWXYZ'
$password += Get-RandomCharacters -length 5 -characters '1234567890'
$password += Get-RandomCharacters -length 5 -characters '!"§$%&/()=?}][{@#*+'

$password = Scramble-String $password

## ======= Aanmaken/Resetten Local Autologon account =======

$SecurePassword = $password | ConvertTo-SecureString -AsPlainText -Force

    ## Indien het account al bestaat, wordt het password en registerwaarden identiek
Set-LocalUser "NC-KioskUser" -Password $SecurePassword -AccountNeverExpires -PasswordNeverExpires 1 -Description "NC-KioskUser - $password"
    ## Indien het account niet bestaat, wordt het aangemaakt
New-LocalUser "NC-KioskUser" -Password $SecurePassword -FullName "NC-KioskUser" -Description "NC-KioskUser - $password" -UserMayNotChangePassword -AccountNeverExpires -PasswordNeverExpires

Add-LocalGroupMember -Group "Gebruikers" -Member "NC-KioskUser"

## ======= Vullen RegisterWaarden Autologon =======

##Gezet via GPP## Set-Itemproperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 1
##Gezet via GPP## New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 1 -PropertyType "String"
##Gezet via GPP## Set-Itemproperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -Value "NC-KioskUser"
##Gezet via GPP## New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -Value "NC-KioskUser" -PropertyType "String"
Set-Itemproperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -value $password
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Value $password -PropertyType "String"
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultDomainName"