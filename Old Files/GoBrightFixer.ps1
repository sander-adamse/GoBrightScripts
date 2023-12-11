function UpdateGoBright {
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

function FixGoBright {
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
}

do {
    Clear-Host
    Write-Host "=== Menu ==="
    Write-Host "Option 1. Update GoBright"
    Write-Host "Option 2. Fix GoBright"
    Write-Host ""
    Write-Host "Q. Quit"

    # Prompt the user for input
    $choice = Read-Host "Enter the number or 'Q' to quit"

    # Process the user's choice
    switch ($choice) {
        '1' { UpdateGoBright }
        '2' { FixGoBright }
        'Q' { break } # Exit the loop if 'Q' is selected
        default { Write-Host "Invalid choice. Please try again." }
    }

    # Pause to allow the user to read the output
    if ($choice -ne 'Q') {
        Read-Host "Press Enter to continue..."
    }

} while ($choice -ne 'Q')



