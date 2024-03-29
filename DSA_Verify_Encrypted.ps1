<#
    -Script should run from service account on machine with SED Client installed.
    -Service Account's PGP Client will need either:
        A) Group Keys for all group folders added 
        B) Service Account will need to be added to all AD SGs for encrypted folders
        C) Service Account can be manually added to any groups within SEMS
    -Service Account will also need NTFS permissions to read/write any encrypted folder directories and temp dir. 
    -Add all group key encrypted folders you want to check to pgpfolders.txt in same directory as DSA_Verify_PGPNetshare.ps1
        If folders contain spaces they must be sandwiched in double quotes
        subfolders and files within the parent folders can contain spaces with no issues
    -Script uses pgpnetshare.exe to check if files and folders within are encrypted or not. 
        If unencrypted, copies files out then back in to re-encrypt with group key of folder
    
#>
function SearchForUnencrypted
{
    $CurrentDate = Get-Date -Format yyyyMMdd
    #Folder this script is stored in
    $Script_Path = "C:\scripts\PGP_Reencrypt\"
    $VerifyLogFile = $Script_Path + $CurrentDate + "_Encryption.txt"
    #pgpfolders.txt file stored in script folder, contains locations of all encrypted folders to scan.
    $aryPGP_Folder = Get-Content ($Script_Path + "pgpfolders.txt")
    #Appends all files and folders processed to YYYYMMDD_PGP_Rencrypt.log for review
    $Logfile = $Script_Path + $CurrentDate + "_PGP_Reencrypt.log"
    $FolderFlag = ""
    $newline = "`r`n"

    foreach ($PGP_Folder in $aryPGP_Folder)
    {
        #Run pgpnetshare.exe to find unencrypted files > output results to temp log file: YYYYMMDD_Enryption.txt (removed after script is run)
        Start-Process -FilePath "C:\Program Files (x86)\PGP Corporation\PGP Desktop\pgpnetshare.exe" -ArgumentList "-v $PGP_Folder --output-file $VerifyLogFile --verbose" -Wait -NoNewWindow -PassThru
        
        #Parses temp log file for unencrypted files
        $aryUnencrypted = Get-Content $VerifyLogfile | Select-String -pattern "unencrypted \[([^]]+)\]" -AllMatches| ForEach-Object {$_.matches}
        if ($aryUnencrypted)
        {
            foreach ($unencryptedstring in $aryUnencrypted)
            {
                $strTempPath = $unencryptedstring.Value.substring(13, ($unencryptedstring.Value.Length-14))
                #Log Time and File Name
                "$(Get-date) --- Unencrypted: $strTempPath" | Out-file $Logfile -Append -Force
                
                if ((Get-Item $strTempPath).PSIsContainer)
                {
                    #Checks for unencrypted subfolders within encrypted parent folder.
                    #$FolderFlag subfolders get added to end of log file for review. 
                    #Consider copy-item for entire subfolder? Why didn't FinanceIT?
                    $FolderFlag += $newline +$strTempPath
                }
            }
        }    
        else 
        {
            "$(Get-date) --- $PGP_Folder --- All files encrypted" | Out-file $Logfile -Append -Force   
        }

        Remove-item $VerifyLogFile
    }
    "$(Get-Date) --- PGP SCAN COMPLETED" | Out-File $Logfile -Append -Force

    "$newline$newline" + "The following folders are decrypted and need to be reviewed: $FolderFlag" | Out-File $Logfile -Append -Force

    #email report after run
    $From = "WeeklyADComputerCleanup@doit.tamu.edu"
    $To = "Systems@doit.tamu.edu"
    $Subject = "PGP Reencrypt Scan"
    $Body = "See attached logfile for results of the nightly scan for unencrypted files within group-key encrypted folders."
    $SMTPServer = "exchange.tamu.edu"
    $SMTPPort = "465"
    #Have to pass credentials to Send-MailMessage > Give bogus credentials
    $anonPassword = ConvertTo-SecureString -String "anonymous" -AsPlainText -Force
    $anonCredentials = New-Object System.Management.Automation.PSCredential($From,$anonPassword)

    #Send-MailMessage -From $From -to $To -Cc $CC -Subject $Subject -Body $Body -SmtpServer $SMTPServer -Credential $anonCredentials `
    #-Attachments $AttachedReports –DeliveryNotificationOption OnSuccess
    Send-MailMessage -From $From -to "wdell@doit.tamu.edu" -Subject $Subject -Body $Body -SmtpServer $SMTPServer -Credential $anonCredentials -Attachments $Logfile -DeliveryNotificationOption OnSuccess
}    

function main
{
    SearchForUnencrypted
}

main