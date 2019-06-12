    -Script should run from service account on machine with PGP Client installed.
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
    