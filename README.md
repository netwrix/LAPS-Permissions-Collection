# LAPS Permissions Collection
LAPS Permissions Collection script by Kevin Joyce

## Description
Looks up permissions within Active Directory on a target (OU or Computer) to determine access to LAPS attributes (ms-Mcs-AdmPwdExpirationTime and ms-Mcs-AdmPwd).
Requirements: Active Directory PowerShell module, Domain Administrator privileges (to ensure the capability to get attribute GUIDs and view all permissions on all computer objects)


## Usage
1. Popuplate the $target varbiable with the DN of a computer object, or OU to search for computer objects within.
2. OPTIONAL: To output the results to a text file run the following .\LAPS_Permissions_Collection.ps1 > output.txt
