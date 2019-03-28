<#
Author: Kevin Joyce

Requirements: Active Directory PowerShell module, Domain Administrator privileges (to ensure the capability to get attribute GUIDs and view all permissions on all computer objects)

Description: Looks up permissions within Active Directory on a target (OU or Computer) to determine access to LAPS attributes (ms-Mcs-AdmPwdExpirationTime and ms-Mcs-AdmPwd).

Usage: Popuplate the $target varbiable with the DN of a computer object, or OU to search for computer objects within.

To output the results to a text file run the following .\LAPS_Permissions_Collection.ps1 > output.txt
#>

Import-Module ActiveDirectory
##Get the GUID of the extended attributes ms-Mcs-AdmPwdExpirationTime and ms-Mcs-AdmPwd from Schema
$schemaIDGUID = @{}
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(|(name=ms-Mcs-AdmPwdExpirationTime)(name=ms-Mcs-AdmPwd))' -Properties name, schemaIDGUID |
ForEach-Object {$schemaIDGUID.add([System.GUID]$_.schemaIDGUID,$_.name)}

<# **REPLACE DN VARIABLE BELOW**
Declare the distinguishedName of the Computer object directly or OU to search for computers within#>
$target = 'CN=Computers,DC=COMPANY,DC=NET'

##Get distinguished name of all Computer objects from the OU or of the target itself
$computers = Get-ADComputer -SearchBase $target -Filter {name -like '*'}


<#Get objects that have specific permissions on the target(s): 

Full Control(GenericAll) 
Read All Properties(GenericRead)
Write all Properties (WriteProperty where ObjectType = 00000000-0000-0000-0000-000000000000  

#>
Set-Location ad:
foreach ($computer in $computers){
(Get-Acl $computer.distinguishedname).access | 
Where-Object { (($_.AccessControlType -eq 'Allow') -and ($_.activedirectoryrights -in ('GenericRead','GenericAll') -and $_.inheritancetype -in ('All', 'None')) -or (($_.activedirectoryrights -like '*WriteProperty*')-or ($_.activedirectoryrights -like '*GenericRead*') -and ($_.objecttype -eq '00000000-0000-0000-0000-000000000000')))} |
 ft ([string]$computer.name),identityreference, activedirectoryrights, objecttype, isinherited -autosize 
 }
 <#Get objects that have specific permissions on the target(s) and specifically the LAPS attributes:

 WriteProperty
 ReadProperty 
 
 #>
Set-Location ad:
foreach ($computer in $computers){
(Get-Acl $computer.distinguishedname).access | 
Where-Object {(($_.AccessControlType -eq 'Allow') -and (($_.activedirectoryrights -like '*WriteProperty*') -or ($_.activedirectoryrights -like '*ReadProperty*')) -and ($_.objecttype -in $schemaIDGUID.Keys))} |
 ft ([string]$computer.name),identityreference, activedirectoryrights, objecttype, isinherited -AutoSize
 } 