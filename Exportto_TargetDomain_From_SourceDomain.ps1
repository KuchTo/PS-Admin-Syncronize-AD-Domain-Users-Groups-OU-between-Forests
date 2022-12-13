# Zweck: (Teil-) Syncronisation der Objektklassen: organizationalUnit, group und user zwischen zwei getrennten Forests.
# Das Skript ist auf kontinuierliche (regelmäßige) Syncronisation zwischen den Forests optimiert, Änderungen werden erkannt und markiert.
# Objekte, die in dem Zielforest angelegt werden, werden nicht gelöscht oder geändert, sondern bleiben parallel stehen.
# Die Syncronisation besteht aus 2 Skripts, jeweils 1 für den Export aus dem Quellsystem und 1 für den Import ind as Zielsystem
#
#
#  Author: Tobias Kuch
# 
#  Version 1.01 Beta  
#
#  Teil A:  Export Script
#
# Version  0.91 Added employeeType,Initials on user object
# Version  1.00 Added Transfer UNC share with Credentials Support
# Version  1.01 Bug Fixes

$Error.clear()
$sha = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider 
$enc = [system.Text.Encoding]::UTF8



#Common Configurations


$TransferShare = "\\transferserver01.ohne.domainzugehoerigkeit\transfershare"    # Dateiaustausch Share zwischen Quelldomain ind Zieldomain . Muss von beiden Forests aus zugänglich sein, daher Passwortbasiertes Mapping.
$TransferUser = "lokaler Benutzer auf transferserver01" 			 # Muss schreibenden Zugriff auf $TransferShare haben.
$TransferUserPwD = "Passwort des lokalen Benutzers auf transferserver01"

$DatabaseFile = "ADData.xml"
$StatusFileName = "ADStatus.xml"
$LogFileName = "ExportData.log"
$DatabasePath = "\OrdnerName\"							 #Pfad ab $TransferShare zb: OrdnerName. Vollständiger Pfad währe dann: \										#\transferserver01.ohne.domainzugehoerigkeit\transfershare\OrdnerName\



#Threshold Values

$MinReadObjectsfromSource =  900    # Minimum Objects read from Source Domain. If lower count, no Syncronisation will happened
$MaxObjectsDeletedperRun = 1000
$MaxObjectsInsertedperRun = 1000
$MaxObjectsModifiedperRun = 209500

#Cryptographic Values

$HashVerificationActive = $true
$HashPepper = "Hier_ein_beliebigen_String_eintragen_min_8_Zeichen"		# Bitte anpassen.

#Domain Configurations

$DNSSourceDomainName = "sourcedomain.fqdn"					# Bitte anpassen.
$AuthSourceDC = "domaincontroller01.sourcedomain.fqdn"				# Bitte anpassen.



Function Main ()
{
clear-host
$Status = $ErrorActionPreference 
$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory 
$ErrorActionPreference = $Status

write-host "Preparing Connection.." 

# -------- Mapping und Test auf Schreiblaufwerk definiert in Variable $TransferShare  ------------
$SMBMappings= Get-SmbMapping
ForEach ( $Connection in $SMBMappings)
    {
        If ($Connection.RemotePath -eq $TransferShare)
        {
            $Command = "net use " +$Connection.Localpath+ " /delete /yes"
            $Result = Invoke-Expression $Command -ErrorAction SilentlyContinue 
        }
    }
$FreeLetter = Get-SmbClientNextFreeDrive
$Result = New-SmbMapping -LocalPath $FreeLetter -RemotePath $TransferShare -UserName $TransferUser -Password $TransferUserPwD  -ErrorAction SilentlyContinue
If ($Result -eq $Null)
    {
    write-host " failed.. " -ForegroundColor red
    write-host "Cannot Map Network Drive" $FreeLetter "with Unc Path:"$TransferShare" ErrorName:" $Error
    $Error.Clear()
    exit    
    }
$TestFile = $Result.LocalPath + "Writetest.txt"
try
    {
    "Schreibtest." | Out-File -FilePath $TestFile
    Remove-Item $TestFile -ErrorAction Stop
    }
catch
    {
    write-host "Write Test to Path" $TestFile "failed: "$error
    $Error.Clear()
    exit   
    }
$DatabasePath = $Result.LocalPath + $DatabasePath
If (!(Test-Path $DatabasePath))
    {
    write-host "Directory not exist. Create new one."
    New-Item -ItemType Directory -Path $DatabasePath 
    }

$Database = $DatabasePath + $DatabaseFile 
$LogFile = $DatabasePath + $LogFileName
$StatusFile = $DatabasePath + $StatusFileName
$DelPathLW = $Result.LocalPath
# -------- ENDE Mapping und Test Schreiblaufwerk ------------

Write-Host "[READ-ACCESS] to Domain:" $DNSSourceDomainName -ForegroundColor Green

write-host "Database   :"$Database
write-host "Logfile    :"$LogFile
write-host "Statusfile :"$StatusFile 



$Error.clear()
 

# --- Handle status File ------------------------
try
    {
       $Statusobj = Import-Clixml -Path $StatusFile
       $CalcHash = Calculate-Hash ( $Statusobj  )       
       [string]$a = $CalcHash
       [string]$b = $Statusobj.Hash
       if (( $a -ne $b ) -and ( $HashVerificationActive))
       {  
        $CMsg = "Hash from Status File incorrect. Aborted. Hashes:"+$a+ " and "+ $b
        write-host $CMsg -ForegroundColor Red
        Write-Log -Message $CMsg -Path $LogFile -Level Error
        exit
       }
    }
catch
    {
       $object = New-Object PSObject 
       Add-Member -InputObject $object -TypeName Noteproperty „Librastate“ "Initital“ -force
       Add-Member -InputObject $object -TypeName Noteproperty „ExportAllowed“ "1“ -force
       Add-Member -InputObject $object -TypeName Noteproperty „ImportAllowed" "1“ -force
       Add-Member -InputObject $object -TypeName Noteproperty „Hash" "0“ -force     
       $object.Hash = Calculate-Hash ( $object ) 
       $object | Export-Clixml -Path $StatusFile
       $Statusobj = Import-Clixml -Path $StatusFile
    }

write-host $Statusobj.Librastate
If ($Statusobj.Librastate -eq "Initial")
   {
        $CMsg = "New Status File created."
        write-host $CMsg -ForegroundColor Red
        Write-Log -Message $CMsg -Path $LogFile -Level Warn
        exit
    }

If ((!($Statusobj.ExportAllowed)) -and  (!($Statusobj.Librastate -eq "Initial")))
   {
        $CMsg = "Export disabed. Enable it in status File."
        write-host $CMsg -ForegroundColor Red
        Write-Log -Message $CMsg -Path $LogFile -Level Warn
        exit
    }
If ( $Statusobj.Librastate -eq "Export")
    {
        $CMsg = "Export already executed. Please Import first."
        write-host $CMsg -ForegroundColor Red
        Write-Log -Message $CMsg -Path $LogFile -Level Warn
        exit
    }



# --- Handle status File END------------------------

try
    {
    Write-Log -Message  "[AD-Syncronisation  READ] Start." -Path $LogFile -Level Info
    }
catch
    {
    write-host ""
    $CMsg = "Error: Trouble to read or write Log file in Path "+$LogFile +". "+ $Error
    write-host $CMsg -ForegroundColor red
    write-host "Terminated." -ForegroundColor red
    $Error.clear()
    exit 1
    }

try
    {
   
    $DomainInformation = get-ADDomain
    if(!($DomainInformation.DNSRoot -eq $DNSSourceDomainName))
        {
        write-host "Wrong Execution Environment. (Must be:"  $DNSSourceDomainName ") Terminated." -ForegroundColor red 
        exit 1
        }

    # Base Properties:  ObjectClass,Name,ObjectGUID,DistinguishedName,uSNChanged,whenChanged
    $ReadTimeTaken = Measure-Command{
    write-host "Getting OU-Objects from Sourcedomain. " -nonewline
    $Collector = @()
    $Collector = Get-ADObject -Filter { (objectclass -eq "organizationalUnit")  } -Properties ObjectClass,Name,ObjectGUID,DistinguishedName,Description,ProtectedFromAccidentalDeletion,uSNChanged,whenChanged,ou,gPLink,managedBy -server $AuthSourceDC
    $OU = Add-CustomProperties $Collector
    write-host " done.." 
    write-host "Getting Group-Objects from Sourcedomain. " -nonewline
    $Collector = @()
    $Collector += Get-ADObject -Filter { (objectclass -eq "group") } -Properties ObjectClass,Name,ObjectGUID,DistinguishedName,uSNChanged,whenChanged,sAMAccountName,sAMAccountType,CN,CanonicalName,Description,DisplayName,groupType,mail,mailNickname,member,info,managedBy -server $AuthSourceDC
    $Groups = Add-CustomProperties $Collector
    write-host " done.." 
    write-host "Getting User-Objects from Sourcedomain. " -nonewline
    $Collector = @()
    $Collector += Get-ADObject -Filter { objectclass -eq "user" } -Properties ObjectClass,Name,ObjectGUID,DistinguishedName,uSNChanged,whenChanged,sAMAccountName,sAMAccountType,CN,CanonicalName,Description,DisplayName,sn,givenName,department,l,c,co,comment,company,st,streetAddress,telephoneNumber,physicalDeliveryOfficeName,postalCode,houseIdentifier,primaryGroupID,roomNumber,title,userAccountControl,userPrincipalName,codepage,employeeID,HomeDirectory,homeDrive,scriptPath,memberOf,mail,profilePath,employeeType,Initials -server $AuthSourceDC | ? { $_.objectclass -eq "user" }  # Bugfix 
    $Users = Add-CustomProperties $Collector
    write-host " done.."
    #write-host "Getting Contact-Objects from Sourcedomain. " -nonewline
    #$Collector = @()
    #$Collector += Get-ADObject -Filter { (objectclass -eq "contact") } -Properties ObjectClass,Name,ObjectGUID,DistinguishedName,uSNChanged,whenChanged,CN,CanonicalName,Description,DisplayName,sn,givenName,mail,mailNickname -server $AuthSourceDC
    #$Contact = Add-CustomProperties $Collector
    #write-host " done.."
    }
    $CMsg = "Active Directory Read Operation completed in " + $ReadTimeTaken.TotalSeconds + " Seconds."
    write-host $CMsg 
    write-Log -Message $CMsg -Path $LogFile -Level Info
    write-host "Apply Syncronisation Rules. Please wait."
    }
catch
    {
    write-host ""
    $CMsg = "Error: Could not read Source Domain Objects. Error: " + $Error
    write-host $CMsg -ForegroundColor red
    Write-Log -Message $CMsg -Path $LogFile -Level Error
    write-host "Terminated." -ForegroundColor red 
    exit 1
    }
#Init Working Variables
$Collector = @()
$AllSourceADObjects =@()
$AllDBADObjects =@()
$AllSourceADObjects = $Groups
$AllSourceADObjects += $OU
$AllSourceADObjects += $Users
#$AllSourceADObjects +=$Contact
$Groups = @()
$OU=@()
$Users=@()
$Contact =@()
$AllSourceADObjects = $AllSourceADObjects | ? { $_ -ne $NULL}                  # Cleanup / No Null Objects
$AllSourceADObjects = Exclude-SyncronizationObjectsbyRule $AllSourceADObjects  # Mark Objects that applys to static defined Syncronisation Rule(s
$AllSourceADObjects = $AllSourceADObjects | ? { $_.ObjectIsDeleted -ne $true}  # Filter all preious Marked Objects

[string]$Con3 = @($AllSourceADObjects).count
$CMsg =  $Con3 +" Objects from Sourcedomain collected."
write-host $CMsg 
Write-Log -Message $CMsg -Path $LogFile -Level Info
If ( @($AllSourceADObjects).count -lt $MinReadObjectsfromSource)
    {
    $CMsg = "Objects from Sourcedomain lower than Threshold Value "+$MinReadObjectsfromSource+ ". Process terminated."
    write-host $CMsg -ForegroundColor Red
    Write-Log -Message $CMsg -Path $LogFile -Level Error
    exit 1
    }
$AllSourceADObjects =Calculate-Domaindata $AllSourceADObjects # Do Syncronisation Work in Function Calculate-Domaindata 
If (Test-Path $Database)  # if Database already exists, Update it, otherwise create a fresh Database
    { 
    write-host "Reading Database. " -nonewline
    Write-Log -Message "Reading Database. " -Path $LogFile -Level Info
    $AllDBADObjects = Import-Clixml -Path $Database
   
# Filters
    $AllDBADObjects = $AllDBADObjects | ? { $_ -ne $NULL}  # Database Cleanup / No Null Objects
    $AllDBADObjects = $AllDBADObjects | ? { $_.ObjectIsDeleted -ne $true}  # Filter all previous Marked as to deleted Objects
    write-host " done.." 
    
    $CMsg = "Updating Database. "
    write-host $CMsg 
    Write-Log -Message $CMsg -Path $LogFile -Level Info
    try
        {
        $UpdateTimeTaken = Measure-Command { $UpdatedDBADObjects = Update-Database $AllSourceADObjects $AllDBADObjects }
        }
    catch
        {
        $CMsg = "Error: " + $Error
        write-host $CMsg -ForegroundColor red
        Write-Log -Message $CMsg -Path $LogFile -Level Error
        write-host "Ending." -ForegroundColor red 
        exit 1
        }
    write-host ""
    $CMsg = "DB Update in "+ $UpdateTimeTaken.TotalSeconds +" Seconds."
    write-host $CMsg 
    Write-Log -Message $CMsg -Path $LogFile -Level Info
    $error.clear()
    try
        {
        #Clean up, if necessary
        $TmpDbName = $DatabasePath + "dataold.xml"
        If (Test-Path $TmpDbName)
            {
            Remove-Item -Path $TmpDbName -force
            }
        Rename-Item -Path $Database -NewName "dataold.xml" -Force # Debug
        Export-Clixml -Path $Database -InputObject $UpdatedDBADObjects -Force # Write out updated Database
        $CMsg = "Database updated sucessfully."
        # ---Update Status File, that no another Export can be RUN !
        $Statusobj.librastate = "Export"
        $Statusobj.Hash = Calculate-Hash ( $Statusobj ) 
        $Statusobj | Export-Clixml -Path $StatusFile
        # ---Update Status File finished
        write-host $CMsg 
        Write-Log -Message $CMsg -Path $LogFile -Level Info
        $AllSourceADObjects = @()
        

        }
    catch
        {
        $CMsg = "Error: " + $error
        write-host $CMsg -ForegroundColor Red
        Write-Log -Message $CMsg -Path $LogFile -Level Error
        write-host "Ending."
        exit 1
        }


    }
else # create a fresh Database
    {
    try
        {
        $CMsg = "Creating Database. "
        write-host $CMsg 
        Write-Log -Message $CMsg -Path $LogFile -Level Info
        # Calculate Initial Hash values
         ForEach ( $Object in $AllSourceADObjects)
            {
           $Object.Hash = Calculate-Hash ( $Object )
            }
        #End Hash Calculation
        $CreateTimeTaken = Measure-Command { Export-Clixml -Path $Database -InputObject $AllSourceADObjects -Force }
        $CMsg = "DB Initial Creation in "+ $CreateTimeTaken.TotalSeconds +" Seconds."
        # ---Update Status File, that no another Export can be RUN !
        $Statusobj.librastate = "Export"
        $Statusobj.Hash = Calculate-Hash ( $Statusobj ) 
        $Statusobj | Export-Clixml -Path $StatusFile
        # ---Update Status File finished
        write-host $CMsg 
        Write-Log -Message $CMsg -Path $LogFile -Level Info
        $CMsg = "Database created sucessfully."
        write-host $CMsg 
        Write-Log -Message $CMsg -Path $LogFile -Level Info
        $AllSourceADObjects = @()   # In finaler version wieder aktivieren
        }
    catch
        {
        $CMsg = "Error: " + $error
        write-host $CMsg -ForegroundColor Red
        Write-Log -Message $CMsg -Path $LogFile -Level Error
        write-host "Ending."
        exit 1
        }

    }
    $CMsg = "[AD-Syncronisation  READ] Stop."
    Write-Log -Message $CMsg -Path $LogFile -Level Info
    Remove-SmbMapping -LocalPath $DelPathLW -Force # Delete SMB Sharedrive at least
}



Function Calculate-Domaindata ( $InputObject ) # calulate some Attributes in new Domain context
{
 $OutputObject = @()
 ForEach ($ItemT in $InputObject)
    {
    $Tmp = $ItemT.DistinguishedName
    $ItemT.DNLength = $Tmp.Length
    $OutputObject += $ItemT
    }

Return $OutputObject 
}



Function Update-Database ( $LiveSystemData, $DatabaseData )
{
 $OutputObject = @()
 $UpdateCount = 0
 $Columbreak = 0


 $DBASEA = $LiveSystemData | Sort-Object -Property ObjectGUID  # SpeedUp Compare Process
 $DBASEB = $DatabaseData | Sort-Object -Property ObjectGUID  -Descending  # SpeedUp Compare Process

 ForEach ($Item in $DBASEA) { $Item.sync = $false }
 ForEach ($Item in $DBASEB) { $Item.sync = $false }
 
 ForEach ($ObjectLive in $DBASEA  )
    {
    ForEach ($ObjectDataBase in  $DBASEB ) # Search ITEM in Database
        {
        IF ($ObjectLive.ObjectGUID -eq $ObjectDataBase.ObjectGUID) 
            {
                 $ObjectDataBase.sync = $true
                 $ObjectLive.sync = $true

            IF (($ObjectLive.uSNChanged -eq $ObjectDataBase.uSNChanged)-and ($ObjectLive.whenChanged -eq $ObjectDataBase.whenChanged))    #NO CHANGE to existing Object
                {
                #No Change to OU Object
                #write-host "No Change ! :)"
                $Saveparam1 = $ObjectDataBase.TargetSystemObjectGUID
                $Saveparam2 = $ObjectDataBase.TargetSystemuSNChanged
                $Saveparam3 = $ObjectDataBase.TargetSystemwhenChanged
                $Saveparam4 = $ObjectDataBase.HasToBeSync
                $Saveparam5 = $ObjectDataBase.State
                $Saveparam6 = $ObjectDataBase.Hash
                $ObjectDataBase = $ObjectLive
                $ObjectDataBase.TargetSystemObjectGUID = $Saveparam1
                $ObjectDataBase.TargetSystemuSNChanged = $Saveparam2
                $ObjectDataBase.TargetSystemwhenChanged = $Saveparam3
                $ObjectDataBase.HasToBeSync = $Saveparam4
                if ($HashVerificationActive)
                    {
                    $ObjectDataBase.Hash = $Saveparam6
                    }
                    else
                    {
                    $ObjectDataBase.Hash = Calculate-Hash ( $ObjectDataBase )
                    }
                #$ObjectDataBase.Hash = $Saveparam6
                $ObjectDataBase.State = $Saveparam5
                $OutputObject +=$ObjectDataBase
                break
                }
            IF (($ObjectLive.uSNChanged -ne $ObjectDataBase.uSNChanged)-or ($ObjectLive.whenChanged -ne $ObjectDataBase.whenChanged))     #CHANGE to existing Object
                {
                #Update Object
                #Save necessary parameters
                $ObjIsInInsertedState = $false
                $Saveparam1 = $ObjectDataBase.TargetSystemObjectGUID
                $Saveparam2 = $ObjectDataBase.TargetSystemuSNChanged
                $Saveparam3 = $ObjectDataBase.TargetSystemwhenChanged
                $Saveparam4 = $ObjectDataBase.HasToBeSync
                $Saveparam5 = $ObjectDataBase.State
                If ($ObjectDataBase.State -eq "I") {$ObjIsInInsertedState = $true }
                $ObjectDataBase = $ObjectLive
                $ObjectDataBase.TargetSystemObjectGUID = $Saveparam1
                $ObjectDataBase.TargetSystemuSNChanged = $Saveparam2
                $ObjectDataBase.TargetSystemwhenChanged = $Saveparam3
                $ObjectDataBase.HasToBeSync = $Saveparam4
                $ObjectDataBase.Hash =Calculate-Hash ( $ObjectDataBase ) 

                If ($ObjIsInInsertedState)       # If Object is Inserted at a previous state 
                    {
                    $ObjectDataBase.State = "I"  # (State = I, leave it as State Insterted, because it is nor created in the Target Domain therefore it cannot be updated.
                    }
                else                                                                      # therefore it cannot be updated.
                    {
                    $ObjectDataBase.State = "U"   # else mark it as updated
                    }

                $OutputObject +=$ObjectDataBase
                $UpdateCount++      
                #write-host "Object" $ObjectDataBase.DistinguishedName "Updated." 
                if ($UpdateCount -gt $MaxObjectsModifiedperRun)
                    {
                    write-host ""
                    $CMsg = "Modified Objects Count exceeds the Threshold Value "+$MaxObjectsModifiedperRun+". Process terminated."     
                    write-host $CMsg -ForegroundColor Red
                    Write-Log -Message $CMsg -Path $LogFile -Level Error
                    write-host "Ending."
                    exit 1
                    }           
                $Columbreak ++;
                write-host "." -NoNewline
                if ($Columbreak -gt 75)
                    {
                    $Columbreak = 0;
                    write-host "";
                    }
                
                break
                }  
            }

        }

    }
write-host ""
$CMsg = "Updated AD Objects: "+$UpdateCount    
write-host $CMsg -ForegroundColor green
Write-Log -Message $CMsg -Path $LogFile -Level Info
$UpdateCount = 0

$DBASEA = $DBASEA | where { $_.sync -eq $false } #Live
$DBASEB = $DBASEB | where { $_.sync -eq $false } #DB                                                                       

 IF (@($DBASEB).count -gt 0)    #DELETED Object    
   {
   #write-host @($DBASEB).count "deleted items found"
   if ( @($DBASEB).count -gt $MaxObjectsDeletedperRun)
    {
    $CMsg = "Deleteable Objects Count greater than Threshold Value "+$MaxObjectsDeletedperRun+ ". Process terminated."
    write-host $CMsg -ForegroundColor Red
    Write-Log -Message $CMsg -Path $LogFile -Level Error
    write-host "Ending."
    exit 1
    }
   ForEach ($ItemD in $DBASEB) 
        { 
        IF ($ItemD.State -ne "D") 
            { 
            write-host "Object" $ItemD.DistinguishedName "deleted."
            $ItemD.State = "D"
            $ItemD.Hash =Calculate-Hash ($ItemD) 
            $UpdateCount++
            }       
        $OutputObject +=$ItemD        
        }
        IF ($UpdateCount -gt 0) 
            { 
            $CMsg = "Deleted AD Objects: "+$UpdateCount    
            write-host $CMsg -ForegroundColor green
            Write-Log -Message $CMsg -Path $LogFile -Level Info
            }
   }


$UpdateCount = 0
 IF (@($DBASEA).count -gt 0)    #INSERTED Object
    {
    write-host @($DBASED).count "new items found"
    if ( @($DBASEB).count -gt $MaxObjectsInsertedperRun)
        {
        $CMsg = "New Objects Count greater than Threshold Value "+$MaxObjectsInsertedperRun+". Process terminated."
        write-host $CMsg -ForegroundColor Red
        Write-Log -Message $CMsg -Path $LogFile -Level Error
        write-host "Ending."
        exit 1
        }
        ForEach ($ItemI in $DBASEA) 
        { 
        IF ($ItemD.State -ne "I") { write-host "Object" $ItemI.DistinguishedName "added." }
        $ItemI.State = "I"
        $OutputObject +=$ItemI
        $ItemI.Hash =Calculate-Hash ($ItemI)
        $UpdateCount++
        }
       $CMsg = "Inserted AD Objects: "+$UpdateCount    
       write-host $CMsg -ForegroundColor green
       Write-Log -Message $CMsg -Path $LogFile -Level Info
    }

 
Return $OutputObject

}



Function Add-CustomProperties ( $InputObject ) # Adding some Replication Control Fields
{
$OutputObject = @()
 ForEach ($Item in $InputObject )
 {
 $object = New-Object PSObject 
 $object = $Item
 Add-Member -InputObject $object -TypeName Noteproperty „TargetSystemObjectGUID“ "0“ -force
 Add-Member -InputObject $object -TypeName Noteproperty „TargetSystemuSNChanged“ "0“ -force
 Add-Member -InputObject $object -TypeName Noteproperty „TargetSystemwhenChanged" "0“ -force
 # States
 # D = Delete
 # I = Insert
 # S = Syncronized
 # U = Update
 # N = NEw Entry
 Add-Member -InputObject $object -TypeName Noteproperty „State“ „N“ -force
 Add-Member -InputObject $object -TypeName Noteproperty „Sync“ $false -force
 Add-Member -InputObject $object -TypeName Noteproperty „HasToBeSync“ $true -force
 Add-Member -InputObject $object -TypeName Noteproperty „FULLSync“ $true -force
 Add-Member -InputObject $object -TypeName Noteproperty „ObjectIsDeleted“ $false -force
 Add-Member -InputObject $object -TypeName Noteproperty „Hash“ "0“ -force
 Add-Member -InputObject $Item -TypeName Noteproperty „DNLength“ "0“ -force
 $OutputObject += $object
 }
Return $OutputObject 
}





Function Exclude-SyncronizationObjectsbyRule ( $InputObject )

{
#Some Optimizations 
$ObjectCountExcluded = 0

$ExcludeObjectsWithSamAccName  = @("Ausnahme1","Ausnahme2") 		# Hier können Ausnahmen von der Syncronisation definiert werden. Dazu muss der SamAccountname z.b Der Gruppe verwednet werden. Bitte anpassen.

FOR($i=0; $i -le $ExcludeObjectsWithSamAccName.Length -1; $i++)
    {
    $ExcludeSMAccName = $ExcludeObjectsWithSamAccName[$i]
    $SubSet = $InputObject | ? { ($_.SamAccountName -match $ExcludeSMAccName)  -and ($_.HasToBeSync -eq $true ) -and (!($_.State  -eq "S"))}   
    IF (@($SubSet).count -gt 0 )
        {
            ForEach ($Item in $SubSet )
            {  
            write-host "Object"$Item.Name"excluded. Violation of static defined Syncronisation Rule(s) !" -ForegroundColor yellow
            $Item.HasToBeSync = $false
            $Item.State = "S"
            $Item.ObjectIsDeleted  = $true
            $ObjectCountExcluded++
            }
        }
    }

#Exclude Exchange Objects
$ExcludeDN = "CN=Microsoft Exchange System Objects," + $DNSourceDomain
$SubSet = $InputObject | ? { ($_.DistinguishedName -Match $ExcludeDN) -and ($_.HasToBeSync -eq $true ) }   
IF (@($SubSet).count -gt 0 )
    {
        ForEach ($Item in $SubSet )
        {  
        write-host "Object"$Item.Name"excluded. Violation of static defined Syncronisation Rule(s) !" -ForegroundColor yellow
        $Item.HasToBeSync = $false
        $Item.State = "S"
        $Item.ObjectIsDeleted  = $true
        $ObjectCountExcluded++
        }
    }
$CMsg = "Excluded AD Objects from Syncronisation: "+$ObjectCountExcluded    
write-host $CMsg -ForegroundColor green
Write-Log -Message $CMsg -Path $LogFile -Level Info
Return $InputObject 
}


function Write-Log 
{ 
    [CmdletBinding()] 
    Param 
    ( 
        [Parameter(Mandatory=$true, 
                   ValueFromPipelineByPropertyName=$true)] 
        [ValidateNotNullOrEmpty()] 
        [Alias("LogContent")] 
        [string]$Message, 
 
        [Parameter(Mandatory=$false)] 
        [Alias('LogPath')] 
        [string]$Path='C:\Save\PowerShellLog.log', 
         
        [Parameter(Mandatory=$false)] 
        [ValidateSet("Error","Warn","Info")] 
        [string]$Level="Info", 
         
        [Parameter(Mandatory=$false)] 
        [switch]$NoClobber 
    ) 
 
    Begin 
    { 
       # Set VerbosePreference to Continue so that verbose messages are displayed. 
       # $VerbosePreference = 'Continue' 
    } 
    Process 
    { 
         
        # If the file already exists and NoClobber was specified, do not write to the log. 
        if ((Test-Path $Path) -AND $NoClobber) { 
            Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name." 
            Return 
            } 
 
        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path. 
        elseif (!(Test-Path $Path)) { 
            Write-Verbose "Creating $Path." 
            $NewLogFile = New-Item $Path -Force -ItemType File -ErrorAction SilentlyContinue
            } 
 
        else { 
            # Nothing to see here yet. 
            } 
 
        # Format Date for our Log File 
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss" 
 
        # Write message to error, warning, or verbose pipeline and specify $LevelText 
        switch ($Level) { 
            'Error' { 
                Write-Verbose $Message 
                $LevelText = 'ERROR:' 
                } 
            'Warn' { 
                Write-Verbose $Message 
                $LevelText = 'WARNING:' 
                } 
            'Info' { 
                Write-Verbose $Message 
                $LevelText = 'INFO:' 
                } 
            } 
         
        # Write log entry to $Path 
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append 
    } 
    End 
    { 
    } 
}

Function Add-CustomProperties ( $InputObject ) # Adding some Replication Control Fields
{
$OutputObject = @()
 ForEach ($Item in $InputObject )
 {
 $object = New-Object PSObject 
 $object = $Item
 Add-Member -InputObject $object -TypeName Noteproperty „TargetSystemObjectGUID“ "0“ -force
 Add-Member -InputObject $object -TypeName Noteproperty „TargetSystemuSNChanged“ "0“ -force
 Add-Member -InputObject $object -TypeName Noteproperty „TargetSystemwhenChanged" "0“ -force
 # States
 # D = Delete
 # I = Insert
 # S = Syncronized
 # U = Update
 # N = NEw Entry
 Add-Member -InputObject $object -TypeName Noteproperty „State“ „N“ -force
 Add-Member -InputObject $object -TypeName Noteproperty „Sync“ $false -force
 Add-Member -InputObject $object -TypeName Noteproperty „HasToBeSync“ $true -force
 Add-Member -InputObject $object -TypeName Noteproperty „FULLSync“ $true -force
 Add-Member -InputObject $object -TypeName Noteproperty „ObjectIsDeleted“ $false -force
 Add-Member -InputObject $object -TypeName Noteproperty „Hash“ "0“ -force
 Add-Member -InputObject $Item -TypeName Noteproperty „DNLength“ "0“ -force
 $OutputObject += $object
 }
Return $OutputObject 
}


Function Calculate-Hash ( $InputObject ) # Adding Hash
{
 $Data = $HashPepper
 $TypeFound = $false
 $TypeClass = ($InputObject).GetType().Fullname
 #write-host "Debug: Typeclass:" $TypeClass
  if ($TypeClass -eq "System.Management.Automation.PSCustomObject") 
 {
    $Members = $InputObject | gm #-ErrorAction SilentlyContinue 
    ForEach ($Member in $Members )
       {
       If (($Member.Membertype -eq "NoteProperty" ) -and (!($Member.Name -eq "Hash"))-and (!($Member.Name -eq "State")))
           {
              $Property = $Member.Name
             [string] $Value =  $InputObject.$Property
             $Data += $Value
           }
 	    }
 $TypeFound = $true
 }

 if ($TypeClass -eq "System.String")
 {
    $Data = $InputObject
 }

  if (!($TypeFound)) 
 {
    $Members = $InputObject | gm #-ErrorAction SilentlyContinue 
    ForEach ($Member in $Members )
       {
       If (($Member.Membertype -eq "Property" ) -and (!($Member.Name -eq "Hash"))-and (!($Member.Name -eq "State")))
           {
              $Property = $Member.Name
             [string] $Value =  $InputObject.$Property
             $Data += $Value
           }
 	    }
 $TypeFound = $true
 }
 
 $datavalues = $enc.GetBytes($Data) 
 $Hashvalue  = $sha.ComputeHash($datavalues)
 #write-host "Debug: Encrypt String:" $Data
 #write-host "Debug: Hash Value:"  $Hashvalue
 Return $Hashvalue 
}



Function Get-SmbClientNextFreeDrive ()
{
#Get a Free Mapping Drive to Map own Drive
$NextFreeDrive ="NothingFound"
#Specify usable Drives to Map
$DrivesToTest = @("D:","E:","F:","G:","H:","I:","J:","K:","L:","M:","N:","O:","P:","Q:","R:","S:","T:","U:","V:","W:","X:","Y:","Z:")
ForEach ($Drive in (Get-SmbMapping).localpath)
    {
    For ($a=0;$a -le $DrivesToTest.Count;$a++)
        {
        If ($Drive -eq $DrivesToTest[$a])
            {
            $DrivesToTest[$a] = "."
            }
        }  
    }
ForEach ($Drive in (Get-PsDrive).Name)
    {
   # write-host $Drive
    For ($a=0;$a -le $DrivesToTest.Count;$a++)
        {
        $DriveLetter = $Drive + ":"
        If ($DriveLetter -eq $DrivesToTest[$a])
            {
            $DrivesToTest[$a] = "."
            }
        }  
    }

ForEach ($Drive in $DrivesToTest)
    {
    If (!($Drive -eq "."))
            {
            $NextFreeDrive = $Drive
            break
            }
    }
 Return $NextFreeDrive
}




Main

