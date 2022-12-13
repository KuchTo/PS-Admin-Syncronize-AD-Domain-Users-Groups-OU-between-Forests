# Zweck: (Teil-) Syncronisation der Objektklassen: organizationalUnit, group und user zwischen zwei getrennten Forests.
# Das Skript ist auf kontinuierliche (regelmäßige) Syncronisation zwischen den Forests optimiert, Änderungen werden erkannt und markiert.
# Objekte, die in dem Zielforest angelegt werden, werden nicht gelöscht oder geändert, sondern bleiben parallel stehen.
# Die Syncronisation besteht aus 2 Skripts, jeweils 1 für den Export aus dem Quellsystem und 1 für den Import ind as Zielsystem
#
#
#  Author: Tobias Kuch
# 
#  Version 0.8 Beta  Datum: 27.03.2017
#
#  Teil B:  Import Script
#

$Error.clear()

#Common Configurations
$DatabaseFile = "ADData.xml"
$DatabasePath = "Path_TO_XML_Databasefile"
$Database = $DatabasePath + $DatabaseFile 


$DNSTargetDomainName = "VAR_TargetDomainName.TopLevelDomain(eg.com)"
$DNSSourceDomainName = "VAR_SourceDomainName.TopLevelDomain(eg.com)"

$DNTargetDomain = "DC=VAR_TargetDomainName,DC=TopLevelDomain(eg.com)"
$DNSourceDomain = "DC=VAR_SourceDomainName,DC=TopLevelDomain(eg.com)"

$MailTargetDomain = "@VAR_TargetDomainName.TopLevelDomain(eg.com)"
$MailSourceDomain = "@VAR_SourceDomainName.TopLevelDomain(eg.com)"


$GlobalUserPassword = "VAR_GlobalPAsswordForALLNewUsers"
$AuthTargetDC = "VAR_Domaincontroller.VAR_TargetDomainName.TopLevelDomain(eg.com)" 


Function Main ()
{
clear-host

write-host "Preparing.."

try
{
Import-Module Activedirectory
}
catch
{
write-host ""
write-host "Error: Could not read Target Domain Objects. Error: " $Error -ForegroundColor red 
write-host "Terminated." -ForegroundColor red 
exit 1
}

IF (Test-Path $Database)  
{ 
write-host "Reading Database. " -nonewline
$AllDBADObjects = $null
$AllDBADObjects = Import-Clixml -Path $Database

#$AllDBADObjects3 = $AllDBADObjects | ? { $_ -ne $NULL} 
write-host " done.."
write-host "System Update in Progress.."
$UpdateTimeTaken = Measure-Command { $AllDBADObjects = Update-System $AllTargetADObjects $AllDBADObjects }
write-host "System Update in" $UpdateTimeTaken.TotalSeconds "Seconds finished."
    try
    {
    write-host "Database update" -NoNewline
    Remove-Item -Path $Database -force
    $DBUpdateTimeTaken = Measure-Command { Export-Clixml -Path $Database -InputObject $AllDBADObjects -Force }
    write-host " sucessfully." -ForegroundColor Green
    $AllTargetADObjects = @()
    write-host "Database Update in" $DBUpdateTimeTaken.TotalSeconds "Seconds finished."
    }
    catch
    {
    write-host ""
    write-host "Error: Database could not be updated." $Error -ForegroundColor red
    exit 1
    }
}
else
{
    write-host "Error: Database" $Database "could not be found or is not accessible." -ForegroundColor red
    write-host "Terminated" -ForegroundColor red
    exit 1
}
$TotalMinutes = $DBUpdateTimeTaken.TotalMinutes + $UpdateTimeTaken.TotalMinutes
write-host "Run completed in" $TotalMinutes  "Minutes. "

exit 0
}



Function Update-System ( $2LiveSystemDataretired, $DatabaseData )
{
 $UpdateCount = 0


 $DatabaseData = Exclude-SyncronizationObjectsbyFixedRule ( $DatabaseData )
 $DBOU = $DatabaseData   | ? { $_.objectclass -eq "organizationalUnit" } 
 $DBGroups = $DatabaseData | ?  { $_.objectclass -eq "group" }
 $DBUsers = $DatabaseData | ?  { $_.objectclass -eq "user" }
 $DBContact = $DatabaseData | ? { $_.objectclass -eq "contact" }
 $SumA = @($DBOU).count + @($DBGroups).count + @($DBUsers).count + @($DBContact).count
 $SumB = @($DatabaseData).count
 IF ($SumA -ne $SumB) 
    {
    write-host "Internal Error in Function Update-System: Not equal." -ForegroundColor red
    write-host "Terminated." -ForegroundColor red
    exit 1
    }



 IF (@($DBOU).count -gt 0)  
    {
    $DBOUCOPY=$DBOU
    $DBOUCOPY=$DBOUCOPY | sort DNLength
    $NEWDBOU =$DBOUCOPY | ? { $_.State -eq "N" -and $_.HasToBeSync -eq $true  }   
    IF (@($NEWDBOU).count -gt 0) 
        {
        try
            {
            write-host "Getting OU-Objects from Targetdomain. " -nonewline
            $LiveSystemData = Get-ADObject -Filter { (objectclass -eq "organizationalUnit")  } -Properties ObjectClass,Name,ObjectGUID,DistinguishedName,Description,ProtectedFromAccidentalDeletion,uSNChanged,whenChanged,ou,gPLink -server $AuthTargetDC
            write-host " done.." 
            }
            catch
            {
            write-host ""
            write-host "Error: Could not read Target Domain Objects. Error: " $Error -ForegroundColor red 
            write-host "Terminated." -ForegroundColor red 
            exit 1
            }
        ForEach ($Item in $NEWDBOU)     
            {
            $TargetSystemDistinguishedName = $Item.DistinguishedName -replace $DNSourceDomain, $DNTargetDomain 
            IF  ( $LiveSystemData | ? { $_.DistinguishedName -eq $TargetSystemDistinguishedName })
                {
                write-host "Object"$TargetSystemDistinguishedName"still exists in Taget Domain, skipped and marked!" -ForegroundColor yellow
                $Item.HasToBeSync = $false
                $Item.State = "S"
                } else
                {
                $Item = (Add-NEWOU $Item) 
                }

            }
        }
    $NEWDBOU =$DBOUCOPY | ? { $_.State -eq "I" -and $_.HasToBeSync -eq $true  }   
    IF (@($NEWDBOU).count -gt 0) 
        {
        ForEach ($Item in $NEWDBOU)   
            {
            $Item = (Add-NEWOU $Item) 
            }
        }
   
    $NEWDBOU =$DBOUCOPY | ? { $_.State -eq "U" -and $_.HasToBeSync -eq $true  }   
    IF (@($NEWDBOU).count -gt 0) 
        {
        ForEach ($Item in $NEWDBOU)     
            {
            $Item = (Modify-OU $Item) 
            }
        }
    }



IF (@($DBUsers).count -gt 0) 
    {
    $DBUsersCOPY=$DBUsers
    $DBUsersCOPY=$DBUsersCOPY | sort DNLength
    $NEWDBUsers =$DBUsersCOPY | ? { $_.State -eq "N" -and $_.HasToBeSync -eq $true  }   
    IF (@($NEWDBUsers).count -gt 0) 
        {
        try
            {
            write-host "Getting User-Objects from Targetdomain. " -nonewline
            $LiveSystemData = Get-ADObject -Filter { objectclass -eq "user" } -Properties ObjectClass,Name,ObjectGUID,DistinguishedName,uSNChanged,whenChanged,sAMAccountName,sAMAccountType,CN,CanonicalName,Description,DisplayName,sn,givenName,department,l,c,co,comment,company,st,streetAddress,telephoneNumber,physicalDeliveryVAR_SourceDomainNameName,postalCode,houseIdentifier,primaryGroupID,roomNumber,title,userAccountControl,userPrincipalName,codepage,employeeID,HomeTopLevelDomain(eg.com)ectory,homeDrive,scriptPath,memberOf,mail -server $AuthTargetDC | ? { $_.objectclass -eq "user" }
            write-host " done.. "
            }
            catch
            {
            write-host ""
            write-host "Error: Could not read Target Domain Objects. Error: " $Error -ForegroundColor red 
            write-host "Terminated." -ForegroundColor red 
            exit 1
            }
        ForEach ($Item in $NEWDBUsers)     
            {

            $TargetSystemDistinguishedName = $Item.DistinguishedName -replace $DNSourceDomain, $DNTargetDomain 
            IF  ( $LiveSystemData | ? { $_.DistinguishedName -eq $TargetSystemDistinguishedName })
                {
                write-host "Object"$TargetSystemDistinguishedName"still exists in Target Domain, skipped and marked! " -ForegroundColor yellow
                $Item.HasToBeSync = $false
                $Item.State = "S"
                } else
                {
                $Item = (Add-NEWUser $Item)
                $Item = (Modify-User $Item) 
                }

            }
        }

    
    $NEWDBUsers =$DBUsersCOPY | ? { $_.State -eq "I" -and $_.HasToBeSync -eq $true  }   
    IF (@($NEWDBUsers).count -gt 0) 
        {
        ForEach ($Item in $NEWDBUsers)    
            {
            $Item = (Add-NEWUser $Item)
            $Item = (Modify-User $Item) 
            }
        }
   
    $NEWDBUsers =$DBUsersCOPY | ? { $_.State -eq "D" -and $_.HasToBeSync -eq $true  }   
    IF (@($NEWDBUsers).count -gt 0) 
        {
        ForEach ($Item in $NEWDBUsers)    
            {
            $Item = (Del-OldUser $Item) 
            }
        }
  
    $NEWDBUsers =$DBUsersCOPY| ? { $_.State -eq "U" -and $_.HasToBeSync -eq $true  } 
    IF (@($NEWDBUsers).count -gt 0) 
        {
        ForEach ($Item in $NEWDBUsers)     
            {
            $Item = (Modify-User  $Item) 
            }
        }
    }


IF (@($DBGroups).count -gt 0) 
    {
    $DBGroupsCOPY=$DBGroups
    $DBGroupsCOPY=$DBGroupsCOPY | sort DNLength
    $NEWDBGroup =$DBGroupsCOPY | ? { $_.State -eq "N" -and $_.HasToBeSync -eq $true  }   
    IF (@($NEWDBGroup).count -gt 0)
        {
        try
            {
            write-host "Getting Group-Objects from Targetdomain. " -nonewline
            $LiveSystemData= Get-ADObject -Filter { (objectclass -eq "group") } -Properties ObjectClass,Name,ObjectGUID,DistinguishedName,uSNChanged,whenChanged,sAMAccountName,sAMAccountType,CN,CanonicalName,Description,DisplayName,groupType,mail,member,info,ManagedBy -server $AuthTargetDC
            write-host " done.." 
            }
            catch
            {
            write-host ""
            write-host "Error: Could not read Target Domain Objects. Error: " $Error -ForegroundColor red 
            write-host "Terminated." -ForegroundColor red 
            exit 1
            }
        ForEach ($Item in $NEWDBGroup)     
            {
            $TargetSystemDistinguishedName = $Item.DistinguishedName -replace $DNSourceDomain, $DNTargetDomain
            IF  ( $LiveSystemData | ? { $_.DistinguishedName -eq $TargetSystemDistinguishedName })
                {
                write-host "Object"$TargetSystemDistinguishedName" still exists in Taget Domain, skipped and marked!" -ForegroundColor yellow
                $Item.HasToBeSync = $false
                $Item.State = "S"
                } else
                {
                $Item = (Add-NEWGroup $Item)
                $Item = (Update-MembersofGroup $Item) 
                }

            }
        }

    $NEWDBGroup =$DBGroupsCOPY | ? { $_.State -eq "I" -and $_.HasToBeSync -eq $true  }   
    IF (@($NEWDBGroup).count -gt 0) 
        {
        ForEach ($Item in $NEWDBGroup)    
            {
            $Item = (Add-NEWGroup $Item)
            $Item = (Update-MembersofGroup $Item) 
            }
        }
    $NEWDBGroup =$DBGroupsCOPY | ? { $_.State -eq "D" -and $_.HasToBeSync -eq $true  }   
    IF (@($NEWDBGroup).count -gt 0) 
        {
        ForEach ($Item in $NEWDBGroup)     
            {
            $Item = (Del-OLDGroup $Item) 
            }
        }
    $NEWDBGroup =$DBGroupsCOPY | ? { $_.State -eq "U" -and $_.HasToBeSync -eq $true  }   
    IF (@($NEWDBGroup).count -gt 0) 
        {
        ForEach ($Item in $NEWDBGroup)     
            {
            $Item = (Modify-Group  $Item)
            $Item = (Update-MembersofGroup $Item) 
            }
        }
    }


 IF (@($DBOU).count -gt 0)  
    {
    $DBOUCOPY=$DBOU
    $DBOUCOPY=$DBOUCOPY | sort DNLength -Descending
    $NEWDBOU =$DBOUCOPY | ? { $_.State -eq "D" -and $_.HasToBeSync -eq $true  }   
    IF (@($NEWDBOU).count -gt 0) 
        {
        ForEach ($Item in $NEWDBOU)     
            {
            $Item = (Del-OLDOU $Item) 
            }
        }
  
    }
$DBOU = $null
$DBGroups  = $null
$DBUsers = $null
$DBContact = $null
Return $DatabaseData 

}



Function Add-NEWGroup ($GrpOBJ)
{
  try 
    {
    $VPathDN = $GrpOBJ.DistinguishedName -replace $DNSourceDomain, $DNTargetDomain 
    $VManagedby =  $GrpOBJ.managedBy -replace $DNSourceDomain, $DNTargetDomain 
    $Temp = $VPathDN.Split(",")
    $Temp2 = $Temp[0].Length +1
    $VPathDN = $VPathDN.Substring($Temp2)

    $Temp = $NULL
    $Temp4 = $NULL
    write-host "Create Group" $GrpOBJ.name "in Path" $VPathDN -NoNewline

    $Specified = $false
    IF ($GrpOBJ.GroupType -eq "2")
        {
        $GrpScope = "Global"
        $GrpCat = "Distribution"
        $Specified = $true
        }
    IF ($GrpOBJ.GroupType -eq "4")
        {
        $GrpScope = "DomainLocal"
        $GrpCat = "Distribution"
        $Specified = $true
        }
    IF ($GrpOBJ.GroupType -eq "8")
        {
        $GrpScope = "Universal"
        $GrpCat = "Distribution"
        $Specified = $true
        }
    IF ($GrpOBJ.GroupType -eq "-2147483646")
        {
        $GrpScope = "Global"
        $GrpCat = "Security"
        $Specified = $true
        }
    IF ($GrpOBJ.GroupType -eq "-2147483644")
        {
        $GrpScope = "DomainLocal"
        $GrpCat = "Security"
        $Specified = $true
        }
    IF ($GrpOBJ.GroupType -eq "-2147483640")
        {
        $GrpScope = "Universal"
        $GrpCat = "Security"
        $Specified = $true
        }
    IF(!$Specified)
        {
        write-host " failed. Error: Grouptype not determinable."  -ForegroundColor red
        $error.clear()
        return $GrpOBJ
        }
    
    New-ADGroup -Name $GrpOBJ.Name -GroupScope $GrpScope -Path $VPathDN -DisplayName $GrpOBJ.Displayname -GroupCategory $GrpCat -SamAccountName $GrpOBJ.sAMAccountName -Server $AuthTargetDC 
    $Compare = $GrpOBJ.DistinguishedName -replace $DNSourceDomain, $DNTargetDomain 
    $result = Get-ADObject -Filter { DistinguishedName -eq $Compare }  -Properties ObjectGUID,DistinguishedName,uSNChanged,whenChanged -Server $AuthTargetDC
    IF ($Result)
        {
        write-host " success." -ForegroundColor green
        $GrpOBJ.TargetSystemObjectGUID = $Result.ObjectGUID
        $GrpOBJ.TargetSystemuSNChanged = $Result.uSNChanged
        $GrpOBJ.TargetSystemwhenChanged = $Result.whenChanged
        $GrpOBJ.State = "S"
        } else
        {
        write-host " failed. Error: Get-ADObject -Filter { DistinguishedName -eq '"$Compare "' }"-ForegroundColor red
        $error.clear()
        }
    }
    catch
    {
    write-host " failed. Error:" $Error -ForegroundColor red
    $error.clear()
    }
 return $GrpOBJ
}


Function Del-OldGroup ($GrpOBJ)
{
  try 
    {
    $VPathDN = $GrpOBJ.DistinguishedName -replace $DNSourceDomain, $DNTargetDomain 
    $Temp = $VPathDN.Split(",")
    $Temp2 = $Temp[0].Length +1
    $VPathDN = $VPathDN.Substring($Temp2)

    $Temp = $NULL
    $Temp4 = $NULL
    write-host "Delete Group" $GrpOBJ.name "in Path" $VPathDN -NoNewline
   
    Remove-ADGroup -Identity $GrpOBJ.sAMAccountName -Confirm:$false -Server $AuthTargetDC 
  
    $Compare = $GrpOBJ.DistinguishedName -replace $DNSourceDomain, $DNTargetDomain 
    $result = Get-ADObject -Filter { DistinguishedName -eq $Compare }  -Properties ObjectGUID,DistinguishedName,uSNChanged,whenChanged -Server $AuthTargetDC
    IF ($Result)
        {
        write-host " failed. Error: Get-ADObject -Filter { DistinguishedName -eq '"$Compare "' }"-ForegroundColor red
        $error.clear()
        } else
        {
        write-host " success." -ForegroundColor green
        $GrpOBJ.TargetSystemObjectGUID = $Result.ObjectGUID
        $GrpOBJ.TargetSystemuSNChanged = $Result.uSNChanged
        $GrpOBJ.TargetSystemwhenChanged = $Result.whenChanged
        $GrpOBJ.State = "S"
        }
    }
    catch
    {
    write-host " failed. Error:" $Error -ForegroundColor red
    $error.clear()
    }
 return $GrpOBJ
}



Function Update-MembersofGroup ($GrpOBJ)
{

    $GrpChangeDone = $false
    $VPathDN = $GrpOBJ.DistinguishedName -replace $DNSourceDomain, $DNTargetDomain 
    try
        {
        $ISTargetMember =Get-ADGroupMember -Identity $GrpOBJ.SamAccountName -Server $AuthTargetDC  
        IF (@($ISTargetMember).count -gt 500)
            {
            write-host "Update Group-Membership of" $GrpOBJ.name "in Path" $VPathDN -NoNewline
            write-host " failed. Error: Member count greater than 500." -ForegroundColor red
            $error.clear()
            $GrpOBJ.State = "U"
            return $GrpOBJ
            }
        }
        catch
        {
        write-host "Update Group-Membership of" $GrpOBJ.name "in Path" $VPathDN -NoNewline
        write-host " failed. Error: " $error -ForegroundColor red
        $error.clear()
        $GrpOBJ.State = "U"
        return $GrpOBJ
        }
       
    $ShouldTargetMember = $GrpOBJ.member

    
    $ISTargetMember = $ISTargetMember | sort 
    $ShouldTargetMember = $ShouldTargetMember | sort
    [String]$ISTargetMemberStr = $ISTargetMember
    [String]$ShouldTargetMemberStr = $ShouldTargetMember
    
   $GrpOBJ.State = "U"
   $GrpChangeDone = $true
    ForEach ($member in $ShouldTargetMember)
        {
       
        try
            {
            $targetmember = $member -replace $DNSourceDomain, $DNTargetDomain 
            Add-ADGroupMember -Identity $GrpOBJ.sAMAccountName -Members $targetmember -Confirm:$false -Server $AuthTargetDC 
            }
        catch
            {
            $GrpChangeDone = $false
            write-host "Update Group-Membership of" $GrpOBJ.name "with Account " $targetmember -NoNewline
            write-host " failed. Error:" $error -ForegroundColor Red
            $error.clear()
   
            }

        }

    IF ($GrpChangeDone)
        {
        write-host "Update Group-Membership of" $GrpOBJ.name  -NoNewline
        write-host " success. " -ForegroundColor green
        $GrpOBJ.State = "S"
        }
  
   
 return $GrpOBJ
}





Function Modify-Group ($GrpOBJ)
{
write-host "Modify Group: Empty procedure" -ForegroundColor yellow
return $GrpOBJ
}



Function Add-NEWUser ($UserOBJ)
{
  try 
    {
    $VPathDN = $UserOBJ.DistinguishedName -replace $DNSourceDomain, $DNTargetDomain 
    $Temp = $VPathDN.Split(",")
    $Temp2 = $Temp[0].Length +1
    $VPathDN = $VPathDN.Substring($Temp2)

    $Temp = $NULL
    $Temp4 = $NULL
    write-host "Create User" $UserOBJ.name "in Path" $VPathDN -NoNewline
    $userAccountControlValue = $UserOBJ.userAccountControl
    $AccSCRIPT  = $userAccountControlValue -band 0x0001 
    $AccACCOUNTDISABLE = $userAccountControlValue -band 0x0002 
    $AccHOMETopLevelDomain(eg.com)_REQUIRED = $userAccountControlValue -band 0x0008 
    $AccLOCKOUT = $userAccountControlValue -band 0x0010 
    $AccPASSWD_NOTREQD = $userAccountControlValue -band 0x0020 
    $AccPASSWD_CANT_CHANGE = $userAccountControlValue -band 0x0040 
    $AccENCRYPTED_TEXT_PWD_ALLOWED = $userAccountControlValue -band 0x0080 
    $AccTEMP_DUPLICATE_ACCOUN = $userAccountControlValue -band 0x00100 
    $AccNORMAL_ACCOUNT = $userAccountControlValue -band 0x00200   
    $AccINTERDOMAIN_TRUST_ACCOUNT = $userAccountControlValue -band 0x00800   
    $AccWORKSTATION_TRUST_ACCOUNT = $userAccountControlValue -band 0x01000 
    $AccSERVER_TRUST_ACCOUNT = $userAccountControlValue -band 0x02000  
    $AccDONT_EXPIRE_PASSWORD = $userAccountControlValue -band 0x10000 
    $AccMNS_LOGON_ACCOUNT = $userAccountControlValue -band 0x20000 
    $AccSMARTCARD_REQUIRED = $userAccountControlValue -band 0x40000  
    $AccTRUSTED_FOR_DELEGATION = $userAccountControlValue -band 0x80000  
    $AccNOT_DELEGATED = $userAccountControlValue -band 0x100000 
    $AccUSE_DES_KEY_ONLY = $userAccountControlValue -band 0x200000 
    $AccDONT_REQ_PREAUTH = $userAccountControlValue -band 0x400000 
    $AccPASSWORD_EXPIRED = $userAccountControlValue -band 0x800000  
    $AccTRUSTED_TO_AUTH_FOR_DELEGATION = $userAccountControlValue -band  0x1000000  
    $AccPARTIAL_SECRETS_ACCOUNT = $userAccountControlValue -band 0x04000000    
    $VuserPrincipalName = $UserOBJ.userPrincipalName -replace $DNSSourceDomainName, $DNSTargetDomainName 
    $Secure_String_Pwd = ConvertTo-SecureString -String $GlobalUserPassword -AsPlainText -Force
    $AccACCOUNTDISABLE = !$AccACCOUNTDISABLE   
    New-ADUser -Name $UserOBJ.CN -Path $VPathDN -AccountPassword $Secure_String_Pwd -ChangePasswordAtLogon $false -CannotChangePassword $AccPASSWD_CANT_CHANGE -TrustedForDelegation $AccTRUSTED_FOR_DELEGATION -SmartcardLogonRequired $AccSMARTCARD_REQUIRED -PasswordNeverExpires $AccDONT_EXPIRE_PASSWORD -PasswordNotRequired $AccPASSWD_NOTREQD -DisplayName $UserOBJ.DisplayName -Enabled $AccACCOUNTDISABLE -SamAccountName $UserOBJ.sAMAccountName -UserPrincipalName $VuserPrincipalName -Confirm:$false -Server $AuthTargetDC 
    $Compare = $UserOBJ.DistinguishedName -replace $DNSourceDomain, $DNTargetDomain
    $result = $null
    $result = Get-ADObject -Filter { DistinguishedName -eq $Compare }  -Properties ObjectGUID,DistinguishedName,uSNChanged,whenChanged -Server $AuthTargetDC
    IF ($Result)
        {
        write-host " success." -ForegroundColor green
        $UserOBJ.TargetSystemObjectGUID = $Result.ObjectGUID
        $UserOBJ.TargetSystemuSNChanged = $Result.uSNChanged
        $UserOBJ.TargetSystemwhenChanged = $Result.whenChanged
        $UserOBJ.State = "S"
        } else
        {
        write-host " failed. Error: Get-ADObject -Filter { DistinguishedName -eq '"$Compare "' }"-ForegroundColor red
        $error.clear()
        }
    }
    catch
    {
    write-host " failed. Error:" $Error -ForegroundColor red
    $error.clear()
    }
 return $UserOBJ
}


Function Del-OldUser ($UserOBJ)
{
 
  try 
    {
    $VPathDN = $UserOBJ.DistinguishedName -replace $DNSourceDomain, $DNTargetDomain
    $Temp = $VPathDN.Split(",")
    $Temp2 = $Temp[0].Length +1
    $VPathDN = $VPathDN.Substring($Temp2)

    $Temp = $NULL
    $Temp4 = $NULL
    write-host "Delete User" $UserOBJ.name "in Path" $VPathDN -NoNewline  
    Remove-ADUser -Identity $UserOBJ.sAMAccountName -Confirm:$false -Server $AuthTargetDC 
    $Compare = $UserOBJ.DistinguishedName -replace $DNSourceDomain, $DNTargetDomain 
    $result = Get-ADObject -Filter { DistinguishedName -eq $Compare }  -Properties ObjectGUID,DistinguishedName,uSNChanged,whenChanged -Server $AuthTargetDC
    IF ($Result)
        {
        write-host " failed. Error: Get-ADObject -Filter { DistinguishedName -eq '"$Compare "' }"-ForegroundColor red
        $error.clear()
        } else
        {
        write-host " success." -ForegroundColor green
        $UserOBJ.TargetSystemObjectGUID = $Result.ObjectGUID
        $UserOBJ.TargetSystemuSNChanged = $Result.uSNChanged
        $UserOBJ.TargetSystemwhenChanged = $Result.whenChanged
        $UserOBJ.State = "S"
        }
    }
    catch
    {
    write-host " failed. Error:" $Error -ForegroundColor red
    $error.clear()
    }
 return $UserOBJ
}



Function Modify-User ($UserOBJ)
{
$VPathDN = $UserOBJ.DistinguishedName -replace $DNSourceDomain, $DNTargetDomain 
$Temp = $VPathDN.Split(",")
$Temp2 = $Temp[0].Length +1
$VPathDN = $VPathDN.Substring($Temp2)
$Temp = $NULL
$Temp4 = $NULL
$userAccountControlValue = $UserOBJ.userAccountControl
$AccSCRIPT  = $userAccountControlValue -band 0x0001 
$AccACCOUNTDISABLE = $userAccountControlValue -band 0x0002 
$AccHOMETopLevelDomain(eg.com)_REQUIRED = $userAccountControlValue -band 0x0008 
$AccLOCKOUT = $userAccountControlValue -band 0x0010 
$AccPASSWD_NOTREQD = $userAccountControlValue -band 0x0020 
$AccPASSWD_CANT_CHANGE = $userAccountControlValue -band 0x0040 
$AccENCRYPTED_TEXT_PWD_ALLOWED = $userAccountControlValue -band 0x0080 
$AccTEMP_DUPLICATE_ACCOUN = $userAccountControlValue -band 0x00100 
$AccNORMAL_ACCOUNT = $userAccountControlValue -band 0x00200   
$AccINTERDOMAIN_TRUST_ACCOUNT = $userAccountControlValue -band 0x00800   
$AccWORKSTATION_TRUST_ACCOUNT = $userAccountControlValue -band 0x01000 
$AccSERVER_TRUST_ACCOUNT = $userAccountControlValue -band 0x02000  
$AccDONT_EXPIRE_PASSWORD = $userAccountControlValue -band 0x10000 
$AccMNS_LOGON_ACCOUNT = $userAccountControlValue -band 0x20000 
$AccSMARTCARD_REQUIRED = $userAccountControlValue -band 0x40000  
$AccTRUSTED_FOR_DELEGATION = $userAccountControlValue -band 0x80000  
$AccNOT_DELEGATED = $userAccountControlValue -band 0x100000 
$AccUSE_DES_KEY_ONLY = $userAccountControlValue -band 0x200000 
$AccDONT_REQ_PREAUTH = $userAccountControlValue -band 0x400000 
$AccPASSWORD_EXPIRED = $userAccountControlValue -band 0x800000  
$AccTRUSTED_TO_AUTH_FOR_DELEGATION = $userAccountControlValue -band  0x1000000  
$AccPARTIAL_SECRETS_ACCOUNT = $userAccountControlValue -band 0x04000000   
$VuserPrincipalName = $UserOBJ.userPrincipalName -replace $DNSSourceDomainName, $DNSTargetDomainName 
$AccACCOUNTDISABLE = !$AccACCOUNTDISABLE
write-host "Modify Attributes of User" $UserOBJ.SamaccountName -NoNewline 
IF (($UserOBJ.employeeID  -eq "" )  -or ($UserOBJ.employeeID -eq $null ))
    {
    $emp1 = $null
    } else
    {
    $emp1 = $UserOBJ.employeeID
    }
 IF (($UserOBJ.DisplayName -eq "" )  -or ($UserOBJ.DisplayName -eq $null ))
    {
    $Dispname = $null
    } else
    {
    $Dispname = $UserOBJ.DisplayName
    }
IF (($UserOBJ.Description -eq "" ) -or ($UserOBJ.Description -eq $null ))  
    {
    $desc = $null
    } else
    {
    $desc = $UserOBJ.Description
    }
IF (($UserOBJ.givenName -eq "" ) -or ($UserOBJ.givenName -eq $null ))  
    {
    $givenName1 = $null
    } else
    {
    $givenName1 = $UserOBJ.givenName
    }
IF (($UserOBJ.sn -eq "" ) -or ($UserOBJ.sn -eq $null ))   
    {
    $SurName1 = $null
    } else
    {
    $SurName1 = $UserOBJ.sn
    }
IF (($UserOBJ.HomeTopLevelDomain(eg.com)ectory -eq "" ) -or ($UserOBJ.HomeTopLevelDomain(eg.com)ectory -eq $null ))  
    {
    $homed = $null
    } else
    {
    $homed = $UserOBJ.HomeTopLevelDomain(eg.com)ectory
    }
IF (($UserOBJ.homeDrive -eq "" ) -or ($UserOBJ.homeDrive -eq $null ))  
    {
    $homed1 = $null
    } else
    {
    $homed1 = $UserOBJ.homeDrive
    }
IF (($UserOBJ.department -eq "" ) -or ($UserOBJ.department -eq $null ))  
    {
    $dep1 = $null
    } else
    {
    $dep1 = $UserOBJ.department
    }
IF (($UserOBJ.scriptPath -eq "" ) -or ($UserOBJ.scriptPath -eq $null ))  
    {
    $dscript = $null
    } else
    {
    $dscript = $UserOBJ.scriptPath
    }
IF (($UserOBJ.streetAddress -eq "" ) -or ($UserOBJ.streetAddress -eq $null ))  
    {
    $StrAddr = $null
    } else
    {
    $StrAddr = $UserOBJ.streetAddress
    }
IF (($UserOBJ.mail -eq "" ) -or ($UserOBJ.mail -eq $null ))  
    {
    $mail1 = $null
    } else
    {
    $mail2  = $UserOBJ.mail
    $mail1 = $mail2 -replace $MailSourceDomain, $MailTargetDomain  
    }
IF (($UserOBJ.company -eq "" ) -or ($UserOBJ.company -eq $null ))  
    {
    $comp1  = $null
    } else
    {
    $comp1 = $UserOBJ.company
    }
IF (($UserOBJ.l -eq "" ) -or ($UserOBJ.l -eq $null ))  
    {
    $comp1  = $null
    } else
    {
    $city1= $UserOBJ.l
    }
IF (($UserOBJ.telephoneNumber -eq "" ) -or ($UserOBJ.telephoneNumber -eq $null ))  
    {
    $Phone  = $null
    } else
    {
    $Phone = $UserOBJ.telephoneNumber
    } 
IF (($UserOBJ.title -eq "" ) -or ($UserOBJ.title -eq $null ))  
    {
    $tit1  = $null
    } else
    {
    $tit1 = $UserOBJ.title
    }    
IF (($UserOBJ.PostalCode -eq "" ) -or ($UserOBJ.PostalCode -eq $null ))  
    {
    $PC = $null
    } else
    {
    $PC = $UserOBJ.PostalCode
    } 
IF (($UserOBJ.co  -eq "" ) -or ($UserOBJ.co -eq $null ))  
    {
    $CO = $null
    } else
    {
    $CO = $UserOBJ.co 
    }     
    
try
    {
    Set-ADUser -Identity $UserOBJ.TargetSystemObjectGUID -GivenName $GivenName1 -Surname $SurName1 -DisplayName $Dispname -Title $tit1 -EmailAddress $mail1 -VAR_SourceDomainNamePhone $Phone -Company $comp1 -StreetAddress $StrAddr -City $city1 -PostalCode $PC -ScriptPath $dscript -Department $dep1 -HomeTopLevelDomain(eg.com)ectory $homed -HomeDrive $homed1 -CannotChangePassword $AccPASSWD_CANT_CHANGE -TrustedForDelegation $AccTRUSTED_FOR_DELEGATION -SmartcardLogonRequired $AccSMARTCARD_REQUIRED -PasswordNeverExpires $AccDONT_EXPIRE_PASSWORD -PasswordNotRequired $AccPASSWD_NOTREQD -Enabled $AccACCOUNTDISABLE -SamAccountName $UserOBJ.sAMAccountName -UserPrincipalName $VuserPrincipalName -Description $desc -EmployeeID $emp1 -Confirm:$false -Server $AuthTargetDC 
    $result = $null
    write-host " success." -ForegroundColor green
    $UserOBJ.TargetSystemuSNChanged = $Result.uSNChanged
    $UserOBJ.TargetSystemwhenChanged = $Result.whenChanged
    $UserOBJ.State = "S"
  
    }
    catch
    {
    write-host " failed. Error:" $Error -ForegroundColor red
    $UserOBJ.State = "U"
    $error.clear()
    }

return $UserOBJ
}



Function Add-NEWOU ($OUOBJ)
{
  try 
    {
    $VPathDN = $OUOBJ.DistinguishedName -replace $DNSourceDomain, $DNTargetDomain 
    $Temp = $VPathDN.Split(",")
    $Temp2 = $Temp[0].Length +1
    $VPathDN = $VPathDN.Substring($Temp2)

    $Temp = $NULL
    $Temp4 = $NULL
    write-host "Create OU" $OUOBJ.name "in Path" $VPathDN -NoNewline
    New-ADOrganizationalUnit -Name $OUOBJ.name -Path $VPathDN -ProtectedFromAccidentalDeletion $OUOBJ.ProtectedFromAccidentalDeletion -server $AuthTargetDC
    $Compare = $OUOBJ.DistinguishedName -replace $DNSourceDomain, $DNTargetDomain 
    $result = Get-ADObject -Filter { DistinguishedName -eq $Compare }  -Properties ObjectGUID,DistinguishedName,uSNChanged,whenChanged
    IF ($Result)
        {
        write-host " success." -ForegroundColor green
        $OUOBJ.TargetSystemObjectGUID = $Result.ObjectGUID
        $OUOBJ.TargetSystemuSNChanged = $Result.uSNChanged
        $OUOBJ.TargetSystemwhenChanged = $Result.whenChanged
        $OUOBJ.State = "S"
        } else
        {
        write-host " failed. Error: Get-ADObject -Filter { DistinguishedName -eq '"$Compare "' }"-ForegroundColor red
        $error.clear()
        }
    }
    catch
    {
    write-host " failed. Error:" $Error -ForegroundColor red
    $error.clear()
    }
 return $OUOBJ
}



Function Del-OLDOU ($OUOBJ)
{
  try 
    {
    $VPathDN = $OUOBJ.DistinguishedName -replace $DNSourceDomain, $DNTargetDomain 
    $TargetSystemDistinguishedName = $OUOBJ.DistinguishedName -replace $DNSourceDomain, $DNTargetDomain 
    $Temp = $VPathDN.Split(",")
    $Temp2 = $Temp[0].Length +1
    $VPathDN = $VPathDN.Substring($Temp2)
    $Temp = $NULL
    $Temp4 = $NULL
    write-host "Delete OU" $OUOBJ.name "in Path" $VPathDN -NoNewline
    Get-ADOrganizationalUnit -Identity $TargetSystemDistinguishedName | Set-ADObject -ProtectedFromAccidentalDeletion:$false -PassThru | Remove-ADOrganizationalUnit -server $AuthTargetDC -Confirm:$false  
    $Compare = $TargetSystemDistinguishedName
    $result = Get-ADObject -Filter { DistinguishedName -eq $Compare }  -Properties ObjectGUID,DistinguishedName,uSNChanged,whenChanged -server $AuthTargetDC
    IF (!($Result))
        {
        write-host " success." -ForegroundColor green
        $OUOBJ.State = "S"
        } else
        {
        write-host " failed. Error: Get-ADObject -Filter { DistinguishedName -eq '"$TargetSystemDistinguishedName "' }"-ForegroundColor red
        $error.clear()
        }
    }
    catch
    {
    write-host " failed. Error:" $Error -ForegroundColor red
    $error.clear()
    }
 return $OUOBJ
}

Function Modify-OU ($OUOBJ)
{
write-host "Modify OU: Empty procedure" -ForegroundColor yellow
return $OUOBJ
}



Function Exclude-SyncronizationObjectsbyFixedRule ( $InputObject )
{
$ExcludeDN = "CN=Microsoft Exchange System Objects,DC=VAR_SourceDomainName,DC=TopLevelDomain(eg.com)"
$SubSet = $InputObject | ? { $_.DistinguishedName -Match $ExcludeDN }
IF (@($SubSet).count -gt 0 )
    {
        ForEach ($Item in $SubSet )
        {  
        write-host "Object"$Item.Name"excluded. Violation of Syncronisation Rule(s) !" -ForegroundColor yellow
        $Item.HasToBeSync = $false
        $Item.State = "S"
        }
    }


Return $InputObject
}





Main

