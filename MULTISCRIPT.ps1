$bb = Import-Csv C:\Users\a-edwardsbr.old\Documents\Options.csv | Out-GridView  -Title "Select a script" -OutputMode multiple

if ($bb.'Select a type' -eq "AD")
{ 
$cc = Import-Csv C:\Users\a-edwardsbr.old\Documents\scripts2.csv | Out-GridView  -Title "Select a script" -OutputMode multiple
}

if ($bb.'Select a type' -eq "SCCM")
{ 
$dd = Import-Csv C:\Users\a-edwardsbr.old\Documents\scripts3.csv | Out-GridView  -Title "Select a script" -OutputMode multiple
}

if ($bb.'Select a type' -eq "Licenses")
{ 
$licenses = Import-Csv C:\Users\a-edwardsbr.old\Documents\licenses.csv | Out-GridView  -Title "Select a License" -OutputMode multiple
}

if ($cc.script -eq "Password Reset")
{

$user = read-host -Prompt "

Enter username"

$pass = read-host -Prompt "

Enter password to change to"


 Set-ADAccountPassword -Identity $user -NewPassword (ConvertTo-SecureString -AsPlainText "$pass" -Force)
 

}

if ($cc.script -eq "Check PASSWORD Expiry date")
{ 

$user = read-host -Prompt "

Enter username"

Get-ADUser -identity $user -Properties msDS-UserPasswordExpiryTimeComputed | select samaccountname,@{ Name = "Expiration Date"; Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}}

}

if ($cc.script -eq "List Last log on date")
{ 

$user = read-host -Prompt "

Enter username"


Get-ADUser $user -Properties * | select samaccountname,@{ Name = "Last logon date"; Expression={[datetime]::FromFileTime($_."lastlogon")}}

}

if ($cc.script -eq "Account Lockout (Matt script)")
{ 

import-Module ActiveDirectory

$username = read-host -Prompt "

Enter username"

$AccountStatus = get-aduser -identity $username -Properties * | Select givenname,surname,@{ Name = "Username"; Expression={$_.samaccountname}}, Enabled,
Lockedout,
@{ Name = "Bad Password count"; Expression={$_.badpwdcount}},
@{ Name = "Account Expiry Date"; Expression={$_.AccountExpirationDate}},
@{ Name = "Password last set Date"; Expression={$_.PasswordLastSet}},
@{ Name = "Password Expired"; Expression={$_.PasswordExpired}}
#@{ Name = "Password Expiration Date"; Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}}


$GetDate = get-date 

#CHECK IF ENABLED
    if ($AccountStatus.Enabled -eq $false)
    {
        #[System.Windows.MessageBox]::Show('Account is DISABLED - Seek out Employment Status before enabling','Account Disabled','OK')

        Write-Host "
        **Account is NOT ENABLED - Seek out Employment Status before enabling
        
        **Would you like to Enable account?"   
        
        $AnsEnableAccount = read-host "
        **Enable account? [y] YES or [n] NO"

        if ($AnsEnableAccount -eq "y")
        {
            Enable-ADAccount $username
        }
        if ($AnsEnableAccount -eq "n")
        {
        Write-Host "
        **No action taken"
        }
    }


#CHECK IF LOCKED OUT

    if ($AccountStatus.Lockedout -eq $true)
    {
    Write-Host "
    Account is locked, Would you like to unlock account?"

        $AnsUnlockAccount = read-host "
        Unlock account? [y] Yes or [n] No"
        
        if ($AnsUnlockAccount -eq "y")
        {
        Unlock-ADAccount $username
        "
        **Account has been UNLOCKED"
                }
        if ($AnsUnlockAccount -eq "n")
        {
        Write-Host "
        **No action taken"
        }
    }

#CHECK IF ACCOEXPIRED
 
    if ($AccountStatus.'Account Expiry Date' -eq $null)
    {
    "
        **Account has no Expiration Date set - No action required "
    }
    
    if ($AccountStatus.'Account Expiry Date' -lt $GetDate -and $AccountStatus.'Account Expiry Date' -ne $null )
    {
     write-host "
        **Account has Expired - 

        Consider extending or clearing expiration date

        Account Expiry date is:" 
        
        $AccountStatus.'Account Expiry Date'

        write-host "
        **Enter [1] to Clear account expiration 

        OR

        **Enter [2] to Set account expiration date"

        $AnsAccountExpiration = read-host 

        if ($AnsAccountExpiration -eq "1")
        {
            #"clear account Expiration"
            Clear-ADAccountExpiration $username
            Write-Host "
            **Expiration Date has been cleared"
        }
        
        if ($AnsAccountExpiration -eq "2")
        {
        do
            {    
             $date= read-host "
**Please enter a date & time greater than current date

Format: '25/12/2012 09:00', '25 oct 2012 9:00'; 

Entering date alone will set time to 00:00"
             
             $date = $date -as [datetime]
             
             if (!$date) { "Not A valid date and time"}
             
             } 
        while ($date -isnot [datetime] -or $date -lt $getdate)

        write-host "
        "
        $date


        #"Set account exipration date"
        Set-ADAccountExpiration $username $Date
        }
        
    }
    
#CHECK PASSWORD EXPIRED
 
    if($AccountStatus.'Password Expired' -eq $true) 
    {
    write-host "
    **PASWORD HAS EXPIRED, please enter new password: "

    $GetPassword = read-host -Prompt "
    Enter new password"

    Set-ADAccountPassword -Identity $username -NewPassword (ConvertTo-SecureString -AsPlainText $GetPassword -Force)
    
    write-host "
    **Password has been set"
    }

#start-sleep -s 2

get-aduser -identity $username -Properties * | Select givenname,surname,@{ Name = "Username"; Expression={$_.samaccountname}},
Enabled,
Lockedout,
@{ Name = "Bad Password count"; Expression={$_.badpwdcount}},
@{ Name = "Account Expiry Date"; Expression={$_.AccountExpirationDate}},
@{ Name = "Password last set Date"; Expression={$_.PasswordLastSet}},
@{ Name = "Password Expired"; Expression={$_.PasswordExpired}}


#press any key to finish
 if ($Host.Name -eq "ConsoleHost")
    {
        Write-Host "
        Press any key to finish..."
        $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyUp,includekeydown")
    }

}

if ($cc.script -eq "Password Never Expires")
{ 

$user = read-host -Prompt "

Enter username"

Set-ADUser -Identity $user -PasswordNeverExpires $true

}

if ($cc.script -eq "Clear AD User expiry")
{ 

$user = read-host -Prompt "

Enter username"

Clear-ADAccountExpiration -identity $user

}

if ($cc.script -eq "List all Groups AD User is member of")
{ 

$user = read-host -Prompt "

Enter username"

get-ADPrincipalGroupMembership $user | Select Name, samaccountname

}

if ($cc.script -eq "List AD User by name")
{ 

$user = read-host -Prompt "

Enter username"

Get-ADUser -Filter * | where Name -like "*$user*" | Format-Table Name,SamAccountName -A

}

if ($cc.script -eq "List AD group by name")
{ 

$group = read-host -Prompt "

Enter group"

Get-ADGroup -Filter {name -like "*$group*"} -Properties Description | Select Name,Description,samaccountname


}

if ($cc.script -eq "Add user to distrubution group")
{ 

$group = read-host -Prompt "

Enter group"

$user = read-host -Prompt "

Enter username"

Add-DistributionGroupMember -Identity $group@hcma.com.au -Member "$user@hcma.com.au"

}

if ($cc.script -eq "perform gpupdate on remote computer")
{ 

$pc = read-host -Prompt "

Enter PC name"

Invoke-GPUpdate -Force $pc -RandomDelayInMinutes 1

}

if ($dd.script -eq "Add PC to SCCM Group")
{ 

$sccm = Import-Csv C:\Users\a-edwardsbr.old\Documents\items.csv | Out-GridView  -Title "Select a group" -OutputMode Multiple

$PC = read-host -Prompt "

Enter pc name"

Add-ADGroupMember -id $sccm.Name -Members (Get-ADComputer $pc)

}

if ($dd.script -eq "Remove from SCCM")
{

Enter-PSSession -ComputerName grs-sccm2

 Import-Module 'C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1'

 New-PSDrive -Root "grs-sccm2.hcma.com.au" -PSProvider CMSite -Name "ZZ1";

 cd zz1:\

 $pcname = read-host -Prompt "
 Enter pc name"


 Remove-CMDevice $pcname

 exit

 cd C:\Windows\system32\WindowsPowerShell\v1.0

}

if ($dd.script -eq "Remove from SCCM Vincent")
{

Enter-PSSession -ComputerName grs-sccm2

 Import-Module 'C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1'
 Import-Module 'C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1'

 cd zz1:\

 $pcname = read-host -Prompt "
 Enter pc name"


 Remove-CMDevice $pcname

 exit

 cd C:\Windows\system32\WindowsPowerShell\v1.0

}

if ($cc.script -eq "Bitlocker Code")
{
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

#cd C:\users\a-lay\Documents

import-module C:\users\a-lay\Documents\Get-BDERecoveryPassword.ps1 -force

$RecovInput = read-host -Prompt "
    Enter 8 character recovery ID eg. B16DCDD8 | OR |  Computername eg. HIT-PC02LRTC "
if ($Recovinput.Length -eq 8)
{
    Get-BDERecoveryPassword -RecoveryGUID $RecovInput |select RecoveryPassword
}

if ($Recovinput.Length -gt 8)
{
    "
    Recovery ID entered is MORE THAN 8 chars"
}

if ($Recovinput.Length -lt 8)
{
    "
    Recovery ID entered is LESS THAN 8 chars"
}

if ($Recovinput.StartsWith("hit-") -or $Recovinput.StartsWith("HIT-") )
{
    Get-BDERecoveryPassword -ComputerName $RecovInput |select RecoveryPassword
}

}

if ($cc.script -eq "Move user or computer")
{
import-Module ActiveDirectory
#$Branches = import-csv C:\users\a-edwardsbr\documents\Branches.csv


$answer = read-host -Prompt "

Do you want to move a user or computer"


if ($answer -eq "computer")
{

$pcname = read-host -Prompt "

Enter PC Name"

$x = Get-ADComputer $pcname | select distinguishedname 

if ($x -match "OU=(?<content>.*),OU=Managed Workstations,OU=HCMA,DC=hcma,DC=com,DC=au")
{
"This computers current OU is " + $matches['content']


$ou = read-host -Prompt "

Enter New OU"

#$target = Get-ADOrganizationalUnit -LDAPFilter "$ou"


Get-ADComputer $pcname | Move-ADObject -TargetPath "OU=$OU,OU=Managed Workstations,OU=HCMA,DC=hcma,DC=com,DC=au"
}
"Computer successfully moved to $ou OU"
}

else
{
$username = read-host -Prompt "

Enter Username"

$y = Get-ADUser $username | select distinguishedname 

if ($y -match "OU=(?<content>.*),OU=Managed Users,OU=HCMA,DC=hcma,DC=com,DC=au")
{
"This Users current OU is " + $matches['content']
}
$ou = read-host -Prompt "

Enter Location OU"

#$target = Get-ADOrganizationalUnit -LDAPFilter "$ou"


Get-ADuser $username | Move-ADObject -TargetPath "OU=$OU,OU=Managed Users,OU=HCMA,DC=hcma,DC=com,DC=au"

"User successfully moved to $ou OU"

}
}

if ($cc.script -eq "Terminate Account")
{

$user = read-host -Prompt "

Enter username"

$date = read-host -Prompt "

Enter day after termination date (XX/XX/XXXX)"



Disable-ADAccount $user

Set-ADAccountExpiration -Identity $user -DateTime "$date"

Get-ADUser -Identity $User -Properties MemberOf | ForEach-Object {
  $_.MemberOf | Remove-ADGroupMember -Members $_.DistinguishedName -Confirm:$false
}
$ff = Get-ADUser $user -Properties objectguid | select objectguid

 Move-ADObject $ff.objectguid -TargetPath "OU=Disabled Users,OU=Disabled Objects,OU=HCMA,DC=hcma,DC=com,DC=au"
 }

if ($licenses.license -eq "CRM URL")
{
"
         ________________________________________________
________|                                               |_______
\       |        https://crm16.hcma.com.au/crm16        |      /
 \      |                                               |     /
 /      |_______________________________________________|     \
/__________)                                        (__________\



"
}

if ($licenses.license -eq "FastStone")
{
"
 ______________________________________________________
/                                                      \
|      Software:FastStone Capture (20 licenses)        |       
|   ==========================================         |
|   User Name:HITACHI CONSTRUCTION MACHINERY           |
|   Registration Code:SOQMN-KWDBE-ZLNPL-TQVRR          |
|   ==========================================         |
|   Download link of FastStone Capture:                |
|   http://www.faststone.org/FSCapturerDownload.htm    |                            
|                                                      |
|                                                      |
\______________________________________________________/
                     !  !
                     !  !
                     L_ !
                    / _)!
                   / /__L
 _________________/ (____)
                    (____)
 _________________  (____)
                  \_(____)
                     !  !
                     !  !
                     \__/

"
}

if ($licenses.license -eq "SnagIT")
{
"
     0000             0000        7777777777777777/========___________
   00000000         00000000      7777^^^^^^^7777/ || ||   ___________ NE5HD-SFH3M-Z4QXC-MKM8Q-V4CC8
  000    000       000    000     777       7777/=========//
 000      000     000      000             7777// ((     //
0000      0000   0000      0000           7777//   \\   //
0000      0000   0000      0000          7777//========//
0000      0000   0000      0000         7777
0000      0000   0000      0000        7777
 000      000     000      000        7777
  000    000       000    000       77777
   00000000         00000000       7777777
     0000             0000        777777777

"
}

if ($cc.script -eq "Add AD user to site groups")
{
$user = read-host -Prompt "

Enter username"

$y = Get-ADUser $user | select distinguishedname 

if ($y -match "OU=(?<content>.*),OU=Managed Users,OU=HCMA,DC=hcma,DC=com,DC=au")
{
"This Users current OU is " + $matches['content']
}
if ($matches['content'] -eq "Greystanes")
{

Add-ADGroupMember -Identity GREYSTANES -members $user
Add-ADGroupMember -Identity GLS-U-SYDFPRS1-Home -Members $user
}
if ($matches['content'] -eq "Adelaide")
{

Add-ADGroupMember -Identity ADELAIDE -members $user
Add-ADGroupMember -Identity GLS-U-ADL-FSRV1-Home -Members $user
}
if ($matches['content'] -eq "Albury")
{

Add-ADGroupMember -Identity ALBURY -members $user
Add-ADGroupMember -Identity GLS-U-ALB-FSRV1-Home -Members $user
}
if ($matches['content'] -eq "Brisbane")
{

Add-ADGroupMember -Identity BRISBANE -members $user
Add-ADGroupMember -Identity GLS-U-BRI-FSRV1-Home -Members $user
}

if ($matches['content'] -eq "Bunbury")
{

Add-ADGroupMember -Identity BUNBURY -members $user
Add-ADGroupMember -Identity GLS-U-BUN-FSRV1-Home -Members $user
}

if ($matches['content'] -eq "Canberra")
{

Add-ADGroupMember -Identity CANBERRA -members $user
Add-ADGroupMember -Identity GLS-U-REV-FSRV1-Home -Members $user
}

if ($matches['content'] -eq "Darwin")
{

Add-ADGroupMember -Identity DARWIN -members $user
Add-ADGroupMember -Identity GLS-U-DAR-FSRV1-Home -Members $user
}

if ($matches['content'] -eq "Emerald")
{

Add-ADGroupMember -Identity EMERALD -members $user
Add-ADGroupMember -Identity GLS-U-EML-FSRV1-Home -Members $user
}

if ($matches['content'] -eq "Gunnedah")
{

Add-ADGroupMember -Identity Gunnedah -members $user
Add-ADGroupMember -Identity GLS-U-MUS-FSRV1-Home -Members $user
}

if ($matches['content'] -eq "Kalgoorlie")
{

Add-ADGroupMember -Identity KALGOORLIE -members $user
Add-ADGroupMember -Identity GLS-U-KAL-FSRV1-Home -Members $user
}

if ($matches['content'] -eq "Launceston")
{

Add-ADGroupMember -Identity LAUNCESTON -members $user
Add-ADGroupMember -Identity GLS-U-LAU-FSRV1-Home -Members $user
}

if ($matches['content'] -eq "Mackay")
{

Add-ADGroupMember -Identity MACKAY -members $user
Add-ADGroupMember -Identity GLS-U-MCK-FSRV1-Home -Members $user
}

if ($matches['content'] -eq "Melbourne")
{

Add-ADGroupMember -Identity MELBOURNE -members $user
Add-ADGroupMember -Identity GLS-U-MEL-FSRV1-Home -Members $user
}

if ($matches['content'] -eq "Muswellbrook")
{

Add-ADGroupMember -Identity MUSWELLBROOK -members $user
Add-ADGroupMember -Identity GLS-U-MUS-FSRV1-Home -Members $user
}

if ($matches['content'] -eq "Newcastle")
{

Add-ADGroupMember -Identity NEWCASTLE -members $user
Add-ADGroupMember -Identity GLS-U-NEW-FSRV1-Home -Members $user
}

if ($matches['content'] -eq "Perth")
{

Add-ADGroupMember -Identity PERTH -members $user
Add-ADGroupMember -Identity GLS-U-PER-FSRV1-Home -Members $user
}

if ($matches['content'] -eq "Port Hedland")
{

Add-ADGroupMember -Identity PORT HEDLAND -members $user
Add-ADGroupMember -Identity GLS-U-PER-FSRV1-Home -Members $user
}

if ($matches['content'] -eq "Somerton")
{

Add-ADGroupMember -Identity SOMERTON -members $user
Add-ADGroupMember -Identity GLS-U-SOM-FSRV1-Home -Members $user
}

if ($matches['content'] -eq "Revesby")
{

Add-ADGroupMember -Identity SYDNEY -members $user
Add-ADGroupMember -Identity GLS-U-REV-FSRV1-Home -Members $user
}

if ($matches['content'] -eq "Tom Price")
{

Add-ADGroupMember -Identity TOM PRICE -members $user
Add-ADGroupMember -Identity GLS-U-PER-FSRV1-Home -Members $user
}

if ($matches['content'] -eq "Townsville")
{

Add-ADGroupMember -Identity TOWNSVILLE -members $user
Add-ADGroupMember -Identity GLS-U-TWN-FSRV1-Home -Members $user
}


}


if ($bb)
{
Clear-Variable -Name bb
}
if ($cc)
{
Clear-Variable -Name cc
}
if ($dd)
{
Clear-Variable -Name dd
}
if ($licenses)
{
Clear-Variable -Name licenses
}
if ($y)
{
Clear-Variable -Name y
}
if ($matches)
{
Clear-Variable -Name matches
}
if ($user)
{
Clear-Variable -Name user
}
if ($usertoadd)
{
Clear-Variable -Name usertoadd
}



cd C:\Windows\system32\WindowsPowerShell\v1.0





