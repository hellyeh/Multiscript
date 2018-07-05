Function Unlock-HCAAccount ($username)
{

import-Module ActiveDirectory

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

function Set-HCAPasswordNeverExpire ($user)
{
Set-ADUser -Identity $user -PasswordNeverExpires $true 

}

function Get-HCALastLogon ($user)
{
    Get-ADUser $user -Properties * | select samaccountname,@{ Name = "Last logon date"; Expression={[datetime]::FromFileTime($_."lastlogon")}}

}

function Set-HCAPassword ($user, $pass)
{
    Set-ADAccountPassword -Identity $user -NewPassword (ConvertTo-SecureString -AsPlainText "$pass" -Force)
}

function Get-HCAPasswordExpiry ($user)
{
    Get-ADUser -identity $user -Properties msDS-UserPasswordExpiryTimeComputed | select samaccountname,@{ Name = "Expiration Date"; Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}}
}

function Clear-HCAAccountExpiry ($user)
{
    Clear-ADAccountExpiration -identity $user
}

function Get-HCAUsersGroups ($user)
{
    get-ADPrincipalGroupMembership $user | Select Name, samaccountname
}

function Get-HCAUserLike ($user)
{ 
Get-ADUser -Filter * | where Name -like "*$user*" | Format-Table Name,SamAccountName -A 
}

function Get-HCAGroupLike ($group)
{
    Get-ADGroup -Filter {name -like "*$group*"} -Properties Description | Select Name,Description,samaccountname
}

function Add-HCAUserToDitributionGroup ($user, $group)
{
    Add-DistributionGroupMember -Identity $group@hcma.com.au -Member "$user@hcma.com.au"
}

function PerformGPUPdate-HCA ($pc)
{
  Invoke-GPUpdate -Force $pc -RandomDelayInMinutes 1  
}

function Add-HCAUsertoSCCMGroup ($user)
{
$sccm = Import-Csv C:\Users\a-edwardsbr.old\Documents\items.csv | Out-GridView  -Title "Select a group" -OutputMode Multiple

Add-ADGroupMember -id $sccm.Name -Members (Get-ADComputer $pc)
}

function Remove-HCAPCFromSCCMBrendan ($pc)
{
    Enter-PSSession -ComputerName grs-sccm2

 Import-Module 'C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1'

 New-PSDrive -Root "grs-sccm2.hcma.com.au" -PSProvider CMSite -Name "ZZ1";

 cd zz1:\

 $pc = read-host -Prompt "
 Enter pc name"


 Remove-CMDevice $pc

 exit

 cd C:\Windows\system32\WindowsPowerShell\v1.0
}

function Remove-HCAPCFromSCCM ($pc)
{
  Enter-PSSession -ComputerName grs-sccm2

 Import-Module 'C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1'
 Import-Module 'C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1'

 cd zz1:\

 $pc = read-host -Prompt "
 Enter pc name"


 Remove-CMDevice $pc

 exit

 cd C:\Windows\system32\WindowsPowerShell\v1.0
}

function Get-HCABitlocker ($RecovInput)
{
    
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

#cd C:\users\a-lay\Documents

import-module C:\users\a-lay\Documents\Get-BDERecoveryPassword.ps1 -force

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

function Move-HCAUser ($user, $ou)
{
  import-Module ActiveDirectory

Get-ADuser $user | Move-ADObject -TargetPath "OU=$ou,OU=Managed Users,OU=HCMA,DC=hcma,DC=com,DC=au"

}

function Move-HCAPC ($pc, $ou)
{
import-Module ActiveDirectory
Get-ADComputer $pc | Move-ADObject -TargetPath "OU=$ou,OU=Managed Workstations,OU=HCMA,DC=hcma,DC=com,DC=au"
}

function Terminate-HCAUser ($user, $date)
{

Disable-ADAccount $user

Set-ADAccountExpiration -Identity $user -DateTime "$date"

Get-ADUser -Identity $User -Properties MemberOf | ForEach-Object {
  $_.MemberOf | Remove-ADGroupMember -Members $_.DistinguishedName -Confirm:$false
}
$guid = Get-ADUser $user -Properties objectguid | select objectguid

 Move-ADObject $guid.objectguid -TargetPath "OU=Disabled Users,OU=Disabled Objects,OU=HCMA,DC=hcma,DC=com,DC=au"
 
}








cls