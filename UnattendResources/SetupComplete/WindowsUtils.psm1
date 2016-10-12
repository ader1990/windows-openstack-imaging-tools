# Copyright 2014-2015 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

$moduleHome = Split-Path -Parent $MyInvocation.MyCommand.Path
$administratorsGroupSID = "S-1-5-32-544"
$computername = [System.Net.Dns]::GetHostName()

New-Alias -Name Get-ManagementObject -Value Get-WmiObject

function Grant-Privilege {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$User,
        [Parameter(Mandatory=$true)]
        [string]$Grant
    )
    BEGIN {
        $privBin = Join-Path $env:windir "\Setup\Scripts\SetUserAccountRights.exe"
        if (!(Test-Path $privBin)) {
            Throw "Cound not find SetUserAccountRights.exe on the system."
        }
    }
    PROCESS {
        $cmd = @($privBin, "-g", "$User", "-v", $Grant)
        Invoke-JujuCommand -Command $cmd | Out-Null
    }
}

function Invoke-JujuCommand {
    <#
    .SYNOPSIS
     Invoke-JujuCommand is a helper function that accepts a command as an array and returns the output of
     that command as a string. Any error returned by the command will make it throw an exception. This function
     should be used for launching native commands, not powershell commandlets (although that too is possible).
    .PARAMETER Command
     Array containing the command and its arguments
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias("Cmd")]
        [array]$Command
    )
    PROCESS {
        $cmdType = (Get-Command $Command[0]).CommandType
        if($cmdType -eq "Application") {
            # Some native applications write to stderr instead of stdout. If we redirect stderr
            # to stdout and have $ErrorActionPreference set to "stop", powershell will stop execution
            # even though no actual error has happened. Set ErrorActionPreference to SilentlyContinue
            # until after the native application finishes running. The $LASTEXITCODE variable will still
            # be set, and that is what we really care about here.
            $ErrorActionPreference = "SilentlyContinue"
            $ret = & $Command[0] $Command[1..$Command.Length] 2>&1
            $ErrorActionPreference = "Stop"
        } else {
            $ret = & $Command[0] $Command[1..$Command.Length]
        }

        if($cmdType -eq "Application" -and $LASTEXITCODE){
            Throw ("Failed to run: " + ($Command -Join " "))
        }
        if($ret -and $ret.Length -gt 0){
            return $ret
        }
        return $false
    }
}

function Set-ServiceLogon {
    <#
    .SYNOPSIS
    This function accepts a service or an array of services and sets the user under which the service should run.
    .PARAMETER Services
    An array of services to change startup user on. The values of the array can be a String, ManagementObject (returned by Get-WmiObject) or CimInstance (Returned by Get-CimInstance)
    .PARAMETER UserName
    The local or domain user to set as. Defaults to LocalSystem.
    .PARAMETER Password
    The password for the account.

    .NOTES
    The selected user account must have SeServiceLogonRight privilege.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]
        [array]$Services,
        [Parameter(Mandatory=$true)]
        [string]$UserName="LocalSystem",
        [Parameter(Mandatory=$false)]
        [string]$Password=""
    )
    PROCESS {
        foreach ($i in $Services){
            switch($i.GetType().FullName){
                "System.String" {
                    $svc = Get-ManagementObject -Class Win32_Service -Filter ("Name='{0}'" -f $i)
                    if(!$svc){
                        Throw ("Service named {0} could not be found" -f @($i))
                    }
                    Set-ServiceLogon -Services $svc -UserName $UserName -Password $Password
                }
                "System.Management.ManagementObject" {
                    if ($i.CreationClassName -ne "Win32_Service"){
                        Throw ("Invalid management object {0}. Expected: {1}" -f @($i.CreationClassName, "Win32_Service"))
                    }
                    $i.Change($null,$null,$null,$null,$null,$null,$UserName,$Password)
                }
                "Microsoft.Management.Infrastructure.CimInstance" {
                    if ($i.CreationClassName -ne "Win32_Service"){
                        Throw ("Invalid management object {0}. Expected: {1}" -f @($i.CreationClassName, "Win32_Service"))
                    }
                    $ret = Invoke-CimMethod -CimInstance $i `
                                            -MethodName "Change" `
                                            -Arguments @{"StartName"=$UserName;"StartPassword"=$Password;}
                                            echo $UserName
                                            echo $Password
                    if ($ret.ReturnValue){
                        Throw "Failed to set service credentials: $ret"
                    }
                }
                default {
                    Throw ("Invalid service type {0}" -f $i.GetType().Name)
                }
            }
        }
    }
}

function Get-AccountObjectByName {
    <#
    .SYNOPSIS
    Returns a CimInstance or a ManagementObject containing the Win32_Account representation of the requested username.
    .PARAMETER Username
    User name to lookup.
    #>
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)]
        [string]$Username
    )
    PROCESS {
        $u = Get-ManagementObject -Class "Win32_Account" `
                                  -Filter ("Name='{0}'" -f $Username)
        if (!$u) {
            Throw [System.Management.Automation.ItemNotFoundException] "User not found: $Username"
        }
        return $u
    }
}

function Get-GroupObjectByName {
    <#
    .SYNOPSIS
    Returns a CimInstance or a ManagementObject containing the Win32_Group representation of the requested group name.
    .PARAMETER GroupName
    Group name to lookup.
    #>
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)]
        [string]$GroupName
    )
    PROCESS {
        $g = Get-ManagementObject -Class "Win32_Group" `
                                  -Filter ("Name='{0}'" -f $GroupName)
        if (!$g) {
            Throw "Group not found: $GroupName"
        }
        return $g
    }
}

function Get-AccountObjectBySID {
    <#
    .SYNOPSIS
    This will return a Win32_UserAccount object. If running on a system with powershell >= 4, this will be a CimInstance.
    Systems running powershell <= 3 will return a ManagementObject.
    .PARAMETER SID
    The SID of the user we want to find
    .PARAMETER Exact
    This is $true by default. If set to $false, the query will use the 'LIKE' operator instead of '=' when filtering for users.
    .NOTES
    If $Exact is $false, multiple account objects may be returned.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$SID,
        [Parameter(Mandatory=$false)]
        [switch]$Exact=$true
    )
    PROCESS {
        $modifier = " LIKE "
        if ($Exact){
            $modifier = "="
        }
        $query = ("SID{0}'{1}'" -f @($modifier, $SID))
        $s = Get-ManagementObject -Class Win32_UserAccount -Filter $query
        if(!$s){
            Throw "SID not found: $SID"
        }
        return $s
    }
}

function Get-GroupObjectBySID {
    <#
    .SYNOPSIS
    This will return a win32_group object. If running on a system with powershell >= 4, this will be a CimInstance.
    Systems running powershell <= 3 will return a ManagementObject.
    .PARAMETER SID
    The SID of the user we want to find
    .PARAMETER Exact
    This is $true by default. If set to $false, the query will use the 'LIKE' operator instead of '='.
    .NOTES
    If $Exact is $false, multiple win32_account objects may be returned.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$SID,
        [Parameter(Mandatory=$false)]
        [switch]$Exact=$true
    )
    PROCESS {
        $modifier = " LIKE "
        if ($Exact){
            $modifier = "="
        }
        $query = ("SID{0}'{1}'" -f @($modifier, $SID))
        $s = Get-ManagementObject -Class Win32_Group -Filter $query
        if(!$s){
            Throw "SID not found: $SID"
        }
        return $s
    }
}

function Get-AccountNameFromSID {
    <#
    .SYNOPSIS
    This function exists for compatibility. Please use Get-AccountObjectBySID.
    .PARAMETER SID
    The SID of the user we want to find
    .PARAMETER Exact
    This is $true by default. If set to $false, the query will use the 'LIKE' operator instead of '='.
    .NOTES
    If $Exact is $false, multiple account objects may be returned.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$SID,
        [Parameter(Mandatory=$false)]
        [switch]$Exact=$true
    )
    PROCESS {
        # Get-AccountObjectBySID will throw an exception if an account is not found
        return (Get-AccountObjectBySID -SID $SID -Exact:$Exact).Name
    }
}

function Get-GroupNameFromSID {
    <#
    .SYNOPSIS
    This function exists for compatibility. Please use Get-GroupObjectBySID.
    .PARAMETER SID
    The SID of the group we want to find
    .PARAMETER Exact
    This is $true by default. If set to $false, the query will use the 'LIKE' operator instead of '='.
    .NOTES
    If $Exact is $false, multiple win32_group objects may be returned.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$SID,
        [Parameter(Mandatory=$false)]
        [switch]$Exact=$true
    )
    PROCESS {
        return (Get-GroupObjectBySID -SID $SID -Exact:$Exact).Name
    }
}

function Get-AdministratorAccount {
    <#
    .SYNOPSIS
    Helper function to return the local Administrator account name. This works with internationalized versions of Windows.
    #>
    PROCESS {
        $SID = "S-1-5-21-%-500"
        return Get-AccountNameFromSID -SID $SID -Exact:$false
    }
}

function Get-AdministratorsGroup {
    <#
    .SYNOPSIS
    Helper function to get the local Administrators group. This works with internationalized versions of Windows.
    #>
    PROCESS {
        return Get-GroupNameFromSID -SID $administratorsGroupSID
    }
}

function Confirm-IsMemberOfGroup {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$GroupSID,
        [Parameter(Mandatory=$true)]
        [string]$Username
    )
    PROCESS {
        $inDomain = (Get-ManagementObject -Class Win32_ComputerSystem).PartOfDomain
        if($inDomain){
            $domainName = (Get-ManagementObject -Class Win32_ComputerSystem).Domain
            $myDomain = [Environment]::UserDomainName
            if($domainName -eq $myDomain) {
                return (Get-UserGroupMembership -Username $Username -GroupSID $GroupSID)
            }
        }
        $name = Get-GroupNameFromSID -SID $GroupSID
        return Get-LocalUserGroupMembership -Group $name -Username $Username
    }
}

function Get-LocalUserGroupMembership {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Group,
        [Parameter(Mandatory=$true)]
        [string]$Username
    )
    PROCESS {
        $cmd = @("net.exe", "localgroup", $Group)
        $ret = Invoke-JujuCommand -Command $cmd
        $members =  $ret | where {$_ -AND $_ -notmatch "command completed successfully"} | select -skip 4
        foreach ($i in $members){
            if ($Username -eq $i){
                return $true
            }
        }
        return $false
    }
}

function Get-UserGroupMembership {
    <#
    .SYNOPSIS
    Checks whether or not a user is part of a particular group. If running under a local user, domain users will not be visible.
    .PARAMETER Username
    The username to verify
    .PARAMETER GroupSID
    The SID of the group we want to check if the user is part of.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [Alias("User")]
        [string]$Username,
        [Parameter(Mandatory=$true)]
        [string]$GroupSID
    )
    PROCESS {
        $group = Get-GroupObjectBySID -SID $GroupSID
        if($Username.Contains('@')) {
            $data = $Username.Split('@')
            $Username = $data[0]
            $Domain = $data[1]
        } elseif ($Username.Contains('\')) {
            $data = $Username.Split('\')
            $Username = $data[1]
            $Domain = $data[0]
        }
        $scriptBlock =  { $_.Name -eq $Username }
        if($Domain) {
            $scriptBlock = { $_.Name -eq $Username -and $_.Domain -eq $Domain}
        }
        switch($group.GetType().FullName){
            "Microsoft.Management.Infrastructure.CimInstance" {
                $ret = Get-CimAssociatedInstance -InputObject $group `
                                                 -ResultClassName Win32_UserAccount | Where-Object $scriptBlock
            }
            "System.Management.ManagementObject" {
                $ret = $group.GetRelated("Win32_UserAccount") | Where-Object $scriptBlock
            }
            default {
                Throw ("Invalid group object type {0}" -f $group.GetType().FullName)
            }
        }   
        return ($ret -ne $null)
    }
}

function New-LocalAdmin {
    <#
    .SYNOPSIS
    Create a local user account and add it to the local Administrators group. This works with internationalized versions of Windows as well.
    .PARAMETER Username
    The user name of the new user
    .PARAMETER Password
    The password the user will authenticate with
    .NOTES
    This commandlet creates an administrator user that never expires, and which is not required to reset the password on first logon.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [Alias("LocalAdminUsername")]
        [string]$Username,
        [Parameter(Mandatory=$true)]
        [Alias("LocalAdminPassword")]
        [string]$Password
    )
    PROCESS {
        Add-WindowsUser $Username $Password | Out-Null
        Add-UserToLocalGroup -Username $Username -GroupSID $administratorsGroupSID
    }
}

function Add-UserToLocalGroup {
    <#
    .SYNOPSIS
    Add a user to a localgroup
    .PARAMETER Username
    The username to add
    .PARAMETER GroupSID
    The SID of the group to add the user to
    .PARAMETER GroupName
    The name of the group to add the user to
    .NOTES
    GroupSID and GroupName are mutually exclusive
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Username,
        [Parameter(Mandatory=$false)]
        [string]$GroupSID,
        [Parameter(Mandatory=$false)]
        [string]$GroupName
    )
    PROCESS {
        if(!$GroupSID) {
            if(!$GroupName) {
                Throw "Neither GroupSID, nor GroupName have been specified"
            }
        }
        if($GroupName -and $GroupSID){
            Throw "The -GroupName and -GroupSID options are mutually exclusive"
        }
        if($GroupSID){
            $GroupName = Get-GroupNameFromSID $GroupSID
        }
        if($GroupName) {
            $GroupSID = (Get-GroupObjectByName $GroupName).SID
        }
        $isInGroup = Confirm-IsMemberOfGroup -User $Username -Group $GroupSID
        if($isInGroup){
            return
        }
        $cmd = @("net.exe", "localgroup", $GroupName, $Username, "/add")
        Invoke-JujuCommand -Command $cmd | Out-Null
    }
}

function Add-WindowsUser {
    <#
    .SYNOPSIS
    Creates a new local Windows account.
    .PARAMETER Username
    The user name of the new user
    .PARAMETER Password
    The password the user will authenticate with
    .NOTES
    This commandlet creates a local user that never expires, and which is not required to reset the password on first logon.
    #>
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true)]
        [string]$Username,
        [parameter(Mandatory=$true)]
        [string]$Password
    )
    PROCESS {
        try {
            $exists = Get-AccountObjectByName $Username
        } catch [System.Management.Automation.ItemNotFoundException] {
            $exists = $false
        }
        $cmd = @("net.exe", "user", $Username)
        if (!$exists) {
            $cmd += @($Password, "/add", "/expires:never", "/active:yes")
        } else {
            $cmd += $Password
        }
        Invoke-JujuCommand -Command $cmd | Out-Null
    }
}

function Get-RandomString {
    <#
    .SYNOPSIS
    Returns a random string of characters, with a minimum length of 6, suitable for passwords
    .PARAMETER Length
    length of the random string.
    .PARAMETER Weak
    Use a smaller set of characters
    #>
    [CmdletBinding()]
    Param(
        [int]$Length=16,
        [switch]$Weak=$false
    )
    PROCESS {
        if($Length -lt 6) {
            $Length = 6
        }
        if(!$Weak) {
            $characters = 33..122
        }else {
            $characters = (48..57) + (65..90) + (97..122)
        }

        $special = @(33, 35, 37, 38, 43, 45, 46)
        $numeric = 48..57
        $upper = 65..90
        $lower = 97..122

        $passwd = [System.Collections.Generic.List[object]](New-object "System.Collections.Generic.List[object]")
        for($i=0; $i -lt $Length; $i++){
            $c = get-random -input $characters
            $passwd.Add([char]$c)
        }

        $passwd.Add([char](get-random -input $numeric))
        $passwd.Add([char](get-random -input $special))
        $passwd.Add([char](get-random -input $upper))
        $passwd.Add([char](get-random -input $lower))

        $Random = New-Object Random
        return [string]::join("",($passwd|sort {$Random.Next()}))
    }
}

function Start-ExecuteWithRetry {
    <#
    .SYNOPSIS
    In some cases a command may fail several times before it succeeds, be it because of network outage, or a service
    not being ready yet, etc. This is a helper function to allow you to execute a function or binary a number of times
    before actually failing.
    Its important to note, that any powershell commandlet or native command can be executed using this function. The result
    of that command or powershell commandlet will be returned by this function.
    Only the last exception will be thrown, and will be logged with a log level of ERROR.
    .PARAMETER ScriptBlock
    The script block to run.
    .PARAMETER MaxRetryCount
    The number of retries before we throw an exception.
    .PARAMETER RetryInterval
    Number of seconds to sleep between retries.
    .PARAMETER ArgumentList
    Arguments to pass to your wrapped commandlet/command.
    .EXAMPLE
    # If the computer just booted after the machine just joined the domain, and your charm starts running,
    # it may error out until the security policy has been fully applied. In the bellow example we retry 10
    # times and wait 10 seconds between retries before we give up. If successful, $ret will contain the result
    # of Get-ADUser. If it does not, an exception is thrown. 
    $ret = Start-ExecuteWithRetry -ScriptBlock {
        Get-ADUser testuser
    } -MaxRetryCount 10 -RetryInterval 10
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [Alias("Command")]
        [ScriptBlock]$ScriptBlock,
        [int]$MaxRetryCount=10,
        [int]$RetryInterval=3,
        [array]$ArgumentList=@()
    )
    PROCESS {
        $currentErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"

        $retryCount = 0
        while ($true) {
            try {
                $res = Invoke-Command -ScriptBlock $ScriptBlock `
                         -ArgumentList $ArgumentList
                $ErrorActionPreference = $currentErrorActionPreference
                return $res
            } catch [System.Exception] {
                $retryCount++
                if ($retryCount -gt $MaxRetryCount) {
                    $ErrorActionPreference = $currentErrorActionPreference
                    throw
                } else {
                    if($_) {
                        Write-Debug $_
                    }
                    Start-Sleep $RetryInterval
                }
            }
        }
    }
}

function Hide-User {
    param($Username)
    $keyName = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    reg.exe ADD $keyName /f /t "REG_DWORD" /d 0 /v $userName
}

function Set-CloudbaseInitService {
    $username = "cloudbase-init"
    $serviceName = "cloudbase-init"
    $password = Get-RandomString -Length 10
    New-LocalAdmin -Username $username -Password $password
    Hide-User -Username $username
    Grant-Privilege -User $username -Grant "SeServiceLogonRight"
    Grant-Privilege -User $username -Grant "SeAssignPrimaryTokenPrivilege"
    Set-ServiceLogon -Username ".\$username" -Password $password -Services @($serviceName)
}

Export-ModuleMember -Function * -Alias *
