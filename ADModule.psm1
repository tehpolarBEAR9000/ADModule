class WINEventLogger
{
    [string]hidden $source; #ProviderName
    [string]hidden $logLevel;

    WINEventLogger($source,$logLevel){
        $this.source = $source;
        $this.logLevel = $logLevel;
        $this.notifyBadSecurityContext($this.describeRunningSecurityContext());
    }
    [bool] describeRunningSecurityContext(){
        $context = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        return $context.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    [string] notifyBadSecurityContext([bool]$securityContext){
        return "1. Running as Admin: $securityContext `n2. Elevated Permissions Required!"
    }
    [bool] eventSourceExists(){
        return [System.Diagnostics.EventLog]::SourceExists($this.source);
    }
    registerEventSource(){
        [System.Diagnostics.EventLog]::CreateEventSource($this.source,"ADModule");
    }
    [string] WriteEventLogger($msg){
        if( -not ($this.describeRunningSecurityContext() ) ){
            return $this.notifyBadSecurityContext($FALSE)
        }
        if(-not ($this.eventSourceExists())){
            $this.registerEventSource();
            $eventLog = [System.Diagnostics.EventLog]
            $eventLog::WriteEntry($this.source, $msg, $this.logLevel);
            return "Log Succesfully Written"
        }else{
            $eventLog = [System.Diagnostics.EventLog];
            $eventLog::WriteEntry($this.source, $msg, $this.logLevel);
            return "Log Succesfully Written"
        }
    }
    [System.Diagnostics.Eventing.Reader.EventLogRecord]ReadEventLogs(){
        return Get-WinEvent -ProviderName $this.source
    }
}
class LDAPConnector
{
    [string] $searchBase = "OU=domain,DC=example,DC=local"
    [string] $ldapPATH
    $ldapSetParameters = [System.DirectoryServices.DirectoryEntry]::new();
    [string[]] $userList
    
    LDAPConnector($OUSuffix){    
        $this.ldapPATH = "LDAP://$OUSuffix,$($this.searchBase)";
        $this.ldapSetParameters.Path = $this.ldapPATH;
    }
    [string[]] getADUser($nameIsLike){ 
        $logger = [WinEventLogger]::New("ADQueryRequest","Information")
        $logger.WriteEventLogger("A get-ADUser request has been made for $($nameIsLike)")
        return ((($this.ldapSetParameters.Children).distinguishedName).split(',') | ?{$_ -Like "CN=$nameIsLike*"}).Replace('CN=','');
    }
    [string[]] getADUserGroups(){
        $logger = [WinEventLogger]::New("ADQueryRequest","Information")
        $logger.WriteEventLogger("A get-ADUserGroups request has been made.")
        return ($this.ldapSetParameters.Properties['memberOf'].split(',') | ?{$_ -Like "CN=*"}).Replace('CN=','');
    }
    [string[]] getADGroup($groupIsLike){
        $logger = [WinEventLogger]::New("ADQueryRequest","Information")
        $logger.WriteEventLogger("A get-ADGroup request has been made for $($groupIsLike)")
        return ((($this.ldapSetParameters.Children).distinguishedName).split(',') | ?{$_ -Like "CN=$groupIsLike*"}).Replace('CN=','');
    }
    [string[]] getADGroupMembers(){
        $logger = [WinEventLogger]::New("ADQueryRequest","Information")
        $logger.WriteEventLogger("A get-ADGroupMembers request has been made.")
        return ($this.ldapSetParameters.Properties['member']).Replace('CN=','');
    }
    addADGroupMembers($userName){
        $this.userList += "CN=$userName,OU=Users,$($this.searchBase)"
        $this.ldapSetParameters.Properties['member'] | % {$this.userList += $_}
        $this.ldapSetParameters.Properties['member'].Clear()
        
        $this.userList | % {
            $this.ldapSetParameters.Properties['member'].Add($_)
        }
        
        $this.ldapSetParameters.CommitChanges();

        $logger = [WinEventLogger]::New("ADChangeRequest","Warning")
        $logger.WriteEventLogger("An add-ADGroupMembers request has been made for: $($username)")
    } 
}
Class LdapConnectionBUILDER
{
    [string[]] getADUser($nameIsLike){
        If(-not $Args[0]){$OUSuffix = "OU=Users";}else{$OUSuffix = $Args[0];}
    
        $LDAPConnector = [LDAPConnector]::new($OUSuffix);
    
        return $LDAPConnector.getADUser($nameIsLike);
    }
    [string[]] getADUserGroups($userName){
        If(-not $Args[0]){$OUSuffix = "CN=$userName,OU=Users"}else{$OUSuffix = "CN=$userName,$($Args[0])"}
        
        $LDAPConnector = [LDAPConnector]::new($OUSuffix);
        
        return $LDAPConnector.getADUserGroups();
    }
    [string[]] getADGroup($groupIsLike){
        If(-not $Args[0]){$OUSuffix = "OU=Security Groups"}else{$OUSuffix = $Args[0]}
        
        $LDAPConnector = [LDAPConnector]::new($OUSuffix);
        
        return $LDAPConnector.getADGroup($groupIsLike);
    }
    [string[]] getADGroupMembers($groupName){
        If(-not $Args[0]){$OUSuffix = "CN=$groupName,OU=Security Groups"}else{$OUSuffix = "CN=$groupName,$($Args[0])"}
        
        $LDAPConnector = [LDAPConnector]::new($OUSuffix);

        return $LDAPConnector.getADGroupMembers();
    }
    [string[]] addADGroupMembers($groupName, $userName){
        If(-not $Args[0]){$OUSuffix = "CN=$groupName,OU=Security Groups"}else{$OUSuffix = "CN=$groupName,$($Args[0])"}
        
        $LDAPConnector = [LDAPConnector]::new($OUSuffix);
        $LDAPConnector.addADGroupMembers($userName);
        
        return $LDAPConnector.getADGroupMembers();
    }
}
Function getADUser($nameIsLike){
<#
.Synopsis
Queries ADUC (Active Directory Users and Computers)
Uses currently signed-on session for authentication 
.Description
Queries AD User using partial name matches
Uses the internal domain on Aws - there is no option for custom domains / IdP
Tailing '*' is implied for all searches. 'Kevin*' and 'Kevin' produce the same results, while '*Kevin' and 'Kevin' produce different results
Not case sensitive
.Example   
getADUser -nameIsLike "Kevin"
# Returns
    "Kevin James"
    "Kevin Frank"
.Example
getADUser -nameIsLike "*Kell"
# Returns
    "Brenda Askellerin"
    "Branden Kellerhop"
    "Ava Kelleer"
#>
    $getADUSer = New-Object LdapConnectionBUILDER
    $getADUSer.getADUser($nameIsLike);
}
Function getADUserGroups($userName){
<#
.External 
 
.Synopsis
Queries ADUC (Active Directory Users and Computers)
Uses currently signed-on session for authentication 
.Description
Queries AD Group Membership for user.
Uses the internal domain on Aws - there is no option for custom domains / IdP
Cmdlet only accepts Canonical Name - i.e., 'kevin james' and not 'kjames', 'kevin j', '*kevin', etc. Use GetADUser to find Canonical Name 
Not case sensitive
.Example
getADUserGroups -username "Kevin James"
# Returns 	
    "CN=Employees,OU=Security Groups,OU=domain,DC=example,DC=local"
    "CN=Dev Staff,OU=Security Groups,OU=domain,DC=example,DC=local" 
.Example
getADUserGroups -username $(getADUser -nameIsLike 'kevin b')
# Returns
    "CN=Employees,OU=Security Groups,OU=domain,DC=example,DC=local"
    "CN=Dev Staff,OU=Security Groups,OU=domain,DC=example,DC=local" 
#>
    $getADUserGroups = New-Object LdapConnectionBUILDER
    $getADUserGroups.getADUserGroups($userName);
}
Function getADGroup($groupIsLike){
<#
.Synopsis
Queries ADUC (Active Directory Users and Computers)
Uses currently signed-on session for authentication
.Description
Queries AD Groups using partial name matches 
Uses the internal domain on Aws - there is no option for custom domains / IdP
Tailing '*' is implied for all searches. 'Asset*' and 'Asset' produce the same results, while '*Staff' and 'Staff' produce different results
Not case sensitive
.Example
getADGroup -groupIsLike 'it'
#Results
    IT-Share-Group
    IT Manager
    IT Staff
.Example
getADGroup -groupIsLike '*Staff'
#Results
    Employee Staff
    Finance Staff
    ...
#>
    $getADGroup = New-Object LdapConnectionBUILDER
    $getADGroup.getADGroup($groupIsLike);
}
Function getADGroupMembers($groupName){
<#
.Synopsis
Queries ADUC (Active Directory Users and Computers)
Uses currently signed-on session for authentication
.Description
Queries AD Group Membership
Uses the internal domain on Aws - there is no option for custom domains / IdP
Cmdlet only accepts Canonical Name - i.e., 'it staff' and not 'it', '*staff', 'it s*', etc. Use GetADGroup to find Canonical Name 
Not case sensitive
.Example
getADGroupMembers -groupName 'it staff'
#Results
    Tyler Terrance,OU=Users,OU=domain,DC=example,DC=local
    Kevin Brimmington,OU=Users,OU=domain,DC=example,DC=local
.Example
getADGroupMembers -groupName $(getADGroup -groupIsLike 'it s')
#Results
    Tyler Terrance,OU=Users,OU=domain,DC=example,DC=local
    Kevin James,OU=Users,OU=domain,DC=example,DC=local
#>
    $getADGroupMembers = New-Object LdapConnectionBUILDER
    $getADGroupMembers.getADGroupMembers($groupName);
}
Function addADGroupMembers($groupName, $userName){
<#
.Synopsis
Queries ADUC (Active Directory Users and Computers)
Uses currently signed-on session for authentication
.Description
Sets AD Group Membership for AD User
Uses the internal domain on Aws - there is no option for custom domains / IdP
Cmdlet requires Canonical Name for both Group and User; default option is VerbNoun -groupName '' -userName ''
.Example
addADGroupMembers 'it staff' 'kevin franklin'
#Returns
    Kevin franklin,OU=Users,OU=domain,DC=example,DC=local
    ...
#>
    $addADGroupMembers = New-Object LdapConnectionBUILDER;
    $addADGroupMembers.addADGroupMembers($groupName, $userName);
}