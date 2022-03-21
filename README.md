# About

Makes availalbe the following queries into Microsoft Active Directory
 -- Get-ADUser
 -- Get-ADPrincipalGroupMembership
 -- Get-ADGroupMember
 -- Add-ADGroupMember

# Why
Active Directory PowerShell modules and tools sometimes cannot / should not be installed. Using ADModule allows the user to bypass this restriction.

# How

ADModule uses ADSI (Active Directory Services Interfaces) to interact with Microsoft Active Directory. Credentials are handled by the OS.
This means if the user DOMAIN\kevin is signed into the computer, then those credentials will authenticate during the connection.
