Overview
- Queries Active Directory without PowerShell AD Modules      
- Active Directory PowerShell Modules cannot always be installed; using this module addresses that situation  

Components
- ADSI  
- PowerShell manifest file  
- PowerShell module file  
- Functions/methods  
  : Get-ADUser    
  : Get-ADPrincipalGroupMembership  
  : Get-ADGroupMember  
  : Add-ADGroupMember  
- Error Handling  

Output
- Errors and Methods are logged to stderr/stdout streams    
- Error message prints when script is not ran with elevated privileges  
- Method results return  
  : A particular user  
  : One or more groups per user  
  : One or more users per group  
  : All group membership per user, including the newly added group  
