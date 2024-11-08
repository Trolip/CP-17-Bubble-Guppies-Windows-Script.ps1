#rename local user 
if(get-localuser -name Administator)
  (rename-localuser Administator ExAdmin)
if(get-localuser -name Guest)
  (rename-localuser Administator ExGuest)

#audit policy
auditpol /restore \file/audit.csv

#secedit policy
secedit /import /cfg\Password Policies.inf

#windows defender firewall
Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultInboundAction Block -DefaultOutboundAction Allow
Get-NetFirewallProfile
#todo
