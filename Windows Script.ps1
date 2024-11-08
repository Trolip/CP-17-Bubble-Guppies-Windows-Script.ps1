#rename local user 
if(get-localuser -name Administator)
  (rename-localuser Administator ExAdmin)
if(get-localuser -name Guest)
  (rename-localuser Administator ExGuest)

!audit policy
