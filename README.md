FreeRADIUS
==========

The only problem I have ran into is when you intially run radiusd -X after running this script, sometimes winbind chokes
and causes radiusd -X to throw errors.

* if you run this command: `wbinfo -u`
* and you receive this error message: `Error looking up domain users`
* restart winbind: `service winbind restart`

Once you do that, wbinfo -u should populate a list of users and radiud -X should run properly.
