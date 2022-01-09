## Weekly IP Assignment Audit

This is primarily used to find products that are not being charged correctly for the amount of IP addresses assigned to them.  This script will search through all the assignments performed in the last week and then compare how many IP addresses are assigned versus quantity billed for.


This script was designed for Python 3.x.  I recommend running it from a Python Environment.  With below example commands on your workstation.


```
cd ~/location of audit script/
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```


### Example of running the script and output:

```
cd ~/location of audit script/
source venv/bin/activate
python netAudit.py

Username: (Your Username)
Password: (Your Password)


One moment while I gather data...

Step 1 Complete
- 1565 initial assignments found.
- 1128 provisioned assignments removed.
- 83 internal account assignments removed.
- 354 assignments remain.

Step 2 Complete 
- Gathered select information 
 - Hostnames
 - Product Types
 - Unique IDs
- Removed selected Assignments.
 - 263 duplicate Unique IDs.
 - 13 incompatible product types.
 - 3 host(s) pending termination.
- 75 assignments remain.
 
Step 3 Complete 
- IP billing info gathered.
- IP billing cleanup:
 - 74 hosts removed w/ no adjustments needed.
 - 1 hosts to manually check.
 - 0 hosts needs billing adjustments.

Output to: netaudit.txt
Finished in 104.56 second(s)
```


The file netaudit.txt will contain near copy pasta email to be sent to the billing team.  It also contains a copy of the dictionary for troubleshooting should there be any issues with the email output.


#### MANUALLY_CHECK

Some hosts will have "MANUALLY_CHECK" due to the script unable to determine what the IP billing is.  Therefore requires human intervention to load the link and determine what if any adjustments need to be made.
