# OSSEC-MISC
OSSEC-MISC

For the local_decoder.xml to function properly in OSSEC you must make the below change in your ossec.conf file:
```
  <rules>
    <decoder>etc/local_decoder.xml</decoder>
    <decoder>etc/decoder.xml</decoder>
```

update_OSSEC_CDBs-groups.py - pull group membership from AD and update the specified CDB with the group members

update_OSSEC_CDBs-OUs.py - pull all members of an OU out of AD and update the specified CDB with that OUs members
