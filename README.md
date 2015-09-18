# OSSEC-MISC
OSSEC-MISC

For the local_decoder.xml to function properly in OSSEC you must make the below change in your ossec.conf file:
```
  <rules>
    <decoder>etc/local_decoder.xml</decoder>
    <decoder>etc/decoder.xml</decoder>
```
