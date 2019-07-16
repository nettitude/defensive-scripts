# Splunk Queries - IN PROGRESS

## Usage Notes

* These are the bulk of the queries demonstrated during the talk, we will be periodically updating the list as we play with new detections and hope/aim to build up a reasonable repository for people to play with.

* These queries were developed in our lab environment, be sure to modify where required, such as the index, sourcetype and source/destionation IPs.

### Kerberoasting Query
`index=main earliest=-25h sourcetype=WinEventLog:Security EventCode=4769 (Ticket_Encryption_Type = 0x17 AND Account_Name != "*$*") | stats count by Account_Name | sort - count`

### Golden Ticket Detection
`index=main earliest=-25h sourcetype=WinEventLog:* (Account_Name != "Administrator" AND Account_Name != "*$*" AND "Security ID:*500") | stats count by Account_Name, EventCode | sort - count`

### Golden Ticket Abuse Hunting
`index=main earliest=-25h sourcetype=WinEventLog:Security EventCode=4738 (Account_Name != "Administrator" AND Account_Name != "*$*" AND "Security ID:*500") | table Account_Name`

### Identify network connections being made from a specified host
`index=main earliest=-25h sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" SourceIp=10.150.10.34 | stats count by DestinationIp,EventCode | sort - count`

