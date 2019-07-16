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

### Identify all hosts in a network making network connections to a specific IP
`index=main earliest=-25h sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" DestinationIp="68.183.32.229" | stats count by host,SourceIp,EventCode | sort - count`

### Identify all hosts in a network who have made a DNS queries for a specific IP
`index=main earliest=-25h sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22 "68.183.32.229" | stats count by host | sort - count`

### Identify all hosts in a network who are making a network connection to or who have made a DNS query for a specific IP
`index=main earliest=-25h sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" ("EventCode=22" AND "68.183.32.229") OR ("EventCode=3" AND "68.183.32.229") | stats count by ComputerName,EventCode | sort - count`

### Show all hosts in a network who have made a network connection or DNS query to an external IP
`index=main earliest=-25h sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" ("EventCode=22" AND "QueryResults*") OR ("EventCode=3" AND "DestinationIp*") NOT (QueryResults="10.*" OR QueryResults="172.16.*" OR QueryResults="192.168.*") NOT (DestinationIp="10.*" OR DestinationIp="172.16.*" OR DestinationIp="192.168.*") | table ComputerName,Image,DestinationIp,QueryResults`

`index=main earliest=-25h sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" ("EventCode=22" AND "QueryResults*") OR ("EventCode=3" AND "DestinationIp*") NOT (QueryResults="10.*" OR QueryResults="172.16.*" OR QueryResults="192.168.*") NOT (DestinationIp="10.*" OR DestinationIp="172.16.*" OR DestinationIp="192.168.*") | stats count(DestinationIp), count(QueryResults) by host, Image`

### Show all executables talking to external IPs or performing DNS queries
`index=main earliest=-25h sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" "C:\\*.exe" NOT (DestinationIp="10.*" OR DestinationIp="172.16.*" OR DestinationIp="192.168.*") NOT (QueryResults="10.*" OR QueryResults="172.16.*" OR QueryResults="192.168.*") | table ComputerName,Image,DestinationIp,QueryResults | sort - count`
