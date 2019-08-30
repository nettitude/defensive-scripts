# Splunk Queries - IN PROGRESS

## Usage Notes

* These are the bulk of the queries demonstrated during our different talks, we will be periodically updating the list as we play with new detections and hope/aim to build up a reasonable repository for people to play with.

* These queries were developed in our lab environment, be sure to modify where required, such as the index, sourcetype and source/destionation IPs.

## Kerberos

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

## Lateral Movement

### Show installed services where the name is not mgmt_service (can be done with 7045 or 4697)
`index=main LogName=System EventCode=7045 NOT (Service_Name=mgmt_service OR Service_Type="*Kernel*") AND (Service_Start_Type="*demand*")
| eval Message=split(Message,".") 
| eval Short_Message=mvindex(Message,0) 
| eval Service_File_Name=substr(Service_File_Name,1,100)."..." 
| table _time host Service_Name,Service_Type, Service_Start_Type, Service_Account, Short_Message, Service_File_Name`

`index=main earliest=-7d EventCode=4697 NOT (Service_File_Name="C:\\Windows\\*" OR Service_File_Name="\\SystemRoot\\*" OR Service_File_Name="*C:\\Program Files*\\*")
AND (Account_Name != "*$*")
| eval Service_File_Name=substr(Service_File_Name,1,100)."..." 
| table _time, ComputerName, Account_Name, Service_Name, Service_File_Name, Service_Start_Type`

### Show timeout service control manager events for service anomalies
`index=main earliest=-7d sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" LogName=System EventCode=7009 Message="A timeout was reached*" 
| table host _time Message`

### Show registry write events for services and contain the comspec string
`index=main earliest=-14d LogName=Microsoft-Windows-Sysmon/Operational EventCode=13 "HKLM\\System\\CurrentControlSet\\Services\\*" AND "*%%COMSPEC%%*" 
| eval Details=substr(Details,1,100)."..." 
| Table _time host Image TargetObject Details`

### Identify suspicous binaires making smb network connections - needs context as per the talk
`index=main earliest=-14d LogName=Microsoft-Windows-Sysmon/Operational (EventCode=3 AND DestinationPort=135 OR DestinationPort=139 OR DestinationPort=445)
| table UtcTime User Image SourceIp DestinationIp DestinationPort`

### Shows WMI Consumer Events 
`index=main earliest=-7d SourceName=Microsoft-Windows-Sysmon EventCode=21 | table ComputerName, User, EventType, Consumer, Filter, Operation`

### Shows WMI Filter Events
`index=main earliest=-7d SourceName=Microsoft-Windows-Sysmon EventCode=19 | table ComputerName, User, EventType, EventNamespace, Name Operation, Query`

### Show process creation events involving wmiprvse and display the parent and child processes with command line arguments
`index=main earliest=-7d SourceName=Microsoft-Windows-Sysmon EventCode=1 "*wmiprvse.exe*"
| eval CommandLine=substr(CommandLine,1,100)."..." 
| Table UtcTime, ComputerName, User, ParentImage, Image, CommandLine, OriginalFileName`

### Show process creation events with windows events versus sysmon events as above
`index=main earliest=-60d EventCode=4688 Creator_Process_Name="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe" | table Creator_Process_Name, New_Process_Name`

### If WMI is not leveraged within the environmnment, this will show you network logons being made from WMI binaries inside the WBEM directory
`index=main earliest=-7d “C:\Windows\System32\wbem\” EventCode=4624 | table Account_Name, Logon_Type`


### Show events where svchost is spawning mmc to identify mmc20 dcom
`index=main earliest=-30d ("*svchost.exe*" AND "*mmc.exe*") | table User, ComputerName, ParentImage, ParentCommandLine, Image, CommandLine`

### Show events containing the dcomlaunch string and calling rundll32
`index=main earliest=-7d sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 ParentCommandLine="*dcomlaunch*" OriginalFileName="RUNDLL32.EXE" | table _time, ComputerName, User, Image, CommandLine`

### Show events calling shell32 with the SHCreateLocalServer arguement for dcom
`index=main earliest=-30d sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 shell32.dll,SHCreateLocalServerRunDll | table ComputerName, User, CommandLine, ParentCommandLine`
