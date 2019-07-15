# Splunk Queries - IN PROGRESS

## Kerberoasting Query
`index=main earliest=-25h sourcetype=WinEventLog:Security EventCode=4769 (Ticket_Encryption_Type = 0x17 AND Account_Name != "*$*") | stats count by Account_Name | sort - count`

## Golden Ticket Detection
`index=main earliest=-25h sourcetype=WinEventLog:* (Account_Name != "Administrator" AND Account_Name != "*$*" AND "Security ID:*500") | stats count by Account_Name, EventCode | sort - count`
