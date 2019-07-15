# Splunk Queries - IN PROGRESS

## Kerberoasting Query
`index=main earliest=-25d sourcetype=WinEventLog:Security EventCode=4769 (Ticket_Encryption_Type = 0x17 AND Account_Name != "*$*") | stats count by Account_Name | sort - count`

## Golden Ticket Detection
