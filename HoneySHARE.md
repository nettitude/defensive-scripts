#Honey Share
### Use this query to convert it to an alert after setting either the honey share or path you want to alert on, then save the query as an alert - SYSVOL as an example
`index=main earliest=-1d sourcetype="wineventlog:security" EventCode=5140 Share_Name="\\\\*\\SYSVOL" OR Share_Path="\\??\\C:\\Windows\\SYSVOL\\sysvol"`
