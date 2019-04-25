function Disable-NetBIOSResolution {
    <#
    .SYNOPSIS
    
    Disable NetBIOS Resolution on all NICs with TCP/IP Enabled.
    
    Author: Tom MacDonald & Rob Bone (Nettitude Red Team)  
    
    .DESCRIPTION
    
    Please use this script as a scaffold only, and make changes appropriate to your environment after testing in Dev environment.
    Disables NetBIOS Resolution on all NICs with TCP/IP Enabled (ie, has a valid IP)
    Requires running with an appropriately privileged account on the endpoints you wish to change.
        
    .PARAMETER ComputerName
    
    Specifies an array of one or more hosts to enumerate, passable on the pipeline.
    If -ComputerName is not passed, the default behavior is to enumerate all machines
    in the domain returned by Get-DomainComputer.
    
    .PARAMETER InputHostsFile 
    
    Specifies the path to a file which contains a list of hosts to target.
    
    .EXAMPLE
    
    Disable-NetBIOSResolution -ComputerName WS01,WS02

    Disables NetBIOS resolution for WS01 and WS02. 
    
    .EXAMPLE
    
    Disable-NetBIOSResolution -InputHostsFile $ENV:UserProfile\Documents\hostnames.txt
    
    Disables NetBIOS resolution for all hosts listed in $ENV:UserProfile\Documents\hostnames.txt.

    .EXAMPLE

    Hostname | Disable-NetBIOSResolution

    Disables NetBIOS resolution for the current host.

    .EXAMPLE

    Disable-NetBIOSResolution -InputHostsFile .\hostnames.txt | Export-Csv -Append -Path $ENV:UserProfile\Documents\NetBIOS_Disable.txt

    Disable NetBIOS resolution for the hosts listed in hostnames.txt and export the hostname and NetBIOS response codes in CSV format.
 
    .OUTPUTS
    
    A list of objects with the hostname and NetBIOS response codes. 
    #>
    
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ParameterSetName="Pipe")]
        [Alias('DNSHostName')]
        [String[]]
        $ComputerName,

        [String]
        [Parameter(ParameterSetName="File")]
        $InputHostsFile
    )

    # From https://docs.microsoft.com/en-us/windows/desktop/CIMWin32Prov/settcpipnetbios-method-in-class-win32-networkadapterconfiguration
    $responseCodeMap = @{
        "0" = "Successful completion. No reboot required.";
        "1" = "Successful completion. Reboot required.";
        "64" = "Method not supported on this platform.";
        "65" = "Unknown failure.";
        "66" = "Invalid subnet mask.";
        "67" = "An error occurred while processing an instance that was returned.";
        "68" = "Invalid input parameter.";
        "69" = "More than five gateways specified.";
        "70" = "Invalid IP address.";
        "71" = "Invalid gateway IP address.";
        "72" = "An error occurred while accessing the registry for the requested information.";
        "73" = "Invalid domain name.";
        "74" = "Invalid host name.";
        "75" = "No primary or secondary WINS server defined.";
        "76" = "Invalid file.";
        "77" = "Invalid system path.";
        "78" = "File copy failed.";
        "79" = "Invalid security parameter.";
        "80" = "Unable to configure TCP/IP service.";
        "81" = "Unable to configure DHCP service.";
        "82" = "Unable to renew DHCP lease.";
        "83" = "Unable to release DHCP lease.";
        "84" = "IP not enabled on adapter.";
        "85" = "IPX not enabled on adapter.";
        "86" = "Frame or network number bounds error.";
        "87" = "Invalid frame type.";
        "88" = "Invalid network number.";
        "89" = "Duplicate network number.";
        "90" = "Parameter out of bounds.";
        "91" = "Access denied.";
        "92" = "Out of memory.";
        "93" = "Already exists.";
        "94" = "Path, file, or object not found.";
        "95" = "Unable to notify service.";
        "96" = "Unable to notify DNS service.";
        "97" = "Interface not configurable.";
        "98" = "Not all DHCP leases can be released or renewed.";
        "100" = "DHCP not enabled on adapter.";
        "101" = "Other Unknown Error. 4294967295"
    }

    Write-Host "Nettitude - Disable NetBIOS Resolution on all NICs with TCP/IP Enabled." -ForegroundColor Green

    If ($PSBoundParameters.ContainsKey('ComputerName'))
    {
        $targets = $ComputerName.split(",")
    } ElseIf ($PSBoundParameters.ContainsKey('InputHostsFile'))
    {
        $targets = (Get-Content $ENV:UserProfile\Documents\hostnames.txt) 
    }

    $results = @()

    ForEach ($hostname in $targets)
    {
        If(-Not (Test-Connection -ComputerName $hostname -BufferSize 16 -Count 1 -ErrorAction 0))
        {
            Write-Host "[-] WARNING: Cannot reach $hostname, disabling of NetBIOS has failed for this host" -ForegroundColor Red
            $props = [ordered]@{Hostname=$hostname; Description="Host unreachable"; ResponseMessage = "Host unreachable"}
            $result = New-Object -TypeName PSObject -Property $props
            $results += $result
        }
        Else 
        {
            $FindNetAdapters = "Select * from Win32_NetworkAdapterConfiguration where IPEnabled = True"
            $AdapterConfig = Get-WMIObject -query $FindNetAdapters
            $results = @()
            ForEach ($adapter in $AdapterConfig) 
            {
                $StatusCode = $adapter.SetTcpipNetbios(2)
                $StatusMessage = $responseCodeMap[$($StatusCode.ReturnValue.toString())]
                $props = [ordered]@{Hostname=$hostname; Description=$adapter.Description; ResponseMessage = $StatusMessage} 
                $result = New-Object -TypeName PSObject -Property $props
                $results += $result
            }
        }
    }
    $results
}