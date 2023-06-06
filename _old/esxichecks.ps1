###validate ESXi host settings

#$host1 = "192.168.102.30"
#$host1ilo = "192.168.102.10"
#$host2 = "192.168.102.31"
#$host2ilo = "192.168.102.11"
#$host3 = "192.168.102.32"
#$host3ilo = "192.168.102.12"


#$IP=@()
#$Username=@()
#$Password=@()
$Servers = Import-Csv "C:\deid_cluster2.csv" 

Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false -InvalidCertificateAction ignore -confirm:$false | Out-Null

##connect to each host
Write-Host "Pinging ESXi hosts"

foreach($Server in $Servers)
{
if (Test-Connection $Server.ESXIIP -count 1 -Quiet) {

        write-host $Server.ESXIIP "is online" -ForegroundColor Green
        }
        else{
        write-host $Server.ESXIIP "is not online" -ForegroundColor Red
        Break
        write-host "one or more servers cannot successfully ping"
        }

}

#Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false

foreach($Server in $Servers)
{
    # Connect to each ESXI Host
    connect-viserver -server $Server.ESXIIP -user root -password $Server.ESXIPASS

    if (get-vmhost | where{$_.ConnectionState -eq 'connected'}){
        write-host $Server.ESXIIP "is connected" -ForegroundColor Green
        }
        else{
        write-host $Server.ESXIIP "is not connected" -ForegroundColor Red
        
        write-host "the servers are not connected please fix them"
        break
        }

       $esxcli = Get-EsxCli -VMhost $Server.ESXIIP -V2

$result = $esxcli.network.vswitch.standard.list.Invoke()

$vswitch = $result.name | where{$_ -ne $null}

if ($vswitch -eq "vSwitch0")
{
Write-Host "vSwitch0 is present" -ForegroundColor Green
}
else
{
Write-Host "vSwitch0 is not present" -ForegroundColor Red
} 
        
Write-Host "verifying Uplinks ports of vSwitch0" -ForegroundColor Cyan

$Uplinks = $result.Uplinks | where{$_ -ne $null}


if ($Uplinks -in "vmnic1 vmnic0")
{
Write-Host "vmnic0 and vmnic1 are part of vswitch0" -ForegroundColor Green
}
else
{
Write-Host "vmnic0 and vmnic1 are not part of vswitch0" -ForegroundColor Red
}


write-host "verifying portgroups" -ForegroundColor Cyan

$Portgroup = $result.Portgroups | where{$_ -ne $null}

if ($Portgroup -in "Production Storage Management")
{
Write-Host "Portgroups Production Storage and Management are part of vSwitch0" -ForegroundColor Green
}
else
{
Write-Host "Portgroups Production Storage and Management are not part of vSwitch0" -ForegroundColor Red
}

     ##validate ESXi network

     #if(get-vmhost

}
#Get-VMHost