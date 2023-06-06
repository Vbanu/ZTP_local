Import-Module VMware.VimAutomation.Cis.Core
Import-Module VMware.VimAutomation.Core
Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false -InvalidCertificateAction ignore -confirm:$false | Out-Null

$jsonFile=$args[0]

$data = Get-Content $jsonFile -Raw | ConvertFrom-JSON

[array] $ESXihosts = ($data).Servers;

# This is what we will return.  True will be set if there is a failure
$status = 0

try
{
    Foreach ($server in $EsxiHosts)
    {
        #
        # Log into host
        #
        $esxhost = $server.mgmtIP
        $EsxiRootPass = $server.osPassword
        Write-Host "Checking ESXi host [$esxhost]"
        $esxi = Connect-VIServer -Server $esxhost -User "root" -Password $EsxiRootPass -ErrorAction Stop
        $esxcli = Get-EsxCli -VMHost (Get-VMHost $esxi) -V2

        #
        # Check link status on host ports
        #
        $result = $esxcli.network.vswitch.standard.list.Invoke()

        #
        # Hack for Nutanix part of the Demo, remove later
        #
        # Write-Host "vmnic0 on $esxhost is up"
        # Start-Sleep -Seconds 1
        # Write-Host "vmnic1 on $esxhost is up"
        # Start-Sleep -Seconds 1

        foreach($object in $result)
        {
            $nics = $object.Uplinks | Where-Object{$_ -ne $null}
            foreach($nic in $nics)
            {
                $nic_detail = $esxcli.network.nic.get.Invoke(@{nicname="$nic"}) |
                    Select-Object @{N='VMHost';E={$esxi.Name}}, @{N='Switch';E={$result.Name}},
                        @{N='NIC';E={$nic}}, LinkStatus

                if ($nic_detail.LinkStatus -ne "Up")
                {
                    Write-Host "ERROR: $nic on $esxhost has the status of " $nic_detail.LinkStatus -ForegroundColor Red
                    $status = 1
                }
                else {
                    Write-Host "$nic on $esxhost is up"
                }        
            }   
        }
        #
        # We can add additional tests as needed.
        #

        #
        # Test to ensure connectivity between hosts on Storage and vMotion networks
        # ping test must check that mtu 9000 is configured for those interfaces
        #

        #
        # Check that NTP is enabled and time is sync'd across hosts
        #

        # 
        # Ensure ssh is disabled
        # 

        # Disconnect from host
        Disconnect-VIServer -Server $esxi -Confirm:$false
    }
}
catch 
{
    Write-Error $_
    write-host "Failed to execute or complete checks on an ESXi host.  Posible causes are host is powered off or credentials were invalid."
    
    # Disconnect from all hosts.
    $result = Disconnect-VIServer -Confirm:$false | Out-Null
    if ($result -contains $false)
    {
        Write-Host ("Failed to cleanly disconnect from server")
    }
    Exit 1
}	

if ($status -ne 0)
{
    Exit 1
}
else 
{
    Exit 0
}