Import-Module ./library/VMware/ClusterConfig.psm1

#Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Proces
Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false -InvalidCertificateAction ignore -confirm:$false | Out-Null

$jsonFile=$args[0]

$data = Get-Content $jsonFile -Raw | ConvertFrom-JSON

$vCenterIP = $data.vCenter.IP
$vCenterUser = $data.vCenter.username
$vCenterPass = $data.vCenter.password
$vCenterDC = $data.vCenter.DCName
$vCenterCluster = $data.vCenter.clusterName
$ESXihosts = @()
$ESXihosts = ($data).Servers;
try 
{
    # vCenter connection
    Write-Host "Connecting to vCenter Server $vCenter"
    $vCenter = Connect-VIServer -Server $vCenterIP -User $vCenterUser -Password $vCenterPass -ErrorAction Stop
    write-host "Connected to server $vCenter"
    $setclusterHA = Set-vCenterClusterHA -vCenterCluster $vCenterCluster
            if ($setclusterHA -eq $false)
            {
                Write-Host "Failed to set cluster HA "
                #return $false
            }
            else 
            {
                Write-Host "HA enabled on Cluster"
                #return $true
            }
	
}
catch {
    Write-Host "Failed to connect to vCenter."
    Write-Error $_
    return $false
}

exit 0
return 0
