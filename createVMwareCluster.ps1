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
    Write-Host "Connecting to vCenter Server $vCenterIP "
    $vCenter = Connect-VIServer -Server $vCenterIP -User $vCenterUser -Password $vCenterPass -ErrorAction Stop
    write-host "Connected to server $vCenter"
    
    Write-Host "Creating DataCenter [$vCenterDC] on vCenter [$vCenterIP]."
    $datacenter_result = Set-DataCenter -vCenterDC $vCenterDC -vCenterIP $vCenterIP

    if ($datacenter_result -eq $true) 
    {
        #$configure_status = $false
        $configure_status = Set-VCSACluster -vCenterDC $vCenterDC -vCenterCluster $vCenterCluster -ESXIServers $ESXihosts -vCenterIP $vCenterIP
        if ($configure_status -contains $false) 
        {
            Write-Host "Failed to create Cluster"
            return $false
        }
        else 
        {
            write-host "Datacenter and cluster created on vcenter"
			#Should not turn on Cluster HA as it causes vSAN creation to fail, need to turn it on post vSAN 
        
            #$setclusterHA = Set-vCenterClusterHA -vCenterCluster $vCenterCluster
            #if ($setclusterHA -eq $false)
            #{
            #    Write-Host "Failed to set cluster HA"
            #    return $false
            #}
            #else 
            #{
            #    Write-Host "HA enabled on Cluster"
            #    return $true
            #}
        
        #adding vcenter license
        # if($vCenter_License -and $ESXi_License)
        # {
        #     $license_result = Add-License -vCenterData $vCenter -vCenterCluster $vCenterCluster -vCenter_License $vCenter_License -ESXi_License $ESXi_License
        #     if ($license_result -eq $true)
        #     {
        #         write-host "vCenter successfully licensed"
        #         return $true
        #     }
        # }
        # return $true
        }
    }
    else 
    {
        $description = "Datacenter [$vCenterDC] is not created on vCenter [$vCenterIP]."
        Write-Host $description
        return $false
    }
    #disconnect vCenter
}
catch {
    Write-Host "Failed to connect to vCenter."
    Write-Error $_
    return $false
}

exit 0
return 0
