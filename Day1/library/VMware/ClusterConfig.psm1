Import-Module VMware.VimAutomation.Cis.Core
Import-Module VMware.VimAutomation.Core
Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false -InvalidCertificateAction ignore -confirm:$false | Out-Null

Function Set-VCSACluster {
    param
    (
        [parameter(Mandatory = $true)]
        [string] $vCenterDC,
        
        [parameter(Mandatory = $true)]
        [string] $vCenterCluster,
        
        [parameter(Mandatory = $true)]
        $EsxiServers,

        [parameter(Mandatory = $true)]
        [string] $vCenterIP

    )
    try 
    {
        
        Write-Host "Creating cluster [$vCenterCluster] on vCenter."
        $cluster_result = New-vCenterCluster -vCenterCluster $vCenterCluster -vCenterDC $vCenterDC -vCenterIP $vCenterIP

        if ($cluster_result -eq $true) 
        {
            $i = 1
            foreach ($server in $EsxiServers) 
            {
                $server_ip = $server.mgmtIP
                $ESXiPass = $server.osPassword
                $server_result = Get-VMHost -Name $server_ip -ErrorAction SilentlyContinue

                if ($server_result) 
                {
                    if ($server_result.ConnectionState -eq "Disconnected") 
                    {
                        $task = Set-VMhost $server_result -State Connected | Out-Null
                        Start-Job -ScriptBlock { $task } | Wait-Job
                    }
                    $status_description = "ESXi Host [$server_ip] is already added to vCenter cluster [$vCenterCluster]. The Connection Status is [$($server_result.ConnectionState)] and Power State is [$($server_result.PowerState)]."
                    Write-Host $status_description
                }
                else 
                {
                    Write-Host "Adding host [$server_ip] to cluster [$vCenterCluster] on vCenter."
                    $host_result = Add-Host2Cluster -ESXIserverIP $server_ip -ESXIuser "root" -ESXIPass $EsxiPass -vCenterCluster $vCenterCluster  -vCenterDC $vCenterDC

                    if ($host_result -eq $true) 
                    {
                        # Exit maintenance mode
                        try 
                        {
                            Write-Host "Exiting Maintenance mode - $server_ip"
                            $vmHost = Get-VMHost -Name $server_ip
                            $task = Set-VMhost $vmHost -State Connected | Out-Null
                            Start-Job -ScriptBlock { $task } | Wait-Job
                            Write-Host "ESXi Host [$server_ip] is added to vCenter cluster [$vCenterCluster]. The Connection Status is [$($vmHost.ConnectionState)] and Power State is [$($vmHost.PowerState)]."
                        }
                        catch 
                        {
                            Write-Error $_
                            write-host "ESXi Host [$server_ip] is added to vCenter cluster [$vCenterCluster]. But failed to exit maintenance mode"
                            return $false
                        }									
                    }
                    else 
                    {
                        Write-Host = "ESXi Host [$server_ip] is not added to vCenter cluster [$vCenterCluster]."
                        return $false
                    }
                }
                $i++
            }
        }
        else {
            Write-Host "cluster [$vCenterCluster] is not created in vCenter."
        }
    }
    catch {
        write-Host "Exception while adding host to cluster."
        Write-Host $_
    }
}

Function Set-DataCenter {
    param
    (
        [parameter(Mandatory = $true)]
        [String] $vCenterDC,

        [parameter(Mandatory = $true)]
        [String] $vCenterIP
    )

    $vC_Existing_Datacenter = Get-Datacenter -Name $vCenterDC -ErrorAction SilentlyContinue
    if ($vC_Existing_Datacenter) {
        Write-Host "[$vCenterDC] DataCenter already exists on vCenter [$vCenterIP]."
        return $true
    }
    try {
        $Location = Get-Folder -NoRecursion

        # if successfull - create datacenter
        $task = New-DataCenter -Name $vCenterDC -Location $Location -ErrorAction Stop
        Start-Job -ScriptBlock { $task } | Wait-Job
        
        if ($task) {
            Write-Host "Successfully created DataCenter [$vCenterDC] on vCenter [$vCenterIP]."
            return $true
        }
    }
    catch {
        Write-Host "DataCenter [$vCenterDC] not created on vCenter [$vCenterIP]."
        Write-Host  $_
        return $false
    }
}
Function New-vCenterCluster {
    param
    (
        [parameter(Mandatory = $true)]
        [String] $vCenterCluster,
        
        [parameter(Mandatory = $true)]
        [String] $vCenterDC,

        [parameter(Mandatory = $true)]
        [String] $vCenterIP
    )

    $vCenter_DataCenter = Get-Datacenter -Name $vCenterDC -Server $vCenterIP
    if($vCenter_DataCenter)
    {
        $vCenter_Cluster = Get-Cluster -Name $vCenterCluster -Location $vCenterDC -ErrorAction SilentlyContinue
        if ($vCenter_Cluster) 
        {
            write-Host "[$vCenterCluster] Cluster already exists on vCenter."
            return $true
        }
        else {
            try 
            {
                $task = New-Cluster -Name $vCenterCluster -Location $vCenterDC -DrsEnabled -ErrorAction stop
                Start-Job -ScriptBlock { $task } | Wait-Job
                
                if ($task) {
                    Write-Host "Created cluster under DataCenter [$vCenterDC)] on vCenter."
                    return $true
                }
                else {
                    Write-Host "Cluster could not created under DataCenter [$vCenterDC)] on vCenter. $_"
                    return $false
                }
            }
            catch {
                Write-Host "Cluster could not created under DataCenter [$($vCenter_DataCenter.name)] in vCenter. $_"
                return $false
            }
        }
    }
    else 
    {
        Write-Host "No Datacenter found on vCenter"    
        return $false
    }
}

Function Add-License {
    Param
    (    
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Object] $vCenterData,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $vCenter_License,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $vCenterCluster,
        
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $ESXi_License

    )
    try 
    {
        $LM = get-view($vCenterData.ExtensionData.content.LicenseManager) 
        $existinglicenses = $LM.licenses.licensekey 
        
        Foreach ($license in $LM.licenses)
        {   
            if ($license.licenseKey -eq $vCenter_License){
                if ($license.name -notmatch "vCenter"){
                    write-host "Invalid vCenter License"
                    exit(1)
                }
            }
            if ($license.licenseKey -eq $esxi_License){
                if ($license.name -notmatch "vSphere"){
                    write-host "Invalid ESXi License"
                    exit(1)
                }
            }
        }

        if ($vCenter_License -in $existinglicenses)
        {
            $description = "vCenter License already Present on vCenter"
            write-host $description
        }
        else
        {
            $LM.AddLicense($vCenter_License,$null) 
            $LAM = get-view($LM.licenseAssignmentManager) 
            $LAM.UpdateAssignedLicense($vCenter.InstanceUuid,$vCenter_License,$Null)
            $description = "Addded vCenter License"
            write-host $description
        }
        if ($ESXi_License -in $existinglicenses)
        {   
            $description = "ESXi License already Present on vCenter"
            write-host $description
        }
        else 
        {
            
            $cluster_hosts = Get-Cluster -Name $vCenterCluster | Get-VMhost 
            set-vmhost -VMHost $cluster_hosts -LicenseKey $ESXi_License
            foreach ($esxihost in $cluster_hosts){
                $res = Get-VMHost -Name $($esxihost.name) | Select-Object Name, LicenseKey 
                if ($res.LicenseKey -eq $ESXi_License)
                {
                    $description = "Added ESXi License"
                    write-host $description
                }
                else 
                {
                    $description ="Failed to add License/License is Invalid"
                    write-host $description
                    return $false
                }
            }
        }
        return $true
    }
    catch {
        $description = "Failed to Add License.check output for more details."
        write-host $_
        return $false
    } 

}
Function Add-Host2Cluster {
    param
    (
        [parameter(Mandatory = $true)]
        [String] $vCenterDC,

        [parameter(Mandatory = $true)]
        [String] $ESXIserverIP,

        [parameter(Mandatory = $true)]
        [String] $ESXIPass,
        
        [parameter(Mandatory = $true)]
        [String] $ESXIuser,
        
        [parameter(Mandatory = $true)]
        [String] $vCenterCluster
    )

    $vCenter_Cluster = Get-Cluster -Name $vCenterCluster -Location $vCenterDC
    try {
        if (Test-Connection -ComputerName $ESXIserverIP -Count 1) {
            $task = Add-VMHost -Name $ESXIserverIP -Location $vCenter_Cluster -User $ESXIuser -Password $ESXIpass -Force
            Start-Job -ScriptBlock { $task } | Wait-Job

            if ($task) {
                Write-Host "ESXi Host [$ESXIserverIP] is added to vCenter cluster [$vCenter_Cluster)]. The Connection Status is [$($task.ConnectionState)] and Power State is [$($task.PowerState)]."
                return $true
            }
            else {
                Write-Host "ESXi Host [$ESXIserverIP] is not added to vCenter cluster [$vCenter_Cluster)]."
                return $false
            }
        }
        else {
            Write-Host "ESXi Host [$ESXIserverIP] is not pinging. Skipping its addition to the cluster [$vCenter_Cluster)]."
            return $false
        }
    }
    catch {
        Write-Host $_
        Write-Host "ESXi Host [$ESXIserverIP] is not added to vCenter cluster [$vCenter_Cluster)]."
        return $false
    }
}
Function Set-vCenterClusterHA 
{

    Param
    (    
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $vCenterCluster
    )
    
    try 
    {
        $Cluster = Get-Cluster -Name $vCenterCluster -ErrorAction SilentlyContinue
        if (!$Cluster.HAEnabled) 
        {
            $result = Set-Cluster -Cluster $vCenterCluster -HAEnabled:$true -Confirm:$false
            if($result)
            {
                $Description =  "vSphere HA Sucessfully Turned ON for cluster : $vCenterCluster"
                write-host $Description
                return $true
            }
            $Description = "Failed to enable vSphere HA for cluster: $vCenterCluster"
            write-host $Description
            return $false
        }
        else 
        {
            $Description = "vSphere HA is already Turned ON for cluster : $vCenterCluster"
            write-host $Description 
            return $true
        }
    }
    catch
    {   
        write-host $_.exception
        write-host "Failed to Configure HA"
        return $false
    }
}