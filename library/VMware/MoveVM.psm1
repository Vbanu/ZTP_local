Import-Module VMware.VimAutomation.Cis.Core
Import-Module VMware.VimAutomation.Core
Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false -InvalidCertificateAction ignore -confirm:$false | Out-Null

Function Move-VM {
    
    Param
    (    
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $vCenterIP,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $vCenterUser,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $vCenterPass,
        
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $VMName,

        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $TargetHost,
        
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $TargetDatastore
    )
    
    try 
    {
        $vCenter = Connect-VIServer -Server $vCenterIP -User $vCenterUser -Password $vCenterPass -ErrorAction Stop
        write-host "Connected to vCenter [$vCenter]"
        
        $result = Move-VM -VM $VMName -Destination $TargetHost -Datastore $TargetDatastore

        if ($result)
        {
            $Description = "Migrated the VM [$VMName] to [$TargetDatastore]"
            write-host $Description
            return $true
        }
        $Description = "Failed to migrate the VM [$VMName] to [$TargetDatastore]"
        write-host $Description
        return $false
    }
    catch
    {   
        write-host $_.exception
        $Description = "Failed to Migrate VM [$VMName]"        
        return $false
    }
}