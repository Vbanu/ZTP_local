# Connect to the vSphere server
$vcServer = "10.10.1.67"
$vcUsername = "administrator@vsphere.local"
$vcPassword = "HP1nvent!"
Connect-VIServer -Server $vcServer -User $vcUsername -Password $vcPassword

# Define the OVA deployment parameters
$ovaFilePath = "/home/SLE-15SP3.x86_64-15.3-254.ova"
$datastoreName = "vsanDatastoreT"
$vmName = "singlenode_witness"
$network0 = "VM Network"

# Deploy the OVA
$ovfConfig = Get-OvfConfiguration -Ovf $ovaFilePath
Write-Host $ovfConfig.NetworkMapping
$ovfConfig.NetworkMapping | Get-Member

$ovfConfig.NetworkMapping = $ovfConfig.NetworkMapping | Where-Object {$_.Name -eq $network0} # Modify if necessary
$ovfConfig.DatastoreMapping = $ovfConfig.DatastoreMapping | Where-Object {$_.Datastore.Name -eq $datastoreName}


$ovfDeploymentOptions = New-OvfConfiguration $ovfConfig
$ovfDeploymentParams = @{
    OvfConfiguration = $ovfDeploymentOptions
    Name = $vmName
    Datastore = Get-Datastore -Name $datastoreName
    VMHost = Get-VMHost | Select-Object -First 1 # Modify if necessary
    ResourcePool = Get-Cluster | Get-ResourcePool | Select-Object -First 1 # Modify if necessary
}
Write-Host "$Datastore"

$ovfDeploymentTask = Import-VApp -Source $ovaFilePath @ovfDeploymentParams
$ovfDeploymentTask | Wait-Task

# Power on the virtual machine
$vm = Get-VM -Name $vmName
$vm | Start-VM

# Perform basic configuration (example: change the number of CPUs)
$spec = New-Object -TypeName VMware.Vim.VirtualMachineConfigSpec
$spec.NumCPUs = 2 # Modify as needed
$vm.ExtensionData.ReconfigVM_Task($spec) | Wait-Task

# Disconnect from the vSphere server
Disconnect-VIServer -Server $vcServer -Confirm:$false
