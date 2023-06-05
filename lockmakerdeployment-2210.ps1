
$jsonFile=$args[0]

$data = Get-Content $jsonFile -Raw | ConvertFrom-JSON

$lockmakerOVA = "/home/SLE-15SP3.x86_64-15.3-254.ova"
$allhosts = ($data).Servers
#Write-Host $allhosts

for ($i = 0; $i -lt $data.Servers.Count; $i++) {
    $server = $data.Servers[$i]
	
	$esxiHost = $server.esxiHost
    $esxiUsername = $server.username
    $esxiPassword = $server.Password
    $Datastore = $server.Datastore
	$lockmakerHostname = "Edgevm"+$esxiHost
	$vsphereNetwork = $server.vsphereNetwork
	$lockmakerMemInGB = $server.lockmakerMemInGB
	$lockmakerCPUCount = $server.lockmakerCPUCount
	$lockmakerDiskSizeinGB = $server.lockmakerDiskSizeinGB
	
	
	



<# $vCenterServer = ""
$esxiHost = "10.10.103.111"
#$vCenterUsername = "administrator@vsphere.local"
#$vCenterPassword = "HP1nvent!"
#$esxiUsername = "root"
#$esxiPassword = "secret"
#$Datastore = "vsanDatastoreT"
$lockmakerHostname = "Edgevm"+$esxiHost
#$vsphereCluster = ""
$vsphereNetwork = "VM Network"
$lockmakerMemInGB = 32
$lockmakerCPUCount = 16
$lockmakerDiskSizeinGB = 800 #>

#Cheking if minimium memory requirement is met.
if ($lockmakerMemInGB -ge 16)
{
    Write-Host "Memory is greater than or equal to 16GB"
}
else
{
    throw "Memory should greater than or equal to 16"
    exit 1
}

#Checking if minimum CPU count requirement is met.
if ($lockmakerCPUCount -ge 8)
{
    Write-Host "CPU Count is greater than 8"
}
else
{
    throw "CPU Count should be greater than or equal to 8"
    exit 1
}
#Connect to jfrog and get ova image
curl.exe -u lhcp-gateway-bot:CM@2023rock$ -O "https://hcss.jfrog.io/artifactory/lhcp-sles-repo/Golden-image/20230109/publish/images/lockmaker/$lockmakerOVA" --ssl-no-revoke
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false

#If vCenter is blank, connect directly to ESXi server
if (!$vCenterServer)
{
    connect-viserver -server $esxiHost -User $esxiUsername -Password $esxiPassword
    if($global:DefaultVIServer.Name -eq $esxiHost)    {
        Write-host "ESXi connected successfully"
    }
    else{
        throw "Unable to connect to ESXi Server"
    }
}
else {
    #Connect to vSphere
    if ($global:DefaultVIServer.Name -eq $vCenterServer)    {
        Write-Host "vSphere session already established"
    }
    elseif ($global:DefaultVIServer.Name -eq $null)    {
        Write-Host "Not connected to any vSphere, connecting.."
        connect-viserver -Server $vCenterServer -User $vCenterUsername -Password $vCenterPassword 
    }
    elseif ($global:DefaultVIServer.Name -ne $vCenterServer)    {
        throw "Connected to other vSphere server(s), please disconnect prior vSphere connections before running script"
    }

    #Verify connectivity
    if ($global:DefaultVIServer.Name -eq $vCenterServer)
    {
        Write-Host "Vsphere connection established"
    }
    else
    {
        throw "Unable to connect to vSphere, please verify parameters and try again"

    }
}

#Verify VM Name doesn't exist, Deploy the VM on either vSphere or ESXi

$lockmakerVMDetails = Get-VM $lockmakerHostname -ErrorAction 'silentlycontinue'
if ($lockmakerVMDetails) {
    throw "VM with name $lockmakerhostname already exists, exiting.."
    }
elseif ($vCenterServer){
    write-host "Deploying Lockmaker VM on vSphere"
    $vSphereDatastore = Get-Datastore -Name $Datastore
    $vsphereHost = Get-VMHost -Name $esxiHost
    Import-VApp -Source $lockmakerOVA -Location $vsphereCluster -Datastore $vSphereDatastore -Name $lockmakerHostname -VMHost $esxiHost -DiskStorageFormat Thin
}
else{
    write-host "Deploying Lockmaker VM on ESXi"
    $vSphereDatastore = Get-Datastore -Name $Datastore
    $vsphereHost = Get-VMHost -Name $esxiHost
    tar -xf $lockmakerOVA
    $ovfFile = dir *.ovf
    Import-VApp -Source $ovfFile.Name -Datastore $vSphereDatastore -Name $lockmakerHostname -VMHost $esxiHost -DiskStorageFormat Thin
}

#Verify VM Deployment
$lockmakerVMDetails = Get-VM $lockmakerHostname -ErrorAction 'silentlycontinue'
if(!$lockmakerVMDetails){
throw "Lockmaker VM not deployed successfully.. exiting.."}

#Set VM Memory if required
$lockmakerVMDetails = Get-VM $lockmakerHostname
if ($lockmakerMemInGB -eq $lockmakerVMDetails.MemoryGB)
{
    write-host "Memory for VM at default value, skipping edit"
}
else 
{
    write-host "Setting memory to ${lockmakerMemInGB}GB"
    set-VM $lockmakerHostname -MemoryGB $lockmakerMemInGB -Confirm:$false
}

if($lockmakerCPUCount -eq $lockmakerVMDetails.numCpu)
{
    write-host "CPU Count for VM at default value, skipping edit"
}
else
{
    write-host "Setting CPU count to $lockmakerCPUCount"
    set-VM $lockmakerHostname -NumCpu $lockmakerCPUCount -Confirm:$false
}

#Verify VM has set CPU and memory, and start VM

$lockmakerVMDetails = Get-VM $lockmakerHostname

if ($lockmakerVMDetails.MemoryGB -eq $lockmakerMemInGB)
{
    Write-Host "Memory set correctly"
}
else
{
    throw "Memory not set correctly, please verify VM is in a healthy state"
}
if ($lockmakerVMDetails.numCpu -eq $lockmakerCPUCount)
{
    Write-Host "CPU count set correctly"
}
else
{
    throw "CPU count not set correctly, please verify VM is in a healthy state"
}

#Check data disk size and modify if neccisary Modify Data disk  size
$VMDisks = Get-HardDisk $lockmakerVMDetails
if ($VMDisks[1] -eq $lockmakerDiskSizeinGB){
    write-host "Disk size is at requested value.."
    }
else{
Set-HardDisk $VMDisks[1] -CapacityGB $lockmakerDiskSizeinGB -confirm:$false}

#Verify Disk size
$VMDisksverify = Get-HardDisk $lockmakerVMDetails
if($VMDisksverify[1].CapacityGB -notmatch $lockmakerDiskSizeinGB){
    throw "VM disk size not set correctly, please verify VM is in a healthy state"}


start-vm $lockmakerHostname -Confirm:$false
if (! $?){
    Write-Host "Starting the VM failed."
    exit 1
}
disconnect-viserver -Confirm:$false | Out-Null
#disconnect-viserver
}
