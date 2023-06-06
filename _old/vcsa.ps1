 
### VCSA selection, depends on what site, ?sites 1-200?####

### depending on the site ID can have a if site ID is 200###
$VCSA = "192.168.102.33"
$VCSAUSER = "administrator@bas-hpe.local"
$VCSAPASS = "Password!234"


Set-PowerCLIConfiguration -Scope User -InvalidCertificateAction Ignore -Confirm:$false

Write-Host "Connecting to vCenter" -Foregroundcolor "Green"

Connect-VIServer -Server $VCSA -User $VCSAUSER -Password $VCSAPASS


##add hosts
Add-VMHost -Name "192.168.102.30" -Location site1 -User root -Password "Password!234" -Force
Add-VMHost -Name "192.168.102.31" -Location site1 -User root -Password "Password!234" -Force
Add-VMHost -Name "192.168.102.32" -Location site1 -User root -Password "Password!234" -Force


#add licenses
#get-vmhost -name * -location site1 | set-vmhost -LicenseKey 00000-00000-00000-00000-00000

#setHA on cluster
set-cluster -Cluster "site1" -HAEnabled:$true -Confirm:$false

#move VM to shared storage
move-vm -vm 'testvm' -Datastore 'sharedstorage'

#power on VM
start-vm -vm 'testvm'