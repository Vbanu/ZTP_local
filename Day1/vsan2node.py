import argparse
import atexit
import json
import os
import ssl
import sys

from log_file_gen import *

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "library"))
import VMware.vsanapiutils as vsanapiutils
import VMware.vsanmgmtObjects as vsanmgmtObjects
from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim
from termcolor import cprint

#
# Get the json file from the argument pass and set it up to be used
#
parser = argparse.ArgumentParser()

parser.add_argument('jsonFile')
parser.add_argument('--debug', 
                    default=True)
parser.add_argument('--allFlash', 
                    default=True)
#Change the Default when we get the production design done.
parser.add_argument('--vSANvmk', 
                    default="vmk1")
parser.add_argument('--preferdomain', 
                    default="fd1")
parser.add_argument('--seconddomain', 
                    default="fd2")
          
args = parser.parse_args()

with open(args.jsonFile) as datafile:
    data = json.load(datafile)

debug = args.debug
vmknic = args.vSANvmk
preferdomain = args.preferdomain
seconddomain = args.seconddomain

Witness = data['Witness']
witnesshost = Witness['IP']
witnesshostuser = Witness['username']
witnesshostpwd = Witness['password']
witnessdc = Witness['DCName']

vCenter = data['vCenter']
Ded_ID=data["DEDID"]
store_id="ST "+data["StoreID"]
d={"Ded_ID":Ded_ID,"store_id":store_id}

def printGreen(x):
    cprint(x, 'green')

def printRed(x):
    cprint(x, 'red')

#
# Get the cluster we need
#
def getClusterInstance(clusterName, serviceInstance):
    content = serviceInstance.RetrieveContent()
    searchIndex = content.searchIndex
    datacenters = content.rootFolder.childEntity
    # Look for the cluster in each datacenter attached to vCenter
    for datacenter in datacenters:
        cluster = searchIndex.FindChild(datacenter.hostFolder, clusterName)
        if cluster is not None:
            return cluster 
        else:
            continue

def yes(ques) :
   "Force the user to answer 'yes' or 'no' or something similar. Yes returns true"
   while 1 :
      ans = input(ques)
      ans = str.lower(ans[0:1])
      return True if ans == 'y' else False

def CollectMultiple(content, objects, parameters, handleNotFound=True):
   if len(objects) == 0:
      return {}
   result = None
   pc = content.propertyCollector
   propSet = [vim.PropertySpec(
      type=objects[0].__class__,
      pathSet=parameters
   )]

   while result == None and len(objects) > 0:
      try:
         objectSet = []
         for obj in objects:
            objectSet.append(vim.ObjectSpec(obj=obj))
         specSet = [vim.PropertyFilterSpec(objectSet=objectSet, propSet=propSet)]
         result = pc.RetrieveProperties(specSet=specSet)
      except vim.ManagedObjectNotFound as ex:
         objects.remove(ex.obj)
         result = None

   out = {}
   for x in result:
      out[x.obj] = {}
      for y in x.propSet:
         out[x.obj][y.name] = y.val
   return out


def sizeof_fmt(num, suffix='B'):
   for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
      if abs(num) < 1024.0:
         return "%3.1f%s%s" % (num, unit, suffix)
      num /= 1024.0
   return "%.1f%s%s" % (num, 'Yi', suffix)

def getHostSystem(hostname, dcRef, si):
   searchIndex = si.content.searchIndex
   hostSystem = searchIndex.FindByIp(datacenter = dcRef, ip = hostname, vmSearch = False) or \
                searchIndex.FindByDnsName(datacenter = dcRef, dnsName = hostname, vmSearch = False)
   return hostSystem

def AddHost(host, user='root', pwd=None, dcRef=None, si=None, sslThumbprint=None, port=443):
   '''
   Add a host to a data center
   Returns a host system
   '''

   cnxSpec = vim.HostConnectSpec(
           force=True,
           hostName=host,
           port=port,
           userName=user,
           password=pwd,
           vmFolder=dcRef.vmFolder
   )

   if sslThumbprint:
      cnxSpec.sslThumbprint = sslThumbprint

   hostParent = dcRef.hostFolder

   try:
      task = hostParent.AddStandaloneHost(addConnected = True, spec = cnxSpec)
      vsanapiutils.WaitForTasks([task], si)
      return getHostSystem(host, dcRef, si)
   except vim.SSLVerifyFault as e:
      #By catching this exception, user doesn't need input the host's thumbprint of the SSL certificate, the logic below
      #will do this automaticlly
      cnxSpec.sslThumbprint = e.thumbprint
      task = hostParent.AddStandaloneHost(addConnected = True, spec = cnxSpec)
      vsanapiutils.WaitForTasks([task], si)
      return getHostSystem(host, dcRef, si)
   except vim.DuplicateName as e:
      raise Exception("AddHost: ESX host %s has already been added to VC." % host)


if sys.version_info[:3] > (2, 7, 8):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

#
# Connect to vCenter Server
#
si = SmartConnect(
    host=vCenter['IP']  ,
    user=vCenter['username']  ,
    pwd=vCenter['password']  ,
    port=int(443),
    sslContext=context)

#print (si.content)
logger.info(si.content,extra=d)

if si and debug:
    #print ("Connected to vCenter")
    logger.info("Connected to vCenter",extra=d)

#
# This will automatically Disconnect from vCenter upon any exit scenario
#
atexit.register(Disconnect, si)

#
# Find the the cluster
#
cluster = getClusterInstance(vCenter['clusterName'], si)
if not cluster:
        logger.exception('The required cluster not found in inventory, validate input.',extra=d)
        exit()
if debug:
    logger.info(cluster,extra=d)

#
# The cluster needs to be licensed for vSAN, so we will do that first if defined in the XML file.
# If it is not there, that means there is already a license installed and waiting to be assigned.
#

#if vCenter['vSANLicense']:
#    print('Assigning vSAN License')
#    lm = si.content.licenseManager
#    lam = lm.licenseAssignmentManager
#    lam.UpdateAssignedLicense(
#        entity=cluster._moId,
#        licenseKey=vCenter['vSANLicense']
#    )

vcMos = vsanapiutils.GetVsanVcMos(si._stub, context=context)
vsanClusterSystem = vcMos['vsan-cluster-config-system']
vsanVcDiskManagementSystem = vcMos['vsan-disk-management-system']

#
# Based on the user input, determine if this is an all-flash or hybrid cluster+
#
isallFlash = args.allFlash
logger.info('Enable VSAN with {} mode'.format('all flash' if isallFlash else 'hybrid'),extra=d)

#
# Get the needed info from all the hosts in the cluster
#
hostProps = CollectMultiple(si.content, cluster.host,
                                ['name', 'configManager.vsanSystem', 'configManager.storageSystem'])
hosts = hostProps.keys()

# XXX TODO - Below scanerio might occur due to partially valid vSAN configuraiuons or failed vSAN confgurations.
# Better option is to manually delete vSAN and release all drives. We need to document these steps as Reset Steps for field engneer to get vSAN 
# Zero State safely.
# Steps to get vSAN to ZERO state -
# 1. ssh to ESXi host and do: esxcli vsan cluster leave
# 2. check the output of: esxcli vsan storage list and get the “VSAN Disk Group UUID”
# 3. continue with: esxcli vsan storage remove -u <uuid from command above>
# 4. Repeat on the second and third node 
# 5. From vCenter UI select vSAN Cluster Cluster->Configure->vSAN-->Services "turn off vSAN" 
# ---------------------------
# Find any InUse disks and wipe them to make them eligable. 
# Understanding is primarily there are 3 states - 'eligible', 'ineligible' and, 'InUse'. NS204i boot drives falls in 'ineligible' category. 
# depending on if it's a new disk are vSAN consumed states will change between 'ineligible' <-> 'InUse'  
#for host in hosts:
#     disks = [result.disk for result in
#             hostProps[host]['configManager.vsanSystem'].QueryDisksForVsan() if result.state == 'InUse']
#     print ('Found InUse disks {} in host {}'.format([disk.displayName for disk in disks], hostProps[host]['name']))
#     # If there is existing data on the drives, they will be wiped
#     for disk in disks:
#         if "NS204i" not in disk.displayName: 
#             print (disk)
#             if yes('Do you want to wipe disk {}?\nPlease Always check the partition table and the data stored'
#                 ' on those disks before doing any wipe! (yes/no)?'.format(disk.displayName)):
#                hostProps[host]['configManager.storageSystem'].UpdateDiskPartitions(disk.deviceName, vim.HostDiskPartitionSpec())

tasks = []
#
# Set the Multicast Adressing
#
configInfo = vim.VsanHostConfigInfo(
    networkInfo=vim.VsanHostConfigInfoNetworkInfo(
        port=[vim.VsanHostConfigInfoNetworkInfoPortConfig(
        device=vmknic,
        ipConfig=vim.VsanHostIpConfig(
            upstreamIpAddress='224.1.2.3',
            downstreamIpAddress='224.2.3.4'
        )
        )]
    )
)

for host in hosts:
    #print ('Enable VSAN trafic in host {} with {}'.format(hostProps[host]['name'], vmknic))
    logger.info('Enable VSAN trafic in host {} with {}'.format(hostProps[host]['name'], vmknic),extra=d)
    task = hostProps[host]['configManager.vsanSystem'].UpdateVsan_Task(configInfo)
    tasks.append(task)
vsanapiutils.WaitForTasks(tasks, si)
del tasks[:]

# Change the Virtual SAN configuration to claim disks manually
#print ('Enable VSAN by claiming disks manually')
logger.info('Enable VSAN by claiming disks manually',extra=d)
vsanReconfigSpec = vim.VimVsanReconfigSpec( modify=True,
    vsanClusterConfig=vim.VsanClusterConfigInfo( enabled=True,
        defaultConfig=vim.VsanClusterConfigInfoHostDefaultInfo(autoClaimStorage=False)
    )
)
# Enable dedupe and Compression if we are all flash
if isallFlash:
      #print('Enable deduplication and compression for VSAN. This could take several minutes...')
      logger.info('Enable deduplication and compression for VSAN. This could take several minutes...',extra=d)
      vsanReconfigSpec.dataEfficiencyConfig = vim.VsanDataEfficiencyConfig(
         compressionEnabled=True,
         dedupEnabled=True
      )

task = vsanClusterSystem.VsanClusterReconfig(cluster, vsanReconfigSpec)
vsanapiutils.WaitForTasks([task], si)

# Time to claim and mark disks for cache and capacity
diskmap = {host: {'cache':[],'capacity':[]} for host in hosts}
cacheDisks = []
capacityDisks = []

if isallFlash:
    #Get eligible ssd from host
    for host in hosts:
        ssds = [result.disk for result in hostProps[host]['configManager.vsanSystem'].QueryDisksForVsan() if
            result.state == 'eligible' and result.disk.ssd]
        #Assumption here is smaller disks are cache and the larger capacity.  If cache and
        # capacity are the same, we need to write how to handle that
        smallerSize = min([disk.capacity.block * disk.capacity.blockSize for disk in ssds])
        for ssd in ssds:
            size = ssd.capacity.block * ssd.capacity.blockSize
            if size == smallerSize:
                diskmap[host]['cache'].append(ssd)
                cacheDisks.append((ssd.displayName, sizeof_fmt(size), hostProps[host]['name']))
            else:
                diskmap[host]['capacity'].append(ssd)
                capacityDisks.append((ssd.displayName, sizeof_fmt(size), hostProps[host]['name']))
else:
    # Hybrid config.  SSD are Cache, HDD are capacity
    for host in hosts:
        disks = [result.disk for result in hostProps[host]['configManager.vsanSystem'].QueryDisksForVsan() if
            result.state == 'eligible']
        ssds = [disk for disk in disks if disk.ssd]
        hdds = [disk for disk in disks if not disk.ssd]

        for disk in ssds:
            diskmap[host]['cache'].append(disk)
            size = disk.capacity.block * disk.capacity.blockSize
            cacheDisks.append((disk.displayName, sizeof_fmt(size), hostProps[host]['name']))
        for disk in hdds:
            diskmap[host]['capacity'].append(disk)
            size = disk.capacity.block * disk.capacity.blockSize
            capacityDisks.append((disk.displayName, sizeof_fmt(size), hostProps[host]['name']))
#print out to console what we did
if debug:
    logger.info('Claim these disks to cache disks',extra=d)
    for disk in cacheDisks:
        logger.info('Name:{}, Size:{}, Host:{}'.format(disk[0], disk[1], disk[2]),extra=d)


    logger.info('Claim these disks to capacity disks',extra=d)
    for disk in capacityDisks:
        logger.info('Name:{}, Size:{}, Host:{}'.format(disk[0], disk[1], disk[2]),extra=d)

#Now, put the drive configuration into the  spec
for host,disks in diskmap.items():
    if disks['cache'] and disks['capacity']:
        dm = vim.VimVsanHostDiskMappingCreationSpec(
            cacheDisks=disks['cache'],
            capacityDisks=disks['capacity'],
            creationType='allFlash' if isallFlash else 'hybrid',
            host=host
        )

        task = vsanVcDiskManagementSystem.InitializeDiskMappings(dm)
        tasks.append(task)


logger.info('Wait for create disk group tasks finish',extra=d)
vsanapiutils.WaitForTasks(tasks, si)
del tasks[:]

# print to console the disk group configuration
if debug:
    #print ('Display disk groups in each host')
    logger.info('Display disk groups in each host',extra=d)
    for host in hosts:
        diskMaps = vsanVcDiskManagementSystem.QueryDiskMappings(host)

        for index, diskMap in enumerate(diskMaps, 1):
            #print ('Host:{}, DiskGroup:{}, Cache Disks:{}, Capacity Disks:{}'.format(hostProps[host]['name'], index,
                                                                                    #diskMap.mapping.ssd.displayName,
                                                                                    #[disk.displayName for disk in
                                                                                    #diskMap.mapping.nonSsd]))
                                                                                    
            logger.info('Host:{}, DiskGroup:{}, Cache Disks:{}, Capacity Disks:{}'.format(hostProps[host]['name'], index,diskMap.mapping.ssd.displayName,[disk.displayName for disk in diskMap.mapping.nonSsd]),extra=d)                                                                         


#Adding witness code starts here...
vcMos = vsanapiutils.GetVsanVcMos(si._stub, context = context)
vsanScSystem = vcMos['vsan-stretched-cluster-system']
searchIndex = si.content.searchIndex

#print ('Start to add physical witness host')
dcRef = searchIndex.FindChild(entity = si.content.rootFolder, name = witnessdc)
#witnessHost = AddHost(witnesshost, user=witnesshostuser ,pwd=witnesshostpwd, dcRef=dcRef, si=si)
witnessHost = getHostSystem(witnesshost, dcRef, si)
disks = []

disks = [result.disk for result in witnessHost.configManager.vsanSystem.QueryDisksForVsan() if
        result.state == 'eligible']
diskMapping = None

if disks:
  #witness host need at lease one disk group, For non-witness-OVF, please make sure there are enough
  #eligible disks. For witness host which created from witness ovf, there is no such worry.
  ssds = [disk for disk in disks if disk.ssd]
  nonSsds = [disk for disk in disks if not disk.ssd]
  #host with hybrid disks
  if len(ssds) > 0 and len(nonSsds) > 0:
     diskMapping = vim.VsanHostDiskMapping(
        ssd = ssds[0],
        nonSsd = nonSsds
     )
  #host with all-flash disks,choose the ssd with smaller capacity for cache layer.
  if len(ssds) > 0 and len(nonSsds) == 0:
     smallerSize = min([disk.capacity.block * disk.capacity.blockSize for disk in ssds])
     smallSsds = []
     biggerSsds = []
     for ssd in ssds:
        size = ssd.capacity.block * ssd.capacity.blockSize
        if size == smallerSize:
           smallSsds.append(ssd)
        else:           biggerSsds.append(ssd)
     diskMapping = vim.VsanHostDiskMapping(
        ssd = smallSsds[0],
        nonSsd = biggerSsds
     )

preferedFd = preferdomain
secondaryFd = seconddomain

firstFdHosts = []
secondFdHosts = []
for host in hosts:
  firstFdHosts.append(host)
  break
for host in set(hosts) - set(firstFdHosts):
  secondFdHosts.append(host)

faultDomainConfig = vim.VimClusterVSANStretchedClusterFaultDomainConfig(
  firstFdHosts = firstFdHosts,
  firstFdName = preferedFd,
  secondFdHosts = secondFdHosts,
  secondFdName = secondaryFd
)

logger.info('start to create stretched cluster',extra=d)
task = vsanScSystem.VSANVcConvertToStretchedCluster(cluster=cluster, faultDomainConfig=faultDomainConfig,
                                                      witnessHost=witnessHost, preferredFd=preferedFd,
                                                      diskMapping=diskMapping)
vsanapiutils.WaitForTasks([task], si)

#
# Enable Performance service
#
#print ('Enable perf service on this cluster')
logger.info('Enable perf service on this cluster',extra=d)

vsanPerfSystem = vcMos['vsan-performance-manager']
task = vsanPerfSystem.CreateStatsObjectTask(cluster)
vsanapiutils.WaitForTasks([task], si)
