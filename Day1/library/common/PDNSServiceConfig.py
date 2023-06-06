'''
DISCLAIMER OF WARRANTY
This document may contain the following HPE or other software: XML, CLI
statements, scripts, parameter files. These are provided as a courtesy, free of
charge, AS-IS by Hewlett Packard Enterprise, L.P. (HPE). HPE shall have no
obligation to maintain or support this software. HPE MAKES NO EXPRESS OR
IMPLIED WARRANTY OF ANY KIND REGARDING THIS SOFTWARE INCLUDING ANY WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE OR NON-INFRINGEMENT.
HPE SHALL NOT BE LIABLE FOR ANY DIRECT, INDIRECT, SPECIAL, INCIDENTAL OR
CONSEQUENTIAL DAMAGES, WHETHER BASED ON CONTRACT, TORT OR ANY OTHER LEGAL
THEORY,IN CONNECTION WITH OR ARISING OUT OF THE FURNISHING, PERFORMANCE OR USE
OF THIS SOFTWARE.(c) Copyright 2017 Hewlett Packard Enterprise, L.P. The
information contained herein is subject to change without notice. The only
warranties for HPE products and services are set forth in the express warranty
statements accompanying such products and services. Nothing herein should be
construed as constituting an additional warranty. HPE shall not be liable for
technical or editorial errors or omissions contained herein.
'''

import localModules
import SSHPython
import os
import sys
import time
import common
import json
from datetime import date
import tempfile
import shutil
import random
from Common_Python import reportIntro, reportRow, gatewayConstants
import requests
import logging

from python_logger import logger_fle_lvl
logger_fle_lvl('info')

gwCon = gatewayConstants()
mgmtServerMgmtPurpose = gwCon.mgmtServerMgmtPurpose
iloMgmtPurpose = gwCon.iloMgmtPurpose
netSwitchMgmtPurpose = gwCon.netSwitchMgmtPurpose
pduMgmtPurpose = gwCon.pduMgmtPurpose

nfs_share = "/srv/nfs/default_HA-1"
map =[]

def addRack2PArubaSwitchDetails(scid, node, tags):
    """ 
    Function to create Forward Lookup Zone Records
    Currently will provide IP:HOSTNAME mapping for 
    1. Switches
    """
    string = ""
    resstring = ""
    for x in scid.getRack2PArubaNetworkSwitchHostNameIPDetail(purpose=netSwitchMgmtPurpose, keyname='hostName'):
        ptr_domain = get_ptr_zone(purpose=netSwitchMgmtPurpose, map_list=map)
        (hostname,ip) = x
        return_code = pushARecords(ip, hostname, scid, node, tags)
        if return_code == 204:
            string += f'{hostname}\t\tIN A {ip}\n'
            lst = ip.split(".")[::-1]
            ip = ".".join(lst[0:4])
            return_code = pushPTRRecord(ip, hostname, scid, node, tags, ptr_domain)
            if return_code == 204:
                resstring += f'{hostname}\t\tIN PTR {ip}\n'
            else:
                logging.info(f"{ptr_domain} doesn't exist.")
                return(2)
        else:
            logging.info(f"{tags['@@DOMAIN@@']} doesn't exist.")
            return(1)
            
    #logging.info("------------------------done for networkswitch-------------------------------")
    logging.info(string)
    logging.info(resstring)
    return(string.rstrip("\n"),0)

def addSlingshotSwitchDetails(scid, node, tags):
    """ 
    Function to create Forward Lookup Zone Records
    Currently will provide IP:HOSTNAME mapping for 
    1. Switches
    """
    string = ""
    resstring = ""
    for x in scid.getSlingshotNetworkSwitchHostNameIPDetail(purpose=netSwitchMgmtPurpose, keyname='hostName'):
        ptr_domain = get_ptr_zone(purpose=netSwitchMgmtPurpose, map_list=map)
        (hostname,ip,xname) = x
        return_code = pushARecords(ip, xname, scid, node, tags)
        if return_code == 204:
            return_code = pushCNAMERecords(xname, hostname, scid, node, tags)
            if return_code == 204:
                string += f'{xname}\t\tIN A {ip}\n'
                lst = ip.split(".")[::-1]
                ip = ".".join(lst[0:4])
                return_code = pushPTRRecord(ip, xname, scid, node, tags, ptr_domain)
                if return_code == 204:
                    resstring += f'{hostname}\t\tIN PTR {ip}\n'
                else:
                    logging.info(f"{ptr_domain} doesn't exist.")
                    return(2)
            else:
                logging.info(f"{tags['@@DOMAIN@@']} doesn't exist.")
                return(1) 
        else:
            logging.info(f"{tags['@@DOMAIN@@']} doesn't exist.")
            return(1)
    #logging.info("------------------------done for networkswitch-------------------------------")
    logging.info(string)
    logging.info(resstring)
    return(string.rstrip("\n"),0)

def addHostsDetails(scid, node, tags):
    """ 
    Function to create Forward Lookup Zone Records
    Currently will provide IP:HOSTNAME mapping for 
    1. All physical servers (3 Nodes)
    2. iLOs
    3. K3S Masters (3 VMs)
    4. switches
    5. VMs (OV,iLOamp)
    6. VMs (AFC)
    """
    string = ""
    resstring = ""
    for x in scid.getHostNameIPDetail(purpose=mgmtServerMgmtPurpose, keyname='hostName'):
        ptr_domain = get_ptr_zone(purpose=mgmtServerMgmtPurpose, map_list=map)
        (ip, hostname) = x
        return_code = pushARecords(ip, hostname, scid, node, tags)
        if return_code == 204:
            string += f'{hostname}\t\tIN A {ip}\n'
            lst = ip.split(".")[::-1]
            ip = ".".join(lst[0:4])
            return_code = pushPTRRecord(ip, hostname, scid, node, tags, ptr_domain)
            if return_code == 204:
                resstring += f'{hostname}\t\tIN PTR {ip}\n'
            else:
                logging.info("not able to add record")
                return(None,1)    
        else:
            return(None,1)
    #logging.info("-----------------done for msm list---------------------")
    for x in scid.getHostNameIPDetail(purpose=iloMgmtPurpose, keyname='iloHostName'):
        ptr_domain = get_ptr_zone(purpose=iloMgmtPurpose, map_list=map)
        (ip, hostname) = x
        return_code = pushARecords(ip, hostname, scid, node, tags)
        if return_code == 204:
            string += f'{hostname}\t\tIN A {ip}\n'
            lst = ip.split(".")[::-1]
            ip = ".".join(lst[0:4])
            return_code = pushPTRRecord(ip, hostname, scid, node, tags, ptr_domain)
            if return_code == 204:
                resstring += f'{hostname}\t\tIN PTR {ip}\n'
            else:
                return(None,1)    
        else:
            return(None,1)
    #logging.info("-----------------------------done for iLO-------------------------------")
    for x in scid.getPduDetails():
        ptr_domain = get_ptr_zone(purpose=pduMgmtPurpose, map_list=map)
        (ip, hostname) = x
        return_code = pushARecords(ip, hostname, scid, node, tags)
        if return_code == 204:
            string += f'{hostname}\t\tIN A {ip}\n'
            lst = ip.split(".")[::-1]
            ip = ".".join(lst[0:4])
            return_code = pushPTRRecord(ip, hostname, scid, node, tags, ptr_domain)
            if return_code == 204:
                resstring += f'{hostname}\t\tIN PTR {ip}\n'
            else:
                return(None,1)    
        else:
            return(None,1)  
    #logging.info("-----------------------done for PDUManagement------------------------------")  
    for x in scid.getNetworkSwitchHostNameIPDetail(purpose=netSwitchMgmtPurpose, keyname='hostName'):
        ptr_domain = get_ptr_zone(purpose=netSwitchMgmtPurpose, map_list=map)
        (ip, hostname) = x
        return_code = pushARecords(ip, hostname, scid, node, tags)
        if return_code == 204:
            string += f'{hostname}\t\tIN A {ip}\n'
            lst = ip.split(".")[::-1]
            ip = ".".join(lst[0:4])
            return_code = pushPTRRecord(ip, hostname, scid, node, tags, ptr_domain)
            if return_code == 204:
                resstring += f'{hostname}\t\tIN PTR {ip}\n'
            else:
                return(None,1)    
        else:
            return(None,1)
    #logging.info("------------------------done for networkswitch-------------------------------")
    vms = scid.getVMName()
    for vm in vms:
        (vm_hostname, vm_ip, vm_purpose) = vm
        return_code = pushARecords(vm_ip, vm_hostname, scid, node, tags)
        ptr_domain = get_ptr_zone(purpose=vm_purpose, map_list=map)
        if return_code == 204:
            string += f'{vm_hostname}\t\tIN A {vm_ip}\n'
            lst = vm_ip.split(".")[::-1]
            ip = ".".join(lst[0:4])
            return_code = pushPTRRecord(ip, vm_hostname, scid, node, tags, ptr_domain)
            if return_code == 204:
                resstring += f'{vm_hostname}\t\tIN PTR {ip}\n'
            else:
                return(None,1)    
        else:
            return(None,1)
    #logging.info("-------------done for vms------------------------------------")
    logging.info(string)
    logging.info(resstring)
    return(string.rstrip("\n"),0)

def validateDNSwithnslookup(node,record):
    """
    Validate DNS Service with NSLOOKUP
    Randomly choose the hostname:ip and validate nslookup provides right data
    """
    client, resultFlag = SSHPython.connect_host(node['ip'], node['user'], node['password'])
    lines = record.split('\n')
    (ip, hostname) = random.choice(lines).split("IN A")
    forwardlookupcmd = f"nslookup {ip.strip()} localhost"
    restart = "systemctl restart pdns pdns-recursor"
    status,output,error = SSHPython.execute_command(client, restart, exitCodeCheck=True)
    time.sleep(30)
    status,output,error = SSHPython.execute_command(client, forwardlookupcmd, exitCodeCheck=True)
    logging.info(output)
    if hostname.strip() in output:
        logging.info("nslookup with forwardlookup successful on ",client)
    else:
        logging.info("Check DNS Configurations Manually")
    if status == 'Pass':
        return True
    else:
        return False

'''def installPackage(client):
    cmd = f"zypper mr -e -a; zypper --non-interactive --quiet addrepo --refresh https://download.opensuse.org/repositories/home:paddg/SLE_15_SP2/home:paddg.repo"
    zypperinstallcmd = f"zypper -n --no-gpg-checks install -y pdns pdns-backend-sqlite3 sqlite3 pdns-recursor"
    status,output,error = SSHPython.execute_command(client, cmd, exitCodeCheck=True)
    status,output,error = SSHPython.execute_command(client, zypperinstallcmd, exitCodeCheck=True)
    if status == "Pass":
        return True
    else:
        logging.info("zypper refresh/zypper install failed")
        return False'''

def createfileAfterReplacementtags(tags, templateName):
    """
    Handles the following
    1. create tmpDir 
    2. copy the templates files 
    3. ReplaceTagsinFile and creates a working copy of file
    """
    dataDir = common.getCGDataDirectory()
    srcDir = os.path.join(dataDir, "pdns")

    # Temporary directory
    tempDir = tempfile.mktemp()
    # Copying configuration files to temporary directory
    shutil.copytree(srcDir, tempDir)
    common.ReplaceTagsInFile(tempDir, templateName, tags)
    return(tempDir)

def createFileCopyToRemoteHost(fpath, tags, client):
    """
    Function to copy the zoned files/named.conf to appropriate directory in the destinated VMs
    """
    src_dst = {"pdns.conf": "/etc/pdns/pdns.conf" ,
    "externaldnsdeployment.yaml": "/root/externaldnsdeployment.yaml" ,
    "externaldnsrbac.yaml": "/root/externaldnsrbac.yaml",
    "pdns_to_named": "/root/pdns_to_named.py",
    "recursor.conf": "/etc/recursor.conf"
    }
    if client:
        # logging.info(fpath)
        # fname = fpath.split("\\")[-1]
        # logging.info(fname)
        fname = os.path.basename(fpath)
        dst = src_dst[fname]
        response = SSHPython.upload_file(client, fpath, dst)
        shutil.rmtree(fpath.strip(fname))
        if response == "Pass":
            logging.info("Successfully copied to %s"%client)
            if ".yaml" in fname:
                cmd = "kubectl apply -f %s"%dst
                status,output,error = SSHPython.execute_command(client, cmd, exitCodeCheck=True)
                logging.info(output)
        else:
            logging.info("Upload failed to %s"%client)
    else:
        response = "Fail"
        logging.info("Connection to %s not successful"%client)
    return response

def stopStartPDNSService(client):
    """
    Stop and start the powerdns
    """
    stopcmd = "systemctl stop pdns pdns-recursor"
    enablecmd = "systemctl enable pdns pdns-recursor"
    startcmd = "systemctl start pdns pdns-recursor"
    reloadcmd = "systemctl daemon-reload"
    status,output,error = SSHPython.execute_command(client, reloadcmd, exitCodeCheck=True)
    time.sleep(10)
    status,output,error = SSHPython.execute_command(client, stopcmd, exitCodeCheck=True)
    time.sleep(10)
    status,output,error = SSHPython.execute_command(client, enablecmd, exitCodeCheck=True)
    time.sleep(10)
    status,output,error = SSHPython.execute_command(client, startcmd, exitCodeCheck=True)
    time.sleep(20)
    if status == "Pass":
        return True
    else:
        return False

def validatePDNSServiceStatus(client):
    """
    Validate the status of pdns.service(bind)
    """
    cmd = "systemctl status pdns"
    status,output,error = SSHPython.execute_command(client, cmd, exitCodeCheck=True)
    if "active (running)" in output and status == "Pass":
        return True
    else:
        return False

def validatePDNSRecursorStatus(client):
    """
    Validate the status of pdns-recoursor.service(bind)
    """
    cmd = "systemctl status pdns-recursor"
    status,output,error = SSHPython.execute_command(client, cmd, exitCodeCheck=True)
    if "active (running)" in output and status == "Pass":
        return True
    else:
        return False

def createMountFolder(nodes):
    retval = 0
    try:
        for node in nodes:
            client, resultFlag = SSHPython.connect_host(node['ip'], node['user'], node['password'])
            if resultFlag == "Pass":
                cmd = "showmount -e"
                status, output, error = SSHPython.execute_command(client, cmd, exitCodeCheck=True)
                if status == "Pass":
                    if "/srv/nfs/default_HA-1" in output:
                        logging.info("/srv/nfs/default_HA-1 is available")
                        cmd01 = "mkdir -p /srv/nfs/default_HA-1/powerdns"
                        status, output, error = SSHPython.execute_command(client, cmd01, exitCodeCheck=True)
                        if status == "Pass":
                            logging.info("Successfully created the powerdns directory")
                            retval = 0
                            break
                        else:
                            logging.info("Failed to create the powerdns directory")
                            retval = 1
                    else:
                        logging.info("/srv/nfs/default_HA-1 is not available")
                        retval = 1
                else:
                    logging.info("Failed to list Mount points ")
                    retval = 1
            else:
                logging.info("Failed to login to the node")
                retval = 1
    
    except Exception as e:
        logging.info("Error in createMountFoldre Error: %s" % e)
        retval = 1

    return retval

def createNFSMount(client, tags):
    NFSMount = common.MountNFSShare(client, tags["@@NFSSERVER@@"], 'default_HA-1', '/var/lib/powerdns/', 'powerdns')
    if NFSMount:
        logging.info("Appropriate mount point created")
        return(True)        
    else:
        logging.info("Appropriate mount point could not be created")
        return(False)

def GenerateTagReplacementDict(scid, node):

    primaryDNS = scid.getSolutionPrimaryDNS()
    secondaryDNS = scid.getSolutionSecondaryDNS()
    domain = scid.getSolutionSearchDomainName()
    pdns_hostip = node['ip']
    subnet = scid.getNetworkId("OS and Infrastructure Management Network")
    logging.info(subnet)
    netmask = scid.getNetworkMask("OS and Infrastructure Management Network")
    logging.info(netmask)

    tags = {
        "@@DOMAIN@@": domain,
        "@@PDNSHOSTIP@@": pdns_hostip,
        "@@NODEIP@@": node['ip'],
        "@@PRIMARYDNS@@": primaryDNS,
        "@@SECONDARYDNS@@": secondaryDNS,
        "@@PTRDOMAINLINES@@": getPTRlines(scid,node['ip'])
    }
    
    return tags

def getPTRlines(scid,node_ip):
    ptr_string = ''
    ptr_string = ptr_string+"allow-from=0.0.0.0/0\n"
    nw_name_list = scid.getNetworkName()
    created_zone=[]
    for network in nw_name_list:
        jsonpath = scid.getNetworkDetailsByComponentId(network)
        if 'networkId' in jsonpath.keys():
            logging.info(network)
            ptr_zone = ptr_zones(jsonpath['networkId'], jsonpath['networkMask'])
            logging.info(ptr_zone)
            if ptr_zone in created_zone:
                continue
            ptr_string = ptr_string+"forward-zones+="+ptr_zone+"="+node_ip+":5300\n"
            logging.info(ptr_string)
            created_zone.append(ptr_zone)
        else:
            logging.info("Not able to get the ptr_zones")
    return ptr_string

def configureSqliteDB(client, tags):
    """
    Execute the following commands 
    mkdir -p /var/lib/powerdns 
    sqlite3 /var/lib/powerdns/pdns.sqlite3 < /usr/share/doc/packages/pdns/schema.sqlite3.sql 
    chown -R pdns:pdns /var/lib/powerdns
    """
    cmd = f"mkdir -p /var/lib/powerdns"
    sqlitecmd = f"/usr/bin/sqlite3 /var/lib/powerdns/pdns.sqlite3 < /usr/share/doc/packages/pdns/schema.sqlite3.sql"
    chowncmd = f"chown -R pdns:pdns /var/lib/powerdns"
    status,output,error = SSHPython.execute_command(client, cmd, exitCodeCheck=True)
    mountStatus = createNFSMount(client, tags)
    if mountStatus:
        status,output,error = SSHPython.execute_command(client, sqlitecmd, exitCodeCheck=True)
        time.sleep(10)
        status,output,error = SSHPython.execute_command(client, chowncmd, exitCodeCheck=True)
        time.sleep(10)
        if status == "Pass":
            return(True)
        else:
            return(False)    
    else:
        return(False)
     
def configureMasterPDNSService(scid, node, reportfp):
    """
    Configure Master Power DNS Service on DRBD Cluster 1 - Node 1 
    1. Configure the sqlite database tables 
    2. Configure PDNS conf file 
    3. Start PDNS Service
    4. Validate if PDNS is working 
    """
    client, resultFlag = SSHPython.connect_host(node['ip'], node['user'], node['password'])
    #packageInstallStatus = installPackage(client)
    tags = GenerateTagReplacementDict(scid, node)
    status = configureSqliteDB(client, tags)
    if status:
        logging.info("Configuring SQLite database on %s"%node['ip'])
        reportRow(reportfp, "Sqlite Database Configuration", "Pass", "SQLite Database Configuration Complete")
        #tags = GenerateTagReplacementDict(scid, node)
        tempDir = createfileAfterReplacementtags(tags, "pdns.conf")
        logging.info("Creating pdns.conf and copying to %s"%node['ip'])
        response = createFileCopyToRemoteHost(os.path.join(tempDir, "pdns.conf"), tags, client)
        tempDir = createfileAfterReplacementtags(tags, "recursor.conf")
        logging.info("Creating recursor.conf and copying to %s"%node['ip'])
        response1 = createFileCopyToRemoteHost(os.path.join(tempDir, "recursor.conf"), tags, client)
        if response == "Pass" and response1 == "Pass":
            response = stopStartPDNSService(client)
            if(validatePDNSServiceStatus(client) and validatePDNSRecursorStatus(client)):
                logging.info("PDNS  and PDNS-Recursor successfully running on %s"%node['ip'])
                reportRow(reportfp, "Power DNS Configuration", "Pass", "PDNS Service is successfully running")
                return (True, tags)
            else:
                logging.info("PDNS or Recursor not running properlly, Please check")
                return (False, tags)
        else:
            logging.info("Pdns.conf or recursor.conf file was not copied to target. Check the SSH connection")
            return (False, tags)
    else:
        logging.info("SQLite config DB failed")
        return (False, tags)

def ExternalDNSServiceSetUp(scid, master, tags, reportfp):
    """
    Configure External DNS Service
    Kubectl apply deployment and rbac yaml files to master k3s nodes
    """
    client, resultFlag = SSHPython.connect_host(master['host'], master['user'], master['password'])
    tempDir = createfileAfterReplacementtags(tags, "externaldnsrbac.yaml")
    logging.info("Creating rbac.yaml and applying to %s"%master['host'])
    resp1 = createFileCopyToRemoteHost(os.path.join(tempDir, "externaldnsrbac.yaml"), tags, client)
    tempDir = createfileAfterReplacementtags(tags, "externaldnsdeployment.yaml")
    logging.info("Creating deployment.yaml and applying to %s"%master['host'])
    resp2 = createFileCopyToRemoteHost(os.path.join(tempDir, "externaldnsdeployment.yaml"), tags, client)
    if resp1 == "Pass" and resp2 == "Pass":
        logging.info("ExternalDNS is successfully running on %s"%master['host'])
        reportRow(reportfp, "ExternalDNS Configuration", "Pass", "ExternalDNS is successfully running")
        return (True)
    else:
        logging.info("ExternalDNS is not running on %s"%master['host'])
        reportRow(reportfp, "ExternalDNS Configuration", "Fail", "ExternalDNS is not running. Please check")
        return (False)

def getzonedetails(scid, node, tags):
    """
    Performs the below CURL command using python requests module
     curl -v -H 'X-API-Key: pdns'  http://172.28.2.1:11052/api/v1/servers/localhost/zones/cgw.hpe.net
    """
    client, resultFlag = SSHPython.connect_host(node['ip'], node['user'], node['password'])
    if scid.getSolutionHttpProxy() and scid.getSolutionHttpsProxy():
        proxies = {
        'http': scid.getSolutionHttpProxy(),
        'https': scid.getSolutionHttpsProxy(),
        }
    else:
        proxies = None
        logging.info("No HTTP Proxy details provided going with no-proxy")
    
    noproxy = {
        "http": None,
        "https": None,
        }
    try:
        tokenheaders = {'X-API-Key':  'pdns',}
        url= "http://%s:11052/api/v1/servers/localhost/zones"%(tags["@@PDNSHOSTIP@@"])
        logging.info("Accessing PDNS WebServer using requests model %s"%tags["@@PDNSHOSTIP@@"])
        logging.info(url)
        res = requests.get(url, verify=False, headers=tokenheaders, proxies=noproxy, timeout=300)
        logging.info(res.text)
        return(res.status_code, res.text)
    except Exception as exc:
        logging.info(exc)
        logging.info("Error getting bearer token without proxy , Retrying with proxy")
        try:
            res = requests.get(url, verify=False, headers=tokenheaders, proxies=proxies, timeout=300)
            logging.info(res.text)
            return(res.status_code, res.text)
        except Exception as exc:
            logging.info(exc)
            logging.info("Error getting bearer token with proxy as well")
            return(1, None)

def createZone(scid, node, tags):
    """
    Performs the below CURL command using python requests module
     curl -v -H 'X-API-Key: pdns'  http://172.28.2.1:11052/api/v1/servers/localhost/zones/cgw.hpe.net
    """
    client, resultFlag = SSHPython.connect_host(node['ip'], node['user'], node['password'])
    if scid.getSolutionHttpProxy() and scid.getSolutionHttpsProxy():
        proxies = {
        'http': scid.getSolutionHttpProxy(),
        'https': scid.getSolutionHttpsProxy(),
        }
    else:
        proxies = None
        logging.info("No proper Http Proxy details provided")
    
    noproxy = {
        "http": None,
        "https": None,
        }
    try:
        tokenheaders = {'X-API-Key':  'pdns',}
        url= "http://%s:11052/api/v1/servers/localhost/zones"%(tags["@@PDNSHOSTIP@@"])
        data =  '{"name":"%s.", "kind": "Master","masters": []}'%tags["@@DOMAIN@@"]
        #logging.info("Creating a new domain/zone in PDNS %s"%tags["@@PDNSHOSTIP@@"])
        logging.info(url)
        res = requests.post(url, verify=False, data=data, headers=tokenheaders, proxies=noproxy, timeout=300)
        logging.info(res.status_code)
        return(res.status_code)
    except Exception as exc:
        logging.info(exc)
        logging.info("Error getting bearer token without proxy , Retrying with proxy")
        try:
            tokenheaders = {'X-API-Key':  'pdns',}
            url= "http://%s:11052/api/v1/servers/localhost/zones"%(tags["@@PDNSHOSTIP@@"])
            data =  '{"name":"%s.", "kind": "Master","masters": []}'%tags["@@DOMAIN@@"]
            logging.info("Creating a new domain/zone in PDNS %s"%tags["@@PDNSHOSTIP@@"])
            logging.info(url)
            res = requests.post(url, verify=False, data=data, headers=tokenheaders, proxies=proxies, timeout=300)
            logging.info(res.status_code)
            return(res.status_code)
        except Exception as exc:
            logging.info(exc)
            logging.info("Error getting bearer token with proxy as well")
            return(1)

def createPTRZone(scid, node, ptr_domain, tags):
    """
    Performs the below CURL command using python requests module
     curl -v -H 'X-API-Key: pdns'  http://172.28.2.1:11052/api/v1/servers/localhost/zones/cgw.hpe.net
    """
    client, resultFlag = SSHPython.connect_host(node['ip'], node['user'], node['password'])
    if scid.getSolutionHttpProxy() and scid.getSolutionHttpsProxy():
        proxies = {
        'http': scid.getSolutionHttpProxy(),
        'https': scid.getSolutionHttpsProxy(),
        }
    else:
        proxies = None
        logging.info("No proper Http Proxy details provided")
    
    noproxy = {
        "http": None,
        "https": None,
        }
    try:
        tokenheaders = {'X-API-Key':  'pdns',}
        url= "http://%s:11052/api/v1/servers/localhost/zones"%(tags["@@PDNSHOSTIP@@"])
        data =  '{"name":"%s.", "kind": "Master","masters": []}'%ptr_domain
        logging.info("Creating reverse domain/zone in PDNS %s"%tags["@@PDNSHOSTIP@@"])
        logging.info(url)
        res = requests.post(url, verify=False, data=data, headers=tokenheaders, proxies=noproxy, timeout=300)
        return(res.status_code)
    except Exception as exc:
        logging.info(exc)
        logging.info("Error getting bearer token without proxy , Retrying with proxy")
        try:
            tokenheaders = {'X-API-Key':  'pdns',}
            url= "http://%s:11052/api/v1/servers/localhost/zones"%(tags["@@PDNSHOSTIP@@"])
            data =  '{"name":"%s.", "kind": "Master","masters": []}'%ptr_domain
            logging.info("Creating reverse domain/zone in PDNS %s"%tags["@@PDNSHOSTIP@@"])
            logging.info(url)
            res = requests.post(url, verify=False, data=data, headers=tokenheaders, proxies=proxies, timeout=300)
            return(res.status_code)
        except Exception as exc:
            logging.info(exc)
            logging.info("Error getting bearer token with proxy as well")
            return(1)

def ptr_zones(gw_ip: str, mask: str):
    try:
        import ipaddress
        ipBin = ''.join([bin(int(x) + 256)[3:] for x in gw_ip.split('.')])
        maskBin = ''.join([bin(int(x) + 256)[3:] for x in mask.split('.')])
        gwBin = ''.join(chr(ord(a) & ord(b)) for a, b in zip(ipBin, maskBin))
        calcGW = '.'.join([str(int(gwBin[0:8], 2)), str(int(gwBin[8:16], 2)), str(
            int(gwBin[16:24], 2)), str(int(gwBin[24:32], 2))])
        ipnetwork = calcGW + "/" + mask
        GW = str(ipaddress.ip_network(ipnetwork)).split("/")[0]
        mask = str(ipaddress.ip_network(ipnetwork)).split("/")[-1]
        reverseLookup=""
        if int(mask) >= 24:
            logging.info("Mask greater than or qual to 24")
            reverseLookup='.'.join((GW.split('.')[::-1])[1:])
        elif int(mask) >=16 and int(mask) < 24:
            logging.info("Mask in between 16 and 24")
            reverseLookup='.'.join((GW.split('.')[::-1])[2:])
        else:
            logging.info("Mask than or qual to 16")
            reverseLookup='.'.join((GW.split('.')[::-1])[3:])
        return str(reverseLookup+".in-addr.arpa")
    except Exception:
        logging.info("exception")
        return ""   

def get_ptr_zone(purpose, map_list):
    for i in map_list:
        if purpose in i['purpose_list']:
            return(i['domain_id'])
        else:
            pass

def ValidateZone(scid, node, tags):

    nw_name_list = scid.getNetworkName()
    logging.info(nw_name_list)
    for network in nw_name_list:
        jsonpath = scid.getNetworkDetailsByComponentId(network)
        if 'networkId' in jsonpath.keys():
            logging.info(network)
            map.append({'domain_id': ptr_zones(jsonpath['networkId'], jsonpath['networkMask']), 'purpose_list': jsonpath['purposeList']})
            logging.info(map)
            ptr_zone = ptr_zones(jsonpath['networkId'], jsonpath['networkMask'])
            logging.info(ptr_zone + " created")
        else:
            logging.info("The network is not a working Network: "+network)
    status, resp= getzonedetails(scid, node, tags)
    if status == 200:
        logging.info(resp)
        if tags["@@DOMAIN@@"] in resp:
            logging.info("Domain created successfully in PDNS")
            return True
        else:
            return False
    else:
        logging.info("Check the get zone details")
        return False   

def createValidateZone(scid, node, tags, reportfp):
    status = createZone(scid, node, tags)
    if status == 201:
        status, resp= getzonedetails(scid, node, tags)
        if status == 200:
            logging.info(resp)
            if tags["@@DOMAIN@@"] in resp:
                reportRow(reportfp, "Create Domain in PDNS", "Pass", "Domain created successfully in PDNS")
            else:
                reportRow(reportfp, "Create Domain in PDNS", "Fail", "Domain not created successfully in PDNS")
                return False
        else:
            logging.info("Check the get zone details")
            return False
    else:
        logging.info("Check the create zone details")
        return False
    nw_name_list = scid.getNetworkName()
    logging.info(nw_name_list)
    for network in nw_name_list:
        jsonpath = scid.getNetworkDetailsByComponentId(network)
        if 'networkId' in jsonpath.keys():
            map.append({'domain_id': ptr_zones(jsonpath['networkId'], jsonpath['networkMask']), 'porpose_list': jsonpath['purposeList']})
            logging.info("This is the maping of networks \n")
            logging.info(map)
            ptr_zone = ptr_zones(jsonpath['networkId'], jsonpath['networkMask'])
            status = createPTRZone(scid, node, ptr_zone, tags)
            if status == 201:
                logging.info(ptr_zone + "created")
            else:
                reportRow(reportfp, "Create Domain in PDNS", "Failed", "Domain not created successfully in PDNS")
                logging.info("Check the create zone details")
                return False
        else:
            logging.info("The network is not a working Network:"+network)
    status, resp= getzonedetails(scid, node, tags)
    if status == 200:
        logging.info(resp)
        if tags["@@DOMAIN@@"] in resp:
            reportRow(reportfp, "Create Domain in PDNS", "Pass", "Domain created successfully in PDNS")
            return True
        else:
            reportRow(reportfp, "Create Domain in PDNS", "Fail", "Domain not created successfully in PDNS")
            return False
    else:
        logging.info("Check the get zone details")
        return False    

def pushARecords(ip, hostname, scid, node, tags):
    '''
    curl -X PATCH --data '{"rrsets": [ {"name": "ap3-iloamp.cgw.hpe.net.", "type": "A", "ttl": 86400, "changetype": "REPLACE", "records": [ {"content": "172.28.7.30", "disabled": false } ] } ] }' 
    -H 'X-API-Key: pdns' http://127.0.0.1:11052/api/v1/servers/localhost/zones/cgw.hpe.net.
    '''
    logging.info(ip, hostname)
    try: 
        client, resultFlag = SSHPython.connect_host(node['ip'], node['user'], node['password'])
        if resultFlag == "Fail":
            raise Exception("Failed to establish SSH connection.")
    
    except Exception as e:
        logging.info("Error: Establishing a SSH connection to host IP: %s. %s"% (node['ip'], e))
        return(1) 

    if scid.getSolutionHttpProxy() and scid.getSolutionHttpsProxy():
        proxies = {
        'http': scid.getSolutionHttpProxy(),
        'https': scid.getSolutionHttpsProxy(),
        }
    else:
        proxies = None
        logging.info("No proper Http Proxy details provided")
    
    noproxy = {
        "http": None,
        "https": None,
        }
    try:
        tokenheaders = {'X-API-Key':  'pdns',}
        url= "http://%s:11052/api/v1/servers/localhost/zones/%s."%(tags["@@PDNSHOSTIP@@"],tags["@@DOMAIN@@"])
        logging.info(url)
        record = hostname+'.'+tags["@@DOMAIN@@"]+'.'
        data =  '{"rrsets": [ {"name": \"%s\", "type": "A", "ttl": 86400, "changetype": "REPLACE", "records": [ {"content": \"%s\", "disabled": false } ] } ] }'%(record,ip)
        logging.info("Creating DNS record %s"%(data))
        logging.info("Adding a new record for %s with IP %s"%(record, ip))

        res = requests.patch(url, verify=False, data=data, headers=tokenheaders, proxies=noproxy, timeout=300)
        if res.status_code == 404:
            logging.info("""Error: Requested zone "%s" was not found. Status code: %s"""%(tags["@@DOMAIN@@"],res.status_code))
        elif res.status_code == 204:
            logging.info("Successful creating A record. Status code: %s" %res.status_code)
        else:
            logging.info("Failed to create A record. Status code: %s" %res.status_code)
        return(res.status_code)
    except Exception as exc:
        logging.info(exc)
        logging.info("Error getting bearer token without proxy , Retrying with proxy.")
        try:
            res = requests.patch(url, verify=False, data=data, headers=tokenheaders, proxies=proxies, timeout=300)
            return(res.status_code)
        except Exception as exc:
            logging.info(exc)
            logging.info("Error getting bearer token with proxy as well.")
            return(1)

def pushCNAMERecords(hostname1, hostname2, scid, node, tags):
    '''
    curl -X PATCH --data '{"rrsets": [ {"name": "ap3-iloamp.cgw.hpe.net.", "type": "A", "ttl": 86400, "changetype": "REPLACE", "records": [ {"content": "172.28.7.30", "disabled": false } ] } ] }' 
    -H 'X-API-Key: pdns' http://127.0.0.1:11052/api/v1/servers/localhost/zones/cgw.hpe.net.
    '''
    logging.info(hostname1, hostname2)
    try: 
        client, resultFlag = SSHPython.connect_host(node['ip'], node['user'], node['password'])
        if resultFlag == "Fail":
            raise Exception("Failed to establish SSH connection.")
    
    except Exception as e:
        logging.info("Error: Establishing a SSH connection to host IP: %s. %s"% (node['ip'], e))
        return(1) 

    if scid.getSolutionHttpProxy() and scid.getSolutionHttpsProxy():
        proxies = {
        'http': scid.getSolutionHttpProxy(),
        'https': scid.getSolutionHttpsProxy(),
        }
    else:
        proxies = None
        logging.info("No proper Http Proxy details provided")
    
    noproxy = {
        "http": None,
        "https": None,
        }
    try:
        tokenheaders = {'X-API-Key':  'pdns',}
        url= "http://%s:11052/api/v1/servers/localhost/zones/%s."%(tags["@@PDNSHOSTIP@@"],tags["@@DOMAIN@@"])
        logging.info(url)
        record = hostname2+'.'+tags["@@DOMAIN@@"]+'.'
        logging.info(record)
        record2 = hostname1+'.'+tags["@@DOMAIN@@"]+'.'
        logging.info(record2)
        data =  '{"rrsets": [ {"name": \"%s\", "type": "CNAME", "ttl": 86400, "changetype": "REPLACE", "records": [ {"content": \"%s\", "disabled": false } ] } ] }'%(record, record2)
        logging.info("Creating CNAME record %s"%(data))
        logging.info("Adding a new CNAME record for %s to %s"%(record, record2))

        res = requests.patch(url, verify=False, data=data, headers=tokenheaders, proxies=noproxy, timeout=300)
        if res.status_code == 404:
            logging.info("""Error: Requested zone "%s" was not found. Status code: %s"""%(tags["@@DOMAIN@@"],res.status_code))
        elif res.status_code == 204:
            logging.info("Successful creating CNAME record. Status code: %s" %res.status_code)
        else:
            logging.info("Failed to create CNAME record. Status code: %s" %res.status_code)
        return(res.status_code)
    except Exception as exc:
        logging.info(exc)
        logging.info("Error getting bearer token without proxy , Retrying with proxy.")
        try:
            res = requests.patch(url, verify=False, data=data, headers=tokenheaders, proxies=proxies, timeout=300)
            return(res.status_code)
        except Exception as exc:
            logging.info(exc)
            logging.info("Error getting bearer token with proxy as well.")
            return(1)

def pushPTRRecord(ip, hostname, scid, node, tags,ptr_domain):
    '''
    curl -X POST --data '{"name":"168.192.in-addr.arpa.", "kind": "Native", "masters": []}' -v -H 'X-API-Key: pdns' http://127.0.0.1:11052/api/v1/servers/localhost/zones

    curl -X PATCH --data '{"rrsets": [ {"name": "ap3-iloamp.cgw.hpe.net.", "type": "A", "ttl": 86400, "changetype": "REPLACE", "records": [ {"content": "172.28.7.30", "disabled": false } ] } ] }' 
    -H 'X-API-Key: pdns' http://127.0.0.1:11052/api/v1/servers/localhost/zones/cgw.hpe.net.
    '''
    client, resultFlag = SSHPython.connect_host(node['ip'], node['user'], node['password'])
    if scid.getSolutionHttpProxy() and scid.getSolutionHttpsProxy():
        proxies = {
        'http': scid.getSolutionHttpProxy(),
        'https': scid.getSolutionHttpsProxy(),
        }
    else:
        proxies = None
        logging.info("No proper Http Proxy details provided")
    
    noproxy = {
        "http": None,
        "https": None,
        }
    try:
        tokenheaders = {'X-API-Key':  'pdns',}
        url= "http://%s:11052/api/v1/servers/localhost/zones/%s."%(tags["@@PDNSHOSTIP@@"],ptr_domain)
        logging.info(url)
        record = hostname+'.'+tags["@@DOMAIN@@"]+'.'
        logging.info(record)
        reversed_ip = ip+".in-addr.arpa."
        data =  '{"rrsets": [ {"name": \"%s\", "type": "PTR", "ttl": 86400, "changetype": "REPLACE", "records": [ {"content": \"%s\", "disabled": false } ] } ] }'%(reversed_ip,record)
        logging.info("Creating PTR record %s"%(data))
        logging.info("Adding a new PTR record for %s with IP %s"%(record, reversed_ip))

        res = requests.patch(url, verify=False, data=data, headers=tokenheaders, proxies=noproxy, timeout=300)
        if res.status_code == 404:
            logging.info("""Error: Requested zone "%s" was not found. Status code: %s"""%(tags["@@DOMAIN@@"],res.status_code))
        elif res.status_code == 204:
            logging.info("Successful creating PTR record. Status code: %s" %res.status_code)
        else:
            logging.info("Failed to create PTR record. Status code: %s" %res.status_code)
        return(res.status_code)
    except Exception as exc:
        logging.info(exc)
        logging.info("Error getting bearer token without proxy , Retrying with proxy")
        try:
            url= "http://%s:11052/api/v1/servers/localhost/zones/%s."%(tags["@@PDNSHOSTIP@@"],ptr_domain)
            record = hostname+'.'+tags["@@DOMAIN@@"]+'.'
            reversed_ip = ip+".in-addr.arpa."
            data =  '{"rrsets": [ {"name": \"%s\", "type": "PTR", "ttl": 86400, "changetype": "REPLACE", "records": [ {"content": \"%s\", "disabled": false } ] } ] }'%(reversed_ip,record)
            res = requests.patch(url, verify=False, data=data, headers=tokenheaders, proxies=proxies, timeout=300)
            return(res.status_code)
        except Exception as exc:
            logging.info(exc)
            logging.info("Error getting bearer token with proxy as well")
            return(1)
        

def enableCron(scid, node, tags):
    client, resultFlag = SSHPython.connect_host(node['ip'], node['user'], node['password'])
    tempDir = createfileAfterReplacementtags(tags, "pdns_to_named")
    logging.info("Creating pdns_to_named.py and copying to %s"%node['ip'])
    response = createFileCopyToRemoteHost(os.path.join(tempDir, "pdns_to_named"), tags, client)
    if response == "Pass":
        installcmd = f"python3 -m pip install requests"
        status,output,error = SSHPython.execute_command(client, installcmd, exitCodeCheck=True)
        cmd = f"chmod 777 /root/pdns_to_named.py"
        croncmd = f"(crontab -l 2>/dev/null; echo \"* * * * * python3 /root/pdns_to_named.py\") | crontab -"
        status,output,error = SSHPython.execute_command(client, cmd, exitCodeCheck=True)
        time.sleep(10)
        status,output,error = SSHPython.execute_command(client, croncmd, exitCodeCheck=True)
        if status == "Pass":
            return True
        else:
            return False