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


import os
import sys
import shutil
import json
import re
import random
import tempfile
import localModules
from pathlib import Path
import SSHPython
from Common_Python import gatewayConstants
import jsonpath_ng

from jsonpath_ng.ext import parse
from jsonpath_ng import jsonpath

'''
from generate_tag_replacement import GenerateTagReplacementDHCP, GenerateTagReplacementDNS,\
    GenerateTagReplacementNTP, GenerateTagReplacementSAT, GenerateTagReplacementLDAP
'''

def create_runtime_Folder(folderName):
    """
    This creates folder in runtime path
    """
    temp = tempfile.mkdtemp()
    folderPath = os.path.join(temp, folderName)
    try:
        os.mkdir(folderPath)
        print('Created folder [{0}]'.format(folderPath))
    except FileExistsError:
        pass
    return folderPath


def copy_file(client, resourceFilePath, destinationFilePath):
    """
    This checks if file exists and copies file if not present already
    """
    copyStatus = "False"
    existStatus = SSHPython.checkFile(client, destinationFilePath)
    if existStatus == "Fail":
        copyStatus = SSHPython.upload_file(
            client, resourceFilePath, destinationFilePath)
        if copyStatus == "Pass":
            print("File [{0}] is copied".format(
                resourceFilePath.split('/')[-1]))
            print("after file copy", existStatus, copyStatus)
            return True
        else:
            print("Unable to copy File [{0}]".format(
                resourceFilePath.split('/')[-1]))
            return False
    else:
        print("File [{0}] is already copied".format(
            resourceFilePath.split('/')[-1]))
        print("after file already exists", existStatus, copyStatus)
        return True


def writeFile(templateFilePath, ConfigFilePath, inputMap):
    """
    This replaces the contents of the file from the provided map
    """
    try:
        shutil.copy2(templateFilePath, ConfigFilePath)
        f = open(ConfigFilePath, 'rt')
        data = f.read()
        for item in inputMap:
            data = data.replace(item, str(inputMap[item]))
        f.close()
        f = open(ConfigFilePath, 'wt')
        f.write(data)
        f.close()
        return True
    except Exception as e:
        print("Exception occurred creating the Config file.")
        print("Exception : ", e)
        return False


def ReplaceTagsInFile(baseDir, fileName, tags):
    """
        source - Source file Path
        destination  - Destination file path
        tags - dictionary object where keys are tags and value are to be replaced in the file

        This Method will use the source as template file and replce all tages and dump in destination file.

        If file exists on destination then it will replace the same.
    """

    if not fileName:
        pass
    # read the source file
    filePath = os.path.join(baseDir, fileName)

    with open(filePath, 'r') as file:
        filedata = file.read()

    # Replacing tags with values
    for tag, value in tags.items():
        if tag and value:
            filedata = filedata.replace(tag, str(value))
        else:
            continue

    # Writing into destination file
    with open(filePath, 'w') as file:
        file.write(filedata)


def getCGDataDirectory():
    return os.path.join(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "cgdata"))


def GetTimeout(minutes=1):
    """
    Send the time after 60 seconds by default otherwise it will provide time after given minutes.
    """
    if minutes < 1:
        minutes = 1
    return time.time() + (60 * minutes)


def ReplaceTagsInFiles(tempdir, appInfo, scid):
    tags = ""
    if appInfo.getName() == "DHCP":
        tags = GenerateTagReplacementDHCP(appInfo.getName(), scid)
    elif appInfo.getName() == "DNS":
        tags = GenerateTagReplacementDNS(appInfo.getName(), scid)
    elif appInfo.getName() == "NTP":
        tags = GenerateTagReplacementNTP(appInfo.getName(), scid)
    elif appInfo.getName() == "SAT":
        tags = GenerateTagReplacementSAT(appInfo.getName(), scid)
    elif appInfo.getName() == "LDAP":
        tags = GenerateTagReplacementLDAP(appInfo.getName(), scid)
    if appInfo.getName() in ["DHCP", "DNS", "NTP"] and appInfo.getConfigmap():
        ReplaceTagsInFile(tempdir, appInfo.getConfigmap(), tags)
        ReplaceTagsInFile(tempdir, appInfo.getDeployment(), tags)
    if appInfo.getName() in ["SAT","LDAP"] and appInfo.getPersistentVolume():
        pv_file = os.path.join(appInfo.getBasePath(),
                               appInfo.getPersistentVolume())
        ReplaceTagsInFile(tempdir, pv_file, tags)
    if appInfo.getName() in ["SAT","LDAP"] and appInfo.getPersistentVolumeClaim():
        pvc_file = os.path.join(appInfo.getBasePath(),
                                appInfo.getPersistentVolumeClaim())
        ReplaceTagsInFile(tempdir, pvc_file, tags)
    if appInfo.getName() in ["SAT","LDAP"] and appInfo.getDeployment():
        deploy_file = os.path.join(
            appInfo.getBasePath(), appInfo.getDeployment())
        ReplaceTagsInFile(tempdir, deploy_file, tags)


def getDataPath():
    try:
        cwd = Path.cwd()
        datapath = os.path.join(os.path.join(os.path.dirname(
            os.path.abspath(__file__)), "..", "..", "data"))
    except Exception as e:
        print("exception:", e)
    return datapath


def getScriptPath():
    try:
        cwd = Path.cwd()
        datapath = os.path.join(os.path.join(os.path.dirname(
            os.path.abspath(__file__)), "..", "..", "script"))
    except Exception as e:
        print("exception:", e)
    return datapath

def getDrbdClusterNumberByAppName(appName):
    filePath = os.path.join(getDataPath(),"DRBDClusters.json")
    try:
        with open(filePath, 'r') as scid_file:
            scid_data = json.load(scid_file)
    except Exception as e:
        print("Error loading SmartCID JSON file: %s, Error: %s", filePath, e)

    jsonPath = f"slesHaClusters[?(@.drbdResources[?(@.componentName == '{appName}')])].clusterNumber"
    try:
        exp = parse(jsonPath)
        objectList = [val.value for val in exp.find(scid_data)]
        if len(objectList) > 0:
            return objectList[0]
    except Exception as e:
        print("Not able to find json path: %s, Error: %s", jsonPath, e)
    return None



def getDrbdResourceByAppName(appName):
    drbd_file = os.path.join(getDataPath(),"DRBDClusters.json")
    with open(drbd_file, 'r') as f:
        drbd_data = json.load(f)
    if drbd_data:
        for data in drbd_data["slesHaClusters"]:
            for drbd_resource in data['drbdResources']:
                if drbd_resource['componentName'].upper() == appName.upper():
                    return drbd_resource
    else:
        print("DRBD Data not exists")
        return None

def Checkfstab(client,mountpath):
    Entryexists=True
    try:
        create_cmd = f"cat /etc/fstab|grep -i {mountpath}|wc -l"
        flag, cmd_out, cmd_err=SSHPython.execute_command(client, create_cmd)
        if "0" in cmd_out:
            Entryexists=False
    except Exception as e:

        print("Exception in check fstab entry ",e)

    return Entryexists

def MountNFSShare(client, clusterIP, componentname, localmountpath, dir = None):
    #flag, cmd_out, cmd_err = None
    Mounted = False
    try:
        if componentname == 'default_HA-1':
            servernfspath = '/srv/nfs/default_HA-1'
        else:
            servernfspath = getDrbdResourceByAppName(componentname)['nfsShare']
            
        if dir:
            servernfspath = servernfspath + "/" + dir

        create_cmd = f"mkdir -p /{localmountpath}"
        mount_cmd = f'mount -t nfs {clusterIP}:{servernfspath} {localmountpath}'
        permanent_mount=f"echo {clusterIP}:{servernfspath} {localmountpath}   nfs defaults 0 2 >>/etc/fstab"
        flag, cmd_out, cmd_err = SSHPython.execute_command(client, create_cmd)
        flag, cmd_out, cmd_err = SSHPython.execute_command(client, mount_cmd)
        status = Checkfstab(client, servernfspath)
        print("fstab entry",status)

        if flag == "Pass" and status:
            print("Already entry is present in fstab")
            Mounted = True
        elif flag =="Pass" and not status:
            flag, cmd_out, cmd_err = SSHPython.execute_command(client, permanent_mount)
            Mounted=True

    except Exception as e:
        print("Exception occured while mounting {}".format(localmountpath),e)

    return Mounted


def getHostEntry(node, domainName):
    tab = "   "
    return node['nodeIp'] + tab + node['nodeHostname'] + "." + domainName + tab + node['nodeHostname']


def createHostEntries(client, primaryNodeIp, nodes, domainName):
    cmd = 'cat /etc/hosts'
    status = True
    flag, cmd_out, cmd_err = SSHPython.execute_command(client, cmd)
    for node in nodes:
        hostEntry = getHostEntry(node, domainName)
        if node['nodeHostname'] + "." + domainName not in cmd_out:
            print("Creating entry - {0}".format(hostEntry))
            cmd = "echo -e {0} >>/etc/hosts".format(hostEntry)
            flag, cmd_out, cmd_err = SSHPython.execute_command(client, cmd)
            if flag != "Pass":
                status = False
        else:
            print("Entry is already created - {0}".format(hostEntry))
    if status:
        print("Host Entries are created in node {0}".format(primaryNodeIp))
        return True
    else:
        print("Host Entries are not created in node {0}".format(primaryNodeIp))
        return False

def findAppMountPoint(parser, mountpoint):
    scidDrbdClusterDetails = parser.getDRBDClusterwithNodeDetails()
    
    scidNodes = scidDrbdClusterDetails['nodes']
    for scidNode in scidNodes:
        scidNode = scidNode['nodeDetails']
        hostname = scidNode['hostName']
        nodeNetworkDetails = parser.getIpAddressByPurpose(scidNode['networkConnections'], gatewayConstants.mgmtServerMgmtPurpose)
        ipAddress = nodeNetworkDetails['ipAddress']
        nodeCredentials = parser.getCredentialsByTarget(scidNode['accessCredentials'], "HOST")
        username = nodeCredentials['userName']
        password = nodeCredentials['password']

        client, connectStatus = SSHPython.connect_host(ipAddress, username, password)
        if connectStatus == "Pass":
            cmd = "lsblk"
            execStatus, ssh_output, ssh_error = SSHPython.execute_command(client, cmd)
            if mountpoint in ssh_output:
                return hostname, client
            
    return False, None

def checkServiceStatus(client, serviceName):
    cmd = f"systemctl is-active {serviceName}"
    execStatus, ssh_output, ssh_error = SSHPython.execute_command(client, cmd)
    if ssh_output == "active":
        return True
    else:
        return False

def get_file_dir(path, file_format):
    file_path = None
    for (root, dirs, file) in os.walk(path):
        for f in file:
            if file_format in f:
                file_path = os.path.join(path,f)
    return(file_path)