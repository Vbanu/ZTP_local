"""
This module will provide the functionality to parse SCID JSON file for gateway and ZTP
"""

import json
import os
import jsonpath_ng
import localModules

from jsonpath_ng.ext import parse
from jsonpath_ng import jsonpath
from Common_Python import gatewayConstants


class SCIDParser:
    """
    This class will provide mechanism to extract data from SCID JSON
    """
    scid_data = None
    infra_obj = None
    base_config_obj = None
    cp_obj = None
    ztp_obj = None

    const=gatewayConstants()
    iloPurpose = const.iloMgmtPurpose
    mgmtPurpose= const.mgmtServerMgmtPurpose
    osInfraNwPurpose= const.osInfraNWPurposeName
    externalNetPurpose = const.externalNetPurpose
    ztpPurpose = const.ztpMgmtPurpose

    def __init__(self):
        pass

    def getCIDID(self):
        return self.infra_obj['siteId']

    def getCreatedBy(self):
        return self.infra_obj['createdBy']

    def getSubmissionDateTime(self):
        return self.infra_obj['lastUpdatedOn']

    def LoadSCIDFile(self, SAT_HOME, serviceObjects):
        """
        Load the file and create the json object
        """
        if type(serviceObjects) is not list:
            res = [scid.strip() for scid in serviceObjects.replace('[','').replace(']','').split(',')]
        else:
            res = serviceObjects

        infraFilePath = os.path.join(SAT_HOME, 'uploads', res[0]).replace ('\\','/')
        baseConfigFilePath = os.path.join(SAT_HOME, 'uploads', res[1]).replace ('\\','/')
        cpFilePath = os.path.join(SAT_HOME, 'uploads', res[2]).replace ('\\','/')
        ztpFilePath = os.path.join(SAT_HOME, 'uploads', res[3]).replace ('\\','/')

        try:
            with open(infraFilePath, 'r') as scid_file:
                self.infra_obj = json.load(scid_file)
        except Exception as e:
            print("Error loading SmartCID JSON file: %s, Error: %s", infraFilePath, e)

        try:
            with open(baseConfigFilePath, 'r') as scid_file:
                self.base_config_obj = json.load(scid_file)
        except Exception as e:
            print("Error loading SmartCID JSON file: %s, Error: %s", baseConfigFilePath, e)

        try:
            with open(cpFilePath, 'r') as scid_file:
                self.cp_obj = json.load(scid_file)
        except Exception as e:
            print("Error loading SmartCID JSON file: %s, Error: %s", cpFilePath, e)
            
        try:
            with open(ztpFilePath, 'r') as scid_file:
                self.ztp_obj = json.load(scid_file)
        except Exception as e:
            print("Error loading SmartCID JSON file: %s, Error: %s", cpFilePath, e)        


    def extractDataUsingJsonPathAndComponent(self, jsonPath, isList=False, component=None):
        """
        Generic function will get the jsonPath string and extract the data from scid_data json object
        """
        # if (self.scid_data == None):
        #     print("Error: SmartCID file is not laoded.")
        #     return
        objectList = None
        try:
            exp = parse(jsonPath)
            if component == None:
                objectList = [val.value for val in exp.find(self.scid_data)]
            else:
                objectList = [val.value for val in exp.find(component)]
        except Exception as e:
            print("Not able to find json path: %s, Error: %s", jsonPath, e)
        if isList:
            return objectList
        else:
            if len(objectList) > 0:
                return objectList[0]
            else:
                return None

    def extractDataUsingJsonPath(self, component, jsonPath, isList=False):
        """
        Generic function will get the jsonPath string and extract the data from scid_data json object
        """
        if (component == None):
            print("Error: SmartCID file is not laoded.")
            return
        objectList = None
        try:
            exp = parse(jsonPath)
            objectList = [val.value for val in exp.find(component)]
        except Exception as e:
            print("Not able to find json path: %s, Error: %s", jsonPath, e)
        if isList:
            return objectList
        else:
            if len(objectList) > 0:
                return objectList[0]
            else:
                return None


    def getNodeipandCredentials(self):
        node_componentId_path = "infrastructure.racks[0]..servers..componentId"
        node_componentId = self.extractDataUsingJsonPath(self.base_config_obj,node_componentId_path,isList=True)
        ret=[]
        for componentId in node_componentId:
            nodeippath = f"infrastructure.racks[0]..servers[?(@.componentId=='{componentId}')].networkConnections[?(@.networkName=='OS and Infrastructure Management Network')].ipAddress"
            nodeip=self.extractDataUsingJsonPath(self.base_config_obj,nodeippath)
            nodeusernamepath=f"racks[0]..servers[?(@.componentId=='{componentId}')]..accessCredentials[?(@.target=='HOST')].userName"
            nodeusername=self.extractDataUsingJsonPath(self.infra_obj,nodeusernamepath)
            nodepasswordpath=f"racks[0]..servers[?(@.componentId=='{componentId}')]..accessCredentials[?(@.target=='HOST')].password"
            nodepassword=self.extractDataUsingJsonPath(self.infra_obj, nodepasswordpath)
            arr=[nodeip,nodeusername,nodepassword]
            ret.append(arr)
        return ret


    def getHostNameILOIPandCredentials(self,purpose,keyname,target):
        server_componentId_path = "infrastructure.racks[0]..servers..componentId"
        server_componentId = self.extractDataUsingJsonPath(self.base_config_obj,server_componentId_path,isList=True)
        ret=[]
        for componentId in server_componentId:
            jsonPath = f"infrastructure.racks[0]..servers[?(@.componentId=='{componentId}')].networkConnections[?(@.purpose == '{purpose}')].ipAddress"
            iloIP = self.extractDataUsingJsonPath(self.base_config_obj,jsonPath)
            jsonPath = f"infrastructure.racks[0]..servers[?(@.componentId=='{componentId}')].{keyname}"
            iloHostName = self.extractDataUsingJsonPath(self.base_config_obj,jsonPath)
            userpath=f"racks[0]..servers[?(@.componentId=='{componentId}')].accessCredentials[?(@.target=='{target}')].userName"
            usernames=self.extractDataUsingJsonPath(self.infra_obj,userpath)
            passwordpath=f"racks[0]..servers[?(@.componentId=='{componentId}')].accessCredentials[?(@.target=='{target}')].password"
            passwords=self.extractDataUsingJsonPath(self.infra_obj,passwordpath)
            domain = self.getSolutionSearchDomainName()
            if domain:
                iloHostName = iloHostName + "." + domain

            tpl = [iloIP, iloHostName,usernames,passwords]
            ret.append(tpl)
        return ret


    def getKubernetesCluster(self):
        """
        Get the kubernetescluster object from SCID JSON
        """
        jsonPath = 'infrastructureManagement.kubernetesCluster'
        return self.extractDataUsingJsonPath(self.cp_obj, jsonPath)

    def getMasterNodeFromKubernetesCluster(self):
        """
        Get master node form kubernetescluster object from SCID JSON
        """
        jsonPath = 'infrastructureManagement.kubernetesCluster.servers[?(@.role=="Master")]'
        return self.extractDataUsingJsonPath(self.cp_obj, jsonPath)
    
    def getMasterNodesFromKubernetesCluster(self):
        """
        Get master node form kubernetescluster object from SCID JSON
        """
        jsonPath = 'infrastructureManagement.kubernetesCluster.servers[?(@.role=="Master")]'
        return self.extractDataUsingJsonPath(self.cp_obj,jsonPath, True)

    def getMasterNodeDeatilsbyNumber(self,nodeNumber=1):
        """
        Get master node form kubernetescluster object from SCID JSON
        """
        node_info={}
        ippath=f"infrastructureManagement.k3sMasterCluster.virtualMachines[{nodeNumber}].networkConnections[0].ipAddress"
        username_path=f"infrastructureManagement.k3sMasterCluster.virtualMachines[{nodeNumber}].accessCredentials[0].userName"
        password_path=f"infrastructureManagement.k3sMasterCluster.virtualMachines[{nodeNumber}].accessCredentials[0].password"
        node_info['host']=(self.extractDataUsingJsonPath(self.cp_obj,ippath))
        node_info['user'] = (self.extractDataUsingJsonPath(self.cp_obj,username_path))
        node_info['password']=(self.extractDataUsingJsonPath(self.cp_obj,password_path))
        return node_info

    def getk3sClusterIP(self):
        """
        Get  kubernetesclusterip  from SCID JSON
        """
        ippath="infrastructureManagement.k3sMasterCluster['virtualIPAddress']"

        return self.extractDataUsingJsonPath(self.cp_obj,ippath)


    def getMasterNodeDetailsForKubernetesCluster(self):
        master = self.getMasterNodeFromKubernetesCluster()
        if master:
            return self.extractDataUsingJsonPath(self.cp_obj,master['serverPath'])
        else:
            return None
    
    ### Not in use
    def getApplicationDNSSearchDomainName(self):
        specificAttr = self.getApplicationSpecificAttributesByName("DNS")
        domain = ""
        if specificAttr:
            domain = (specificAttr['searchDomainName']) if specificAttr.__contains__('searchDomainName') else ""
        return domain    
        

    def getHostNameIPDetail(self, purpose, keyname):
        jsonPath = f"infrastructure.racks[0]..servers..networkConnections[?(@.purpose == '{purpose}')].ipAddress"
        iloIP = self.extractDataUsingJsonPath(self.base_config_obj,jsonPath, isList = True)
        jsonPath = f"infrastructure.racks[0]..servers..{keyname}"
        iloHostName = self.extractDataUsingJsonPath(self.base_config_obj,jsonPath, isList = True)
       
        ret = []
        i = 0
        for ip in iloIP:
            tpl = (ip, iloHostName[i])
            ret.append(tpl)
            i+=1
        
        return ret


    def getK3sHostNameIPDetail(self, purpose, keyname):
        jsonPath = f"infrastructureManagement.k3sMasterCluster.virtualMachines[*]..networkConnections[?(@.purpose == '{purpose}')].ipAddress"
        k3sVmIP = self.extractDataUsingJsonPath(self.cp_obj,jsonPath, isList = True)
        jsonPath = f"infrastructureManagement.k3sMasterCluster.virtualMachines..{keyname}"
        k3sVmHostName = self.extractDataUsingJsonPath(self.cp_obj,jsonPath, isList = True)

        ret = []
        i = 0
        for ip in k3sVmIP:
            tpl = (ip, k3sVmHostName[i])
            ret.append(tpl)
            i+=1

        return ret

    def getSquidHostNameIPDetail(self, purpose, keyname):
        jsonPath = f"infrastructureManagement.squidCluster.virtualMachines[*]..networkConnections[?(@.purpose == '{purpose}')].ipAddress"
        squidVmIP = self.extractDataUsingJsonPath(self.cp_obj,jsonPath, isList = True)
        jsonPath = f"infrastructureManagement.squidCluster.virtualMachines..{keyname}"
        squidVmHostName = self.extractDataUsingJsonPath(self.cp_obj,jsonPath, isList = True)

        ret = []
        i = 0
        for ip in squidVmIP:
            tpl = (ip, squidVmHostName[i])
            ret.append(tpl)
            i+=1

        return ret

    def getPfSenseHostNameIPDetail(self, purpose, keyname):
        jsonPath = f"infrastructureManagement.pfSense.virtualMachines[*]..networkConnections[?(@.purpose == '{purpose}')].ipAddress"
        pfsenseVmIP = self.extractDataUsingJsonPath(self.cp_obj,jsonPath, isList = True)
        jsonPath = f"infrastructureManagement.pfSense.virtualMachines..{keyname}"
        pfsenseVmHostName = self.extractDataUsingJsonPath(self.cp_obj,jsonPath, isList = True)

        ret = []
        i = 0
        for ip in pfsenseVmIP:
            tpl = (ip, pfsenseVmHostName[i])
            ret.append(tpl)
            i+=1

        return ret

    def getMasterNodeSSHDetails(self):
        hostIP = None
        user = None
        password = None

        master = self.getk3sMasterClusterVIP()
        if master:
            hostIP = master
        else:
            return None

        credentials = self.getMasterNodeDeatilsbyNumber(0)
        if credentials:
            user = credentials['user']
            password = credentials['password']
        else:
            return None

        ret = {
            "host": hostIP,
            "user": user,
            "password": password
        }

        return ret

    def getMasterNodeNetworkConnection(self, purpose=mgmtPurpose):
        master = self.getMasterNodeFromKubernetesCluster()
        if master:
            jsonPath = master['serverPath'] + \
                ".networkConnections[?(@.purpose == '" + purpose + "')]"
            return self.extractDataUsingJsonPath(self.cp_obj,jsonPath)
        else:
            return None

    def getMasterNodeCredentials(self, target="HOST"):
        master = self.getMasterNodeFromKubernetesCluster()
        if master:
            jsonPath = master['serverPath'] + \
                ".accessCredentials[?(@.target == '" + target + "')]"
            return self.extractDataUsingJsonPath(self.cp_obj,jsonPath)
        else:
            return None

    def getMasterNodeIP(self):
        node = self.getMasterNodeNetworkConnection()
        if node:
            return node['ipAddress']
        else:
            return None

    def getMasterNodeHostname(self):
        server = self.getMasterNodeDetailsForKubernetesCluster()
        if server:
            return server['hostName']
        else:
            return None

    def getMasterNodeNetworkId(self):
        node = self.getMasterNodeNetworkConnection()
        if node:
            network = self.getNetworkDetailsByName(node['networkName'])
            if network:
                return network['networkId']
            else:
                return None
        else:
            return None

    def getMasterNodeSubnet(self):
        node = self.getMasterNodeNetworkConnection()
        if node:
            network = self.getNetworkDetailsByName(node['networkName'])
            if network:
                return network['networkMask']
            else:
                return None
        else:
            return None

    def getNetworkId(self, name):
        jsonPath = "networks[?(@.name=='" + name + "')]"
        network = self.extractDataUsingJsonPath(self.base_config_obj, jsonPath)
        if network:
            return network['networkId']
        else:
            return None

    def getNetworkDetailsByComponentId(self, name):
        jsonPath = "networks[?(@.componentId=='" + name + "')]"
        network = self.extractDataUsingJsonPath(self.base_config_obj, jsonPath)
        if network:
            return network
        else:
            return None

    def getNetworkName(self):
        jsonPath = "networks..componentId"
        network = self.extractDataUsingJsonPath(self.base_config_obj, jsonPath, isList=True)
        if network:
            return network
        else:
            return None


    def getVMName(self):
        jsonPath = "infrastructureManagement..specificAttributes.hypervisorCluster.virtualMachines"
        cpVms = self.extractDataUsingJsonPath(self.cp_obj,jsonPath)
        baseConfigVms = self.extractDataUsingJsonPath(self.base_config_obj,jsonPath)
        vm_list = []
        for vm in cpVms:
            vm_list.append((vm['hostName'], vm['networkConnections'][0]['ipAddress'], vm['networkConnections'][0]['purpose']))
        for vm in baseConfigVms:
            vm_list.append((vm['hostName'], vm['networkConnections'][0]['ipAddress'], vm['networkConnections'][0]['purpose']))
        if len(vm_list) > 0:
            return vm_list
        else:
            return None

    def getPduDetails(self):
        jsonPath = "infrastructure.racks[0]..pdus"
        pdus = self.extractDataUsingJsonPath(self.base_config_obj, jsonPath)
        print(pdus)
        print(type(pdus))
        pdu_list = []
        for pdu in pdus:
            print(pdu)
            pdu_list.append((pdu['networkConnections'][0]['ipAddress'], pdu['hostName']))
        if len(pdu_list)> 0:
            return pdu_list
        else:
            return None

    def getAgentNodesFromKubernetesCluster(self):
        """
        Get agent nodes form kubernetescluster object from SCID JSON
        """
        jsonPath = 'infrastructureManagement.kubernetesCluster.servers[?(@.role=="Agent")]'
        return self.extractDataUsingJsonPath(self.cp_obj, jsonPath, isList=True)

    def getApplicationByName(self, name):
        """
        Get application object by its name
        """
        jsonPath = 'infrastructureManagement.applications[?(@.name=="' + \
            name + '")]'
        return self.extractDataUsingJsonPath(self.cp_obj, jsonPath, isList=False)
    
    #### yet to be updated #########
    # def getAFCApplicationByName(self, name):
    #     """
    #     Get application object by its name
    #     """
    #     jsonPath = 'infrastructureManagement.configurations.vsphereCluster.virtualMachines[?(@.hostName=="' + \
    #         name + '")]'

    #     return self.extractDataUsingJsonPath(jsonPath, isList=False)

    def getApplicationSpecificAttributesByName(self, name):
        """
        Get specific attributes for the application by its name
        """
        jsonPath = 'infrastructureManagement.applications[?(@.name=="' + \
            name + '")].specificAttributes'
        return self.extractDataUsingJsonPath(self.cp_obj,jsonPath, isList=False)

    def getApplicationsByName(self, name):
        """
        Get applications object by its name
        """
        jsonPath = 'infrastructureManagement.applications[?(@.name=="' + \
            name + '")]'
        return self.extractDataUsingJsonPath(self.cp_obj, jsonPath, isList=True)

    def createDRBDComponentId(self, clusterNumber):
        """
        Create the component String for the DRBD cluster
        """
        clusterId = None
        if clusterNumber < 10:
            clusterId = "DRBDCluster-00" + str(clusterNumber)
        elif clusterNumber < 100 and clusterNumber > 9:
            clusterId = "DRBDCluster-0" + str(clusterNumber)
        else:
            clusterId = "DRBDCluster-" + str(clusterNumber)
        return clusterId

    def getDRBDCluster(self, clusterNumber=1):
        """
        Get DRBD cluster object by it's component ID
        """
        clusterId = self.createDRBDComponentId(clusterNumber)
        jsonPath = 'infrastructureManagement.drbdClusterMultiNodes[?(@.componentId=="' + \
            clusterId + '")]'
        return self.extractDataUsingJsonPath(self.cp_obj, jsonPath, isList=True)

    def getDRBDClusterNFSIP(self, clusterNumber=1, nfsNumber=1):
        """
        Get NFS IP address for the DRBD cluster
        """
        clusterId = self.createDRBDComponentId(clusterNumber)
        jsonPath = 'infrastructureManagement.drbdClusterMultiNodes[?(@.componentId=="' + \
            clusterId + '")]'
        drbdClusterDetails = self.extractDataUsingJsonPath(self.cp_obj, jsonPath, isList=False)
        for nfsDetails in drbdClusterDetails['nfsDetails']:
            if ('server-00'+str(nfsNumber)) in nfsDetails['nodePath']:
                return nfsDetails['networkConnections'][0]['ipAddress']
        

    def getDRBDClusterVirtualIP(self, clusterNumber=1):
        """
        Get virtual IP assigned to DRBD cluster
        """
        clusterId = self.createDRBDComponentId(clusterNumber)
        jsonPath = 'infrastructureManagement.drbdClusterMultiNodes[?(@.componentId=="' + \
            clusterId + '")].clusterVirtualIP'
        return self.extractDataUsingJsonPath(self.cp_obj, jsonPath, isList=False)

    def getSolutionProxySettings(self):
        """
        Get global proxy settings for the solution
        """
        jsonPath = f"hpeIntegrationCenter.proxySettings"
        return self.extractDataUsingJsonPath(self.base_config_obj,jsonPath, isList=False)

    def getSolutionHttpProxy(self):
        """
        Get global http proxy url
        """
        jsonPath = f"hpeIntegrationCenter.proxySettings.httpProxy"
        return self.extractDataUsingJsonPath(self.base_config_obj,jsonPath, isList=False)

    def getSolutionHttpsProxy(self):
        """
        Get global https proxy url
        """
        jsonPath = f"hpeIntegrationCenter.proxySettings.httpsProxy"
        return self.extractDataUsingJsonPath(self.base_config_obj,jsonPath, isList=False)


    def getSolutionDNSSettings(self):
        """
        Get global DNS settings for the solution
        """
        jsonPath = 'hpeIntegrationCenter.dnsSettings'
        return self.extractDataUsingJsonPath(self.base_config_obj,jsonPath, isList=False)


    def getSolutionPrimaryDNS(self):
        """
        Get global primary DNS IP for solution
        """
        jsonPath = 'hpeIntegrationCenter.dnsSettings.primaryDnsIpAddress'
        return self.extractDataUsingJsonPath(self.base_config_obj,jsonPath, isList=False)


    def getSolutionSecondaryDNS(self):
        """
        Get global secondary DNS IP for solution
        """
        jsonPath = 'hpeIntegrationCenter.dnsSettings.secondaryDnsIpAddress'
        return self.extractDataUsingJsonPath(self.base_config_obj,jsonPath, isList=False)


    def getSolutionSearchDomainName(self):
        """
        Get global search domain string for solution
        """
        jsonPath = 'hpeIntegrationCenter.dnsSettings.domainSearchName'
        return self.extractDataUsingJsonPath(self.base_config_obj,jsonPath, isList=False)


    def getSolutionNTPSettings(self):
        """
        Get global NTP settings for solution
        """
        jsonPath = 'hpeIntegrationCenter.ntpSettings'
        return self.extractDataUsingJsonPath(self.base_config_obj, jsonPath, isList=False)

    def getSolutionTimeSettings(self):
        """
        Get global timezone setting for solution
        """
        jsonPath = 'customerSite.timeSettings'
        return self.extractDataUsingJsonPath(self.base_config_obj, jsonPath, isList=False)


    def getNetworkDetailsByName(self, networkName):
        """
        Get the network details for the name it is provided
        """
        jsonPath = 'networks[?(@.name=="' + networkName + '")]'
        return self.extractDataUsingJsonPath(self.base_config_obj,jsonPath, isList=False)


    def getNetworkDetailsByPurpose(self, purpose):
        """
        Get the network details for the purpose list selected for the network
        """
        jsonPath = 'networks'
        networks = self.extractDataUsingJsonPath(self.base_config_obj, jsonPath, isList=False)
        foundNetworks = []
        for network in networks:
            if purpose in network['purposeList']:
                foundNetworks.append(network)
        return foundNetworks

    def getNodeDetailsByComponentId(self, compid):
        jsonPath = "infrastructure.racks[0]..servers[?(@.componentId == '" + \
            compid + "')]"
        return self.extractDataUsingJsonPath(self.base_config_obj, jsonPath)

    def getVmNodeDetailsByPath(self, serverPath):
        """
        Get the node details for the given server path
        """
        return self.extractDataUsingJsonPath(self.base_config_obj, serverPath)

    def getNodeDetailsByPath(self, serverPath):
        
        if "k3sMasterCluster" in serverPath:
            return self.extractDataUsingJsonPath(self.cp_obj, serverPath)
        else:
            server = self.extractDataUsingJsonPath(self.base_config_obj, serverPath)
            serverPath = serverPath.replace('infrastructure.','racks[0].')
            serverPath_cred = f"{serverPath}.accessCredentials" 
            server["accessCredentials"]  = self.extractDataUsingJsonPath(self.infra_obj,serverPath_cred)
            return server


    def getAllNodesDetails(self):
        """
        Get all the node details from SCID
        """
        componentId_path = "infrastructure.racks[0].servers..componentId"
        compId = self.extractDataUsingJsonPath(self.base_config_obj,componentId_path,isList=True)
        ret=[]
        for componentId in compId:
            baseConfigPath = f"infrastructure.racks[0].servers[?(@.componentId=='{componentId}')]"
            baseConfig = self.extractDataUsingJsonPath(self.base_config_obj, baseConfigPath, isList=False)
            infraPath = f"racks[0].servers[?(@.componentId=='{componentId}')]"
            infra = self.extractDataUsingJsonPath(self.infra_obj,infraPath)
            baseConfig['accessCredentials'] = infra['accessCredentials']
            baseConfig['type'] = infra['type']
            ret.append(baseConfig)
        return ret

    def getIpAddressByPurpose(self, networkConnections, purpose):
        """
        Get IP address of component using purpose
        """
        return ([networkConnection for networkConnection in networkConnections if networkConnection['purpose'] == purpose])[0]


    def getCredentialsByTarget(self, accessCredentials, target):
        """
        Get credentials of component using purpose
        """
        return ([accessCredential for accessCredential in accessCredentials if accessCredential['target'] == target])[0]

    # def getDRBDClusterwithNodeDetails(self, clusterNumber=1):
    #     """
    #     Get DRBD cluster object along with Nodes details by it's component ID
    #     """
    #     drbdCluster = self.getDRBDCluster(clusterNumber)
    #     for i in range(len(drbdCluster[0]['nodes'])):
    #         drbdCluster[0]['nodes'][i]['nodeDetails'] = self.extractDataUsingJsonPath(self.cp_obj,drbdCluster[0]['nodes'][i]['serverPath'])

    #     return drbdCluster[0]


    def getDRBDClusterwithNodeDetails(self, clusterNumber=1):
        
        """
        Get DRBD cluster object along with Nodes details by it's component ID
        """
        drbdCluster = self.getDRBDCluster(clusterNumber)
        for i in range(len(drbdCluster[0]['nodes'])):
            nodepath = drbdCluster[0]['nodes'][i]['serverPath']
            drbdCluster[0]['nodes'][i]['nodeDetails'] = self.extractDataUsingJsonPath(self.base_config_obj,drbdCluster[0]['nodes'][i]['serverPath'])
            nodepath_cred = nodepath.replace('infrastructure','racks[0]')
            infra_server_obj = self.extractDataUsingJsonPath(self.infra_obj,nodepath_cred)
            drbdCluster[0]['nodes'][i]['nodeDetails']['accessCredentials'] = infra_server_obj["accessCredentials"]

        return drbdCluster[0]


    def getK3SNodeDetails(self, role):
        """
        Get K3S Node Details by role
        """
        allNodesData = []
        
        if role == "Master" or role == "All":
            mastersData = []
            masterNodeData = self.getMasterNodesFromKubernetesCluster()
            for master in masterNodeData:
                #serverPath = masterNodeData['serverPath']
                masterData = self.getNodeData(master['serverPath'])
                masterData['role'] = 'Master'
                mastersData.append(masterData)
        if role == "Agent" or role == "All":
            agentsData = []
            agentNodeData = self.getAgentNodesFromKubernetesCluster()
            for agent in agentNodeData:
                agentNodeDetails = self.getNodeData(agent['serverPath'])
                agentNodeDetails['role'] = 'Agent'
                agentsData.append(agentNodeDetails)
        if role == "All":
            allNodesData.extend(mastersData)
            allNodesData.extend(agentsData)
            return allNodesData
        elif role == "Master":
            return mastersData
        elif role == "Agent":
            return agentsData

    def getNodeData(self, server_path):
        """
        Get Node data by server path
        """
        if 'Master' in server_path:
            nodeHostName = self.extractDataUsingJsonPath(self.cp_obj, server_path + ".hostName")
            nodeIp = self.extractDataUsingJsonPath(self.cp_obj,
                server_path + '.networkConnections[?(@.purpose=="' + self.mgmtPurpose + '")].ipAddress')
            nodeUserName = self.extractDataUsingJsonPath(self.cp_obj,
                server_path + '.accessCredentials[?(@.target=="HOST")].userName')
            nodePassword = self.extractDataUsingJsonPath(self.cp_obj,
                server_path + '.accessCredentials[?(@.target=="HOST")].password')
            nodeData = {"node_ip": nodeIp, "node_username": nodeUserName,
                        "node_password": nodePassword,
                        "node_hostname": nodeHostName}
            return nodeData
        else:
            nodeHostName = self.extractDataUsingJsonPath(self.base_config_obj, server_path + ".hostName")
            nodeIp = self.extractDataUsingJsonPath(self.base_config_obj,
                server_path + '.networkConnections[?(@.purpose=="' + self.mgmtPurpose + '")].ipAddress')
            infra_server_path = server_path.replace('infrastructure','racks[0]')
            nodeUserName = self.extractDataUsingJsonPath(self.infra_obj,
                infra_server_path + '.accessCredentials[?(@.target=="HOST")].userName')
            nodePassword = self.extractDataUsingJsonPath(self.infra_obj,
                infra_server_path + '.accessCredentials[?(@.target=="HOST")].password')
            nodeData = {"node_ip": nodeIp, "node_username": nodeUserName,
                        "node_password": nodePassword,
                        "node_hostname": nodeHostName}
            return nodeData


    def getAgentNodeSSHDetails(self, nodeinfo):
        hostIP = None
        user = None
        password = None

        node = self.getAgentNodeNetworkConnection(nodeinfo=nodeinfo)
        if node:
            hostIP = node.get('ipAddress')
        else:
            return None

        credentials = self.getAgentNodeCredentials(nodeinfo=nodeinfo)
        if credentials:
            user = credentials.get('userName')
            password = credentials.get('password')
        else:
            return None

        details = {
            "host": hostIP,
            "user": user,
            "password": password
        }

        return details

    def getAgentNodeNetworkConnection(self, purpose=mgmtPurpose, nodeinfo=None):
        if nodeinfo:
            jsonPath = nodeinfo.get('serverPath') + \
                ".networkConnections[?(@.purpose == '" + purpose + "')]"
            return self.extractDataUsingJsonPath(self.base_config_obj,jsonPath)
        else:
            return None

    def getAgentNodeCredentials(self, target="HOST", nodeinfo=None):
        if nodeinfo:
            jsonPath = nodeinfo.get('serverPath') + \
                ".accessCredentials[?(@.target == '" + target + "')]"
            jsonPath_cred = jsonPath.replace('infrastructure','racks[0]')
            return self.extractDataUsingJsonPath(self.infra_obj,jsonPath_cred)
        else:
            return None


    def getAgentNodesFromKubernetesClusterbyindex(self):
        """
        Get agent nodes form kubernetescluster object from SCID JSON
        """
        jsonPath = 'infrastructureManagement.kubernetesCluster.servers[?(@.role=="Agent")]'
        return self.extractDataUsingJsonPath(self.cp_obj,jsonPath, isList=True)
    
    def getServerType(self):
        """
        Get type of the server in the SCID #This is temporary
        """
        servers = self.getAllNodesDetails()
        for server in servers:
            serverType = server['type']
            if serverType.startswith("m510") or serverType.startswith("M510"):
                return "EL"
            if serverType.startswith("DL"):
                return "DL"
            if serverType.startswith("XL"):
                return "Apollo"
    
    def getHostServiceByName(self,serviceName):
        """
        Get Host Service object by it's namehostServices
        """
        jsonPath = 'infrastructureManagement.hostServices[?(@.name=="' + serviceName + '")]'
        return self.extractDataUsingJsonPath(self.cp_obj, jsonPath, isList=False)

    def getMasterNodesKubernetesCluster(self):
        """
        Get master nodes form kubernetescluster object from SCID JSON
        """
        jsonPath = 'infrastructureManagement.kubernetesCluster.servers[?(@.role=="Master")]'
        return self.extractDataUsingJsonPath(self.cp_obj, jsonPath, isList=True)

    def getAgentNodesKubernetesCluster(self):
        """
        Get master nodes form kubernetescluster object from SCID JSON
        """
        jsonPath = 'infrastructureManagement.kubernetesCluster.servers[?(@.role=="Agent")]'
        return self.extractDataUsingJsonPath(self.cp_obj,jsonPath, isList=True)


    def getk3sMasterClusterComponentID(self):
        """
        Get componentId from SCID JSON
        """
        jsonPath = '$.infrastructureManagement.k3sMasterCluster.componentId'
        return self.extractDataUsingJsonPath(self.cp_obj,jsonPath, isList=False)

    def getk3sMasterClusterVIP(self):
        """
        Get virtualIPAddress from SCID JSON
        """
        jsonPath = '$.infrastructureManagement.k3sMasterCluster.virtualIPAddress'
        return self.extractDataUsingJsonPath(self.cp_obj,jsonPath, isList=False)

    def isAruba6300MPresent(self):
        """
        It will check the CID has the switch configuartion with Aruba Switch or not
        """
        # jsonPath = '$.infrastructure.racks[0].networkSwitches[?(@.type =~ "6300M" & @.role == "OOBM")]'
        jsonPath = '$.infrastructure.racks[0]..networkSwitches[?(@.role == "OOBM")]'
        roleCheck = self.extractDataUsingJsonPath(self.base_config_obj,jsonPath, isList=True)
        if len(roleCheck):
            jsonPath_type = '$.racks[0]..networkSwitches[?(@.type =~ "6300M1")]'
            typecheck = self.extractDataUsingJsonPath(self.infra_obj,jsonPath_type, isList=True)
            if len(typecheck):
                return True
            else:
                return False
        else:
            return False

    def getAruba6300MCreds(self):
        """
        It will check the CID has the switch configuartion with Aruba Switch or not
        """
        # jsonPath = '$.infrastructure.racks[0].networkSwitches[?(@.type =~ "6300M" & @.role == "OOBM")]'
        netSwitchDetails = self.getNetworkSwitchDetails()

        #jsonPath = '$.infrastructure.racks[0]..networkSwitches[?(@.role == "OOBM")]'
        #oobmSwitchDetails = self.extractDataUsingJsonPath(self.base_config_obj,jsonPath, isList=True)
        return oobmSwitchDetails(netSwitchDetails[0])

    def isAruba83XXPresent(self):
        """
        It will check the CID has the switch configuartion with Aruba Switch or not
        """
        jsonPath = '$.infrastructure.racks[0]..networkSwitches[?(@.role == "Compute")]'
        rolecheck = self.extractDataUsingJsonPath(self.base_config_obj,jsonPath, isList=True)
        if len(rolecheck):
            jsonPath_type = '$.racks[0]..networkSwitches[?(@.type =~ "8325|8360")]'
            typecheck = self.extractDataUsingJsonPath(self.infra_obj,jsonPath_type, isList=True)
            if len(typecheck):
                return True
            else:
                return False
        else:
            return False
    
    # need to be updated
    # def isSelfManagementOneviewPresent(self):
    #     """
    #     It will check the oneview configuration is present for the managing MRA
    #     """
    #     jsonPath = '$.infrastructureManagement..oneViews[?(@.role=="OV")]'
    #     result = self.extractDataUsingJsonPath(jsonPath, isList=True)
    #     if len(result):
    #         return True
    #     else:
    #         return False

    # need to be updated
    # def isSelfManagementiLOAmpPresent(self):
    #     """
    #     It will check the iloamplifier configuration is present for the managing MRA
    #     """
    #     jsonPath = '$.infrastructureManagement.iloAmplifier'
    #     result = self.extractDataUsingJsonPath(jsonPath, isList=True)
    #     if len(result):
    #         return True
    #     else:
    #         return False

    # in acurate data
    def getHostNameIPDetailForK3SAgentNodes(self, purpose):
        domain = self.getSolutionSearchDomainName()
        if domain:
            domain = "." + domain
        nodes = self.getMasterNodesKubernetesCluster()

        ret = []   
        for node in nodes:
            jsonPath = node.get('serverPath') + \
                ".networkConnections[?(@.networkName == '" + purpose + "')]"
            ip = self.extractDataUsingJsonPath(self.infra_obj,jsonPath).get('ipAddress')
            hostname = self.extractDataUsingJsonPath(node['serverPath']).get('hostName')
            tpl = (ip, hostname + domain)
            ret.append(tpl)
        return ret

    # Not in use, can we delete ?
    def getAgentDetailsByComponentId(self, compid):
        jsonPath = "infrastructure..servers[?(@.componentId == '" + \
                   compid + "')].networkConnections[1].ipAddress"
        ip = self.extractDataUsingJsonPath(self.base_config_obj,jsonPath)
        jsonPath = "$.racks[0]..servers[?(@.componentId =='" + \
                   compid + "')].accessCredentials[?(@.target =='HOST')]"
        credentials = self.extractDataUsingJsonPath(self.infra_obj,jsonPath)

    # not in use can we delelte ??
    def getAFCVirtualIP(self):

        jsonPath = "$.infrastructureManagement.applications[*][?(@.role == 'Active')].virtualIPAddress"

        return self.extractDataUsingJsonPath(self.jsonPath, isList=False)

    def getWorkerNodeNetworkIPbyNumber(self, purpose, nodeNumber=0):
        """
        Get worker node form kubernetescluster object from SCID JSON
        """
        obj = self.extractDataUsingJsonPath(self.cp_obj,"$.infrastructureManagement.kubernetesCluster.servers[?(@.role == 'Agent')]", True)
        path = obj[nodeNumber]['serverPath']
        ippath = f"{path}.networkConnections[?(@.purpose == '{purpose}')].ipAddress"
        ip = (self.extractDataUsingJsonPath(self.base_config_obj,ippath))
        return ip

    def getWorkerNodeDetailsbyNumber(self, nodeNumber=0):
        """
        Get worker node form kubernetescluster object from SCID JSON
        """
        node_info = {}
        obj = self.extractDataUsingJsonPath(self.cp_obj,"$.infrastructureManagement.kubernetesCluster.servers[?(@.role == 'Agent')]", True)
        path = obj[nodeNumber]['serverPath']
        ippath = f"{path}.networkConnections[?(@.purpose == 'Management Server Management')].ipAddress"
        infra_path = path.replace('infrastructure','racks[0]')
        username_path = f"{infra_path}.accessCredentials[?(@.target == 'HOST')].userName"
        # username_path = "$.racks[0]..servers[?(@.componentId=='server-001')].accessCredentials[?(@.target == 'HOST')].userName"
        password_path = f"{infra_path}.accessCredentials[?(@.target == 'HOST')].password"
        node_info['host'] = (self.extractDataUsingJsonPath(self.base_config_obj,ippath))
        node_info['user'] = (self.extractDataUsingJsonPath(self.infra_obj,username_path))
        node_info['password'] = (self.extractDataUsingJsonPath(self.infra_obj,password_path))
        return node_info

    # not in use can we delete
    def getAFCVMIP(self, afcvmnumber=8):

        jsonPath = f"infrastructureManagement.applications[{afcvmnumber}].networkConnections[*].ipAddress"

        return self.extractDataUsingJsonPath(jsonPath)
    

    def getNetworkSwitchHostNameIPDetail(self, purpose, keyname):
        jsonPath = f"infrastructure.racks[0]..networkSwitches..networkConnections[?(@.purpose == '{purpose}')].ipAddress"
        networkSwitchIP = self.extractDataUsingJsonPath(self.base_config_obj,jsonPath, isList = True)
        jsonPath = f"infrastructure.racks[0]..networkSwitches..{keyname}"
        networkHostName = self.extractDataUsingJsonPath(self.base_config_obj,jsonPath, isList = True)
       
        ret = []
        i = 0
        for ip in networkSwitchIP:
            tpl = (ip, networkHostName[i])
            ret.append(tpl)
            i+=1
        
        return ret

    def getarubaFabricComposer(self,role="Master"):
        if role == "Master":
            jsonPath='$.infrastructureManagement.arubaFabricComposerCluster.arubaFabricComposers[?(@.role == "' + role + '")]'
            return self.extractDataUsingJsonPath(self.base_config_obj,jsonPath, isList = False)
        else:
            jsonPath="$.infrastructureManagement.arubaFabricComposerCluster.arubaFabricComposers[?(@.role == '" + role + "')]"
            return self.extractDataUsingJsonPath(self.base_config_obj,jsonPath, isList=True)


    def getarubaFabricComposerALL(self):
        jsonPath='$.infrastructureManagement.arubaFabricComposerCluster.arubaFabricComposers'
        return self.extractDataUsingJsonPath(self.base_config_obj,jsonPath)
    
    def getarubaFabricComposerVirtualIP(self):
        jsonPath='$.infrastructureManagement.arubaFabricComposerCluster.networkConnections[0].ipAddress'
        return self.extractDataUsingJsonPath(self.base_config_obj,jsonPath)
    
    def getHAIPForService(self, type, service):
        jsonPathForIP = f"$.infrastructureManagement.hostServices[?(@.name == '{service}')].specificAttributes.{type}IPAddressJsonPath"
        jsonPath = self.extractDataUsingJsonPath(self.cp_obj,jsonPathForIP, isList=False)
        return self.extractDataUsingJsonPath(self.cp_obj,jsonPath, isList=False)

    def getAFCPassword(self):
        jsonPath = 'racks[0].networkSwitches[*].accessCredentials[*].password'
        return self.extractDataUsingJsonPath(self.infra_obj,jsonPath, isList=True)
    
    def getVirtualMachinesHostNameIPDetail(self, vmcomponent, purpose, keyname):
        jsonPath = f"infrastructureManagement..specificAttributes..hypervisorCluster..virtualMachines[?(@.componentId == '{vmcomponent}')].networkConnections[?(@.purpose == '{purpose}')].ipAddress"
        networkSwitchIP = self.extractDataUsingJsonPath(self.cp_obj,jsonPath, isList = True)
        jsonPath = f"infrastructureManagement..specificAttributes..hypervisorCluster..virtualMachines[?(@.componentId == '{vmcomponent}')].{keyname}"
        networkHostName = self.extractDataUsingJsonPath(self.cp_obj,jsonPath, isList = True)
       
        domain = self.getSolutionSearchDomainName()
        if domain:
            domain = "." + domain
     
        ret = []
        i = 0
        for ip in networkSwitchIP:
            tpl = (ip, networkHostName[i] + domain)
            ret.append(tpl)
            i+=1
        
        return ret

    def getNetworkNameMap(self, networkName):
        networkMap = {
            "Out of Band Management(OOBM) Network" : "oobm-service",
            "OS and Infrastructure Management Network" : "osin-service",
            "Platform Data Network" : "platformdata-service",
            "Platform and GreenLake Services Network" : "platformgreenlakeservices-service",
            "Foundational Services Network" : "foundational-service",
            "Deployment Services Network" : "deployment-service"
        }
        return networkMap[networkName]

    def getNetworksVlanId(self, purpose=osInfraNwPurpose):
        jsonPath = "networks[?(@.name=='" + purpose + "')]"
        network = self.extractDataUsingJsonPath(self.base_config_obj,jsonPath)
        if network:
            return str(network['vlanId'])
        else:
            return None

    def getNetworksSubnet(self, purpose=osInfraNwPurpose):
        jsonPath = "networks[?(@.name=='" + purpose + "')]"
        network = self.extractDataUsingJsonPath(self.base_config_obj,jsonPath)
        networkMask = network['networkMask']
        cidr = sum([bin(int(x)).count('1') for x in networkMask.split('.')])  # convert netmask ip to cidr
        if network:
            return str(cidr)
        else:
            return None

    # this needs to be updated as slaves are not present
    def getArubaFabricComposerVmIps(self):
        jsonPath='$.infrastructureManagement.arubaFabricComposerCluster.arubaFabricComposers[?(@.role == "Master")].nodePath'
        masterIp =  self.extractDataUsingJsonPath(self.base_config_obj,jsonPath, isList = False)

        jsonPathForMasterIP = masterIp + '.networkConnections[0].ipAddress'
        masterIp1 =  self.extractDataUsingJsonPath(self.base_config_obj,jsonPathForMasterIP, isList = False)
        # jsonPath = '$.infrastructureManagement.arubaFabricComposerCluster.arubaFabricComposers[?(@.role == "Slave")].nodePath'
        # standbyIps = self.extractDataUsingJsonPath(self.base_config_obj,jsonPath, isList=True)
        # jsonPathForStandby1_IP = standbyIps[0] + '.networkConnections[0].ipAddress'
        # standby1_Ip = self.extractDataUsingJsonPath(self.base_config_obj,jsonPathForStandby1_IP, isList=False)
        # jsonPathForStandby2_IP = standbyIps[1] + '.networkConnections[0].ipAddress'
        # standby2_Ip = self.extractDataUsingJsonPath(self.base_config_obj,jsonPathForStandby2_IP, isList=False)

        return masterIp1


    def CertificateComponentDetails(self, vmcomponent):
        """
        This function returns the OneView details
        """
        nodeInfo={}
        if(vmcomponent == 'afc-master'):
            jsonObj = self.base_config_obj
        else:
            jsonObj = self.cp_obj

        hostname_path = f"infrastructureManagement..specificAttributes..hypervisorCluster..virtualMachines[?(@.vmName == '{vmcomponent}')].hostName"
        ip_path = f"infrastructureManagement..specificAttributes..hypervisorCluster..virtualMachines[?(@.vmName == '{vmcomponent}')].networkConnections..ipAddress"
        username_path = f"infrastructureManagement..specificAttributes..hypervisorCluster..virtualMachines[?(@.vmName == '{vmcomponent}')].accessCredentials..userName"
        password_path = f"infrastructureManagement..specificAttributes..hypervisorCluster..virtualMachines[?(@.vmName == '{vmcomponent}')].accessCredentials..password"

        nodeInfo['hostname'] = self.extractDataUsingJsonPath(jsonObj, hostname_path)
        nodeInfo['ip'] = self.extractDataUsingJsonPath(jsonObj, ip_path)
        nodeInfo['username'] = self.extractDataUsingJsonPath(jsonObj, username_path)
        nodeInfo['password'] = self.extractDataUsingJsonPath(jsonObj, password_path)
        nodeInfo['fqdn'] = f'{self.extractDataUsingJsonPath(jsonObj, hostname_path)}.{self.getSolutionSearchDomainName()}'
        return nodeInfo


    def getDRBDNfsDetails(self, clusterNumber=1):
        """
        Get NFS details of DRBD cluster
        """
        clusterId = self.createDRBDComponentId(clusterNumber)
        jsonPath = 'infrastructureManagement.drbdClusterMultiNodes[?(@.componentId=="' + \
            clusterId + '")].nfsDetails'
        return self.extractDataUsingJsonPath(self.cp_obj,jsonPath, isList=False)


    def getPduDetailsInfo(self):
        """
        Get PDU details from rack
        """
        componentId_path = "infrastructure.racks[0].pdus..componentId"
        compId = self.extractDataUsingJsonPath(self.base_config_obj,componentId_path,isList=True)
        ret=[]
        for componentId in compId:
            baseConfigPath = f"infrastructure.racks[0].pdus[?(@.componentId=='{componentId}')]"
            baseConfig = self.extractDataUsingJsonPath(self.base_config_obj, baseConfigPath, isList=False)

            infraPath = f"racks[0].pdus[?(@.componentId=='{componentId}')]"
            infra = self.extractDataUsingJsonPath(self.infra_obj,infraPath)
            baseConfig['accessCredentials'] = infra['accessCredentials']
            baseConfig['type'] = infra['type']
            ret.append(baseConfig)
        return ret


    def getSnmpDetails(self):
        """
        Get global SNMP settings for solution
        """
        jsonPath = 'solutionNetworkSettings.snmpSettings'
        return self.extractDataUsingJsonPath(self.base_config_obj, jsonPath, isList=False)


    def getServerDetails(self):
        """
        Get Server details from rack
        """
        componentId_path = "infrastructure.racks[0].servers..componentId"
        compId = self.extractDataUsingJsonPath(self.base_config_obj,componentId_path,isList=True)
        ret=[]
        for componentId in compId:
            baseConfigPath = f"infrastructure.racks[0].servers[?(@.componentId=='{componentId}')]"
            baseConfig = self.extractDataUsingJsonPath(self.base_config_obj, baseConfigPath, isList=False)

            infraPath = f"racks[0].servers[?(@.componentId=='{componentId}')]"
            infra = self.extractDataUsingJsonPath(self.infra_obj,infraPath)
            baseConfig['accessCredentials'] = infra['accessCredentials']
            baseConfig['type'] = infra['type']
            baseConfig['rackElevationStart'] = infra['rackElevationStart']
            baseConfig['rackElevationEnd'] = infra['rackElevationEnd']
            baseConfig['lighthouseModuleId'] = infra['lighthouseModuleId']

            ret.append(baseConfig)
        return ret


    def getCPNetworks(self):
        """
        Get the network details for the name it is provided
        """
        networks = []
        networkName = ['Out of Band Management(OOBM) Network', 'OS and Infrastructure Management Network', 'Platform Data Network', 'Platform and GreenLake Services Network', 'Dead Network', 'Aruba VSX Keep Alive','pfSense Sync Network']
        for network in networkName:
            jsonPath = 'networks[?(@.name=="' + network + '")]'
            networks.append(self.extractDataUsingJsonPath(self.base_config_obj,jsonPath))
        # return dict(networks=networks)
        return networks


    def getNetworkSwitchDetails(self):
        """
        Get network switch details from rack
        """
        componentId_path = "infrastructure.racks[0].networkSwitches..componentId"
        compId = self.extractDataUsingJsonPath(self.base_config_obj,componentId_path,isList=True)
        #print(compId)
        ret=[]
        for componentId in compId:
            baseConfigPath = f"infrastructure.racks[0].networkSwitches[?(@.componentId=='{componentId}')]"
            baseConfig = self.extractDataUsingJsonPath(self.base_config_obj, baseConfigPath, isList=False)

            infraPath = f"racks[0].networkSwitches[?(@.componentId=='{componentId}')]"
            infra = self.extractDataUsingJsonPath(self.infra_obj,infraPath)
            baseConfig['accessCredentials'] = infra['accessCredentials']
            baseConfig['type'] = infra['type']
            ret.append(baseConfig)

        return ret
        #return dict(networkSwitches=ret)


    def getAruba6300MCreds(self):
        """
        It will check the CID has the switch configuartion with Aruba Switch or not
        """
        switchDetails = self.getNetworkSwitchDetails()
        jsonPath = '$.networkSwitches[?(@.role =="OOBM")]'
        oobmSwitchDetails = self.extractDataUsingJsonPath(switchDetails, jsonPath, isList=True)
        oobmSwitches = []
        for oobm in oobmSwitchDetails:
            jsonPath = '$.networkSwitches[?(@.role =="OOBM")]'
            ip = self.extractDataUsingJsonPath(oobm, '$.networkConnections[?(@.purpose=="Network Switch Management")].ipAddress')
            username= self.extractDataUsingJsonPath(oobm, '$.accessCredentials[0].userName')
            password = self.extractDataUsingJsonPath(oobm, '$.accessCredentials[0].password')
            oobmSwitches.append(dict(ip=ip, username=username, password=password))
        for oobmSwitch in oobmSwitches:
            print(self.extractDataUsingJsonPath(oobmSwitch, '$.ip'))
        return oobmSwitches


    def getHpeIntegrationCenterSettings(self):
        """
        Get global proxy settings for the solution
        """
        jsonPath = f"hpeIntegrationCenter"
        return self.extractDataUsingJsonPath(self.base_config_obj,jsonPath, isList=False)

    def getInfraManagement(self):
        """
        Get global proxy settings for the solution
        """
        jsonPath = f"infrastructureManagement"
        return self.extractDataUsingJsonPath(self.base_config_obj,jsonPath, isList=False)


    def getTimeSettings(self):
        """
        Get global proxy settings for the solution
        """
        jsonPath = f"customerSite.timeSettings"
        return self.extractDataUsingJsonPath(self.base_config_obj,jsonPath, isList=False)

    def getTimezoneName(self):
        """
        Get the timezone name
        """
        jsonPath = f"customerSite.timeSettings.timeZoneName"
        return self.extractDataUsingJsonPath(self.base_config_obj,jsonPath, isList=False)


    def getRackComponentId(self, rackNumber=0):
        """
        Get the rack's componentId by rack number
        """
        jsonPath = f"racks[0].componentId"
        compId = self.extractDataUsingJsonPath(self.infra_obj, jsonPath, isList=False)
        return compId

    def getDHCPNodePathDetails_byNodeNumber(self, nodeNuber):
        dhcpServiceDetails = self.getHostServiceByName("dhcp")
        jsonPath = dhcpServiceDetails['nodePaths'][nodeNuber]
        basic_details =  self.extractDataUsingJsonPath(self.base_config_obj, jsonPath)


        jsonPath_cred = jsonPath.replace('infrastructure','racks[0]')
        cred_details = self.extractDataUsingJsonPath(self.infra_obj,jsonPath_cred+".accessCredentials")
        # return type(basic_details), type(cred_details)
        basic_details['accessCredentials'] = cred_details
        return basic_details
 

    def getDataFromInfraAndBaseConfig(self):
        scid_data = {}

        serverInfo = self.getServerDetails()
        networkSwitchs = self.getNetworkSwitchDetails()
        pdus = self.getPduDetailsInfo()
        rackComponentId = self.getRackComponentId()

        scid_data["infrastructure"]={}
        scid_data["infrastructure"]["racks"] = []
        scid_data["infrastructure"]["racks"].append(dict(componentId=rackComponentId))
        scid_data["infrastructure"]["racks"][0]["networkSwitches"]=networkSwitchs
        scid_data["infrastructure"]["racks"][0]["servers"] = serverInfo
        scid_data["infrastructure"]["racks"][0]["pdus"] = pdus

        scid_data["infrastructureManagement"] = self.getInfraManagement()
        scid_data["infrastructureManagement"]["arubaFabricComposerCluster"] = self.extractDataUsingJsonPath("infrastructureManagement.arubaFabricComposerCluster", component=self.base_config_obj)
        scid_data["infrastructureManagement"]["kubernetesCluster"] = self.extractDataUsingJsonPathAndComponent("infrastructureManagement.kubernetesCluster", component=self.cp_obj)
        scid_data["infrastructureManagement"]["k3sMasterCluster"] = self.extractDataUsingJsonPathAndComponent( "infrastructureManagement.k3sMasterCluster", component=self.cp_obj)
        scid_data["infrastructureManagement"]["drbdClusterMultiNodes"] = self.extractDataUsingJsonPathAndComponent( "infrastructureManagement.drbdClusterMultiNodes", component=self.cp_obj)
        scid_data["infrastructureManagement"]["applications"] = self.extractDataUsingJsonPathAndComponent( "infrastructureManagement.applications", component=self.cp_obj)
        scid_data["infrastructureManagement"]["hostServices"] = self.extractDataUsingJsonPathAndComponent( "infrastructureManagement.hostServices", component=self.cp_obj)
        scid_data["infrastructureManagement"]["oneViews"] = self.extractDataUsingJsonPathAndComponent( "infrastructureManagement.oneViews", component=self.cp_obj)
        scid_data["infrastructureManagement"]["iloAmplifier"] = self.extractDataUsingJsonPathAndComponent("infrastructureManagement.iloAmplifier", component=self.cp_obj)
        scid_data["infrastructureManagement"]["specificAttributes"] = self.extractDataUsingJsonPathAndComponent("infrastructureManagement.specificAttributes", component=self.cp_obj)
        scid_data["infrastructureManagement"]["pfSense"] = self.extractDataUsingJsonPathAndComponent("infrastructureManagement.pfSense", component=self.cp_obj)
        
        scid_data["networks"] = self.getCPNetworks()
        scid_data["timeSettings"] = self.getTimeSettings()
        scid_data["hpeIntegrationCenter"] = self.getHpeIntegrationCenterSettings()
        scid_data["hpeIntegrationCenter"]["snmpSettings"] = self.getSnmpDetails()

        file_path = os.path.join(os.environ["SAT_HOME"],"gl-gateway-infra-artifacts")
        is_dir = os.path.isdir(file_path)
        if not is_dir:
            os.mkdir(file_path)

        jsonFile = os.path.join(file_path, 'infraBaseConfig.json').replace ('\\','/')
        out_file = open(jsonFile, "w")
        json.dump(scid_data, out_file, indent = 2)
        out_file.close()
        return scid_data

    def getsquidClusterALL(self):
        jsonPath='$.infrastructureManagement.squidCluster'
        return self.extractDataUsingJsonPath(self.cp_obj,jsonPath)

    def getsquidClusterVMs(self):
        jsonPath='$.infrastructureManagement.squidCluster.virtualMachines'
        return self.extractDataUsingJsonPath(self.cp_obj,jsonPath)

    def getSolutionSquidProxyLANVIP(self, purpose=mgmtPurpose):
        jsonPath = f"infrastructureManagement.squidCluster.lanCarpVirtualIP.networkConnections[?(@.purpose == '{purpose}')].ipAddress"
        return self.extractDataUsingJsonPath(self.cp_obj,jsonPath, isList=False)

    def getSolutionSquidProxyWANVIP(self, purpose=externalNetPurpose):
        jsonPath = f"infrastructureManagement.squidCluster.wanCarpVirtualIP.networkConnections[?(@.purpose == '{purpose}')].ipAddress"
        return self.extractDataUsingJsonPath(self.cp_obj,jsonPath, isList=False)

    def getSolutionSquidProxyPort(self):
        jsonPath = f"infrastructureManagement.squidCluster.squidProxyPort"
        return self.extractDataUsingJsonPath(self.cp_obj,jsonPath, isList=False)

    def getSolutionSquidProxyIPURL(self):
        squid_ip = self.getSolutionSquidProxyLANVIP()
        squid_port = self.getSolutionSquidProxyPort()
        if squid_ip and squid_port:
            squid_ipurl = f"http://{squid_ip}:{squid_port}/"
            return squid_ipurl
        return None

    def getVMDetailsByPath(self, serverPath):
        return self.extractDataUsingJsonPath(self.cp_obj, serverPath)


"""
Below Functions will provide the functionality to parse SCID JSON file for ZTP(Zero Touch Provisioning)
"""

    def getEdgeServers(self, purpose=ztpPurpose):
        jsonPath = "This will be updated from the final version of ECaas SCID"
        return self.extractDataUsingJsonPath(self.ztp_obj,jsonPath, isList=False)
        
    def getEdgeVcenter(self, purpose=ztpPurpose):
        jsonPath = "This will be updated from the final version of ECaas SCID"
        return self.extractDataUsingJsonPath(self.ztp_obj,jsonPath, isList=False)
        
    def getEdgeWitness(self, purpose=ztpPurpose):
        jsonPath = "This will be updated from the final version of ECaas SCID"
        return self.extractDataUsingJsonPath(self.ztp_obj,jsonPath, isList=False)
        
    def getEdgeMDFArubaSwitch(self, purpose=ztpPurpose):
        jsonPath = "This will be updated from the final version of ECaas SCID"
        return self.extractDataUsingJsonPath(self.ztp_obj,jsonPath, isList=False)
        
    def getEdgeADFArubaSwitch(self, purpose=ztpPurpose):
        jsonPath = "This will be updated from the final version of ECaas SCID"
        return self.extractDataUsingJsonPath(self.ztp_obj,jsonPath, isList=False)