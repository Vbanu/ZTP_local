import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
import time

import paramiko
import requests
from jsonpath_ng.ext import parse
#from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings()
#requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from collections import defaultdict

# Module content <START>
ServiceRootURL = "https://%s/redfish/v1/"
iLORstLoginURL = "https://%s/redfish/v1/SessionService/Sessions"
iLOTimeZoneURL = "https://%s/redfish/v1/systems/1/bios/settings"
iLOUserAccountURL = "https://%s/redfish/v1/AccountService/Accounts"
iLOLogoutURL = "https://%s/redfish/v1/AccountService/Accounts"
iLONetworkURL = "https://%s/redfish/v1/Managers/1/EthernetInterfaces/1"
#DedicatediLONetworkURL = "https://%s/redfish/v1/Managers/1/EthernetInterfaces/1"
SharediLONetworkURL = "https://%s/redfish/v1/Managers/1/EthernetInterfaces/2"
systemResetURL = "https://%s/redfish/v1/Systems/1/Actions/ComputerSystem.Reset"
iLOResetURL = "https://%s/redfish/v1/managers/1/Actions/Manager.Reset"
arrayControllerURL = "https://%s/redfish/v1/systems/1/SmartStorage/ArrayControllers/0"
logicalDriveURL = "https://%s/redfish/v1/systems/1/smartstorageconfig/settings"
serverModelURL = "https://%s/redfish/v1/chassis/1"
computerSystem1URL = "https://%s/redfish/v1/Systems/1/"
processorURL = "https://%s/redfish/v1/Systems/1/Processors/%s"
pciDevicesURL = "https://%s/redfish/v1/Systems/1/PCIDevices"
pciMemberDevicesURL = "https://%s/redfish/v1/Systems/1/PCIDevices/%s"
biosURL = "https://%s/redfish/v1/systems/1/bios"
iLOFactoryDefaultsURL = "https://%s/redfish/v1/managers/1/Actions/Oem/Hpe/HpeiLO.ResetToFactoryDefaults"
virtualMediaURL = "https://%s/redfish/v1/managers/1/virtualmedia/2"
SecureBootURL = "https://%s/redfish/v1/Systems/1/SecureBoot"
iLOSecureEraseURL = "https://%s/redfish/v1/Systems/1/Actions/Oem/Hpe/HpeComputerSystemExt.SecureSystemErase"
NtpURL = "https://%s/redfish/v1/Managers/1/DateTime"

#URLs added for ILO Security settings
ManagerURL = "https://%s/redfish/v1/Managers/1"
UpdateServiceURL = "https://%s/redfish/v1/UpdateService"
AccountServiceURL = "https://%s/redfish/v1/accountservice"
SecurityStateURL = "https://%s/redfish/v1/Managers/1/SecurityService"
LicenseKeyURL = "https://%s/redfish/v1/Managers/1/LicenseService"

# URLs added for Instance Type BIOS tagging
systemChassis1URL = "https://%s/redfish/v1/chassis/1"
chassis1DevicesURL = "https://%s/redfish/v1/chassis/1/Devices"
chassisMemberDevicesURL = "https://%s/redfish/v1/chassis/1/Devices/%s"
BIOSsettingsURL = "https://%s/redfish/v1/systems/1/bios/settings"
BiosMapURLgen10P = "https://%s/redfish/v1/Systems/1/Bios/oem/hpe/mappings/"
#  URLs added for Enable/Disable NICs
VirtualNicURL = "https://%s/redfish/v1/Managers/1/"
hostNicURL = "https://%s/redfish/v1/systems/1/bios/settings/"
NicURL = "https://%s/redfish/v1/Systems/1/BaseNetworkAdapters/%s/"
BiosMapURL = "https://%s/redfish/v1/Systems/1/Bios/mappings"

#  URLs added for CSR certificate
genCSRURL = "https://%s/redfish/v1/Managers/1/SecurityService/HttpsCert/Actions/HpeHttpsCert.GenerateCSR"
dwnldCSRURL = "https://%s/redfish/v1/Managers/1/SecurityService/HttpsCert/"
importCertURL = "https://%s/redfish/v1/Managers/1/SecurityService/HttpsCert/Actions/HpeHttpsCert.ImportCertificate/"
viewCertURL = "https://%s/redfish/v1/Managers/1/SecurityService/HttpsCert/"

#URL for Dime Licencing
flashDIMELicensefile1="https://%s/redfish/v1/UpdateService/Actions/UpdateService.SimpleUpdate/"
validateDIMELicense1="https://%s/redfish/v1/Managers/1/SecurityService/TrustedOSSecurityModules"

#  URLs added for Enabling Encryption in SmartArray Controller
EncryptionURL = "https://%s/redfish/v1/systems/1/smartstorageconfig/settings"

baseURL = "https://%s%s"
nicDevicesURL = "https://%s/redfish/v1/Systems/1/BaseNetworkAdapters/"
smartStorageURL = "https://%s/redfish/v1/systems/1/smartstorage/arraycontrollers"
storageURL = "https://%s/redfish/v1/systems/1/storage"
DedicatediLONetworkURL = "https://%s/redfish/v1/Managers/1/EthernetInterfaces/1"

# URLs added for SNMP Configuration
snmpURL = "https://%s/redfish/v1/Managers/1/NetworkProtocol"
snmpConfigURL = "https://%s/redfish/v1/Managers/1/SnmpService"

#URLs added for ILO Security settings
ManagerURL = "https://%s/redfish/v1/Managers/1"
UpdateServiceURL = "https://%s/redfish/v1/UpdateService"
AccountServiceURL = "https://%s/redfish/v1/accountservice"
SecurityStateURL = "https://%s/redfish/v1/Managers/1/securityservice"
LicenseKeyURL = "https://%s/redfish/v1/Managers/1/LicenseService"
NetworkProtocolURL = "https://%s/redfish/v1/Managers/1/NetworkProtocol"

#URLs for IDevID and Platform Certificates
IDevIDURL = "https://%s/redfish/v1/Managers/1/SecurityService/SystemIDevID/Certificates/1"
PlatformIDURL = "https://%s/redfish/v1/Managers/1/SecurityService/PlatformCert/Certificates/1"

#URL for Mellanox CX6
chassisNetAdapterfunctionURL = "https://%s/redfish/v1/chassis/1/NetworkAdapters/%s/NetworkDeviceFunctions/%s"
chassisNetAdaptersURL = "https://%s/redfish/v1/Chassis/1/NetworkAdapters/"

# URLs for Power
chassisPowerURL = "https://%s/redfish/v1/chassis/1/Power"

XMLDataURL = "https://%s/xmldata?item=all"
logoffURL = {}
authCodeMap = {}

ERROR_INVALID_SESSION = 2
ERROR_API_TIMEOUT = 3



# Defining class for iLO network configuration 

class ILONwConfig:
    def  __init__(self):

        self.__iLOHostName=""
        self.__iLONwdomainName=""
        self.__iLOHostIP=""
        self.__iLONwSubnetMask=""
        self.__iLONwGateway=""
        self.__iLONwDNS=""
    
    def SetiLOHostName(self,iloHstName):
        self.__iLOHostName = iloHstName
    
    def GetiLOHostName(self):
        return self.__iLOHostName
    
    def SetiLONwDomainName(self,iLONwdomainName):
        self.__iLONwdomainName = iLONwdomainName
    
    def GetiLONwdomainName(self):
        return self.__iLONwdomainName

    def SetiLOHostIP(self,iLOHostIP):
        self.__iLOHostIP = iLOHostIP
    
    def GetiLOHostIP(self):
        return self.__iLOHostIP

    def SetiLONwSubnetMask(self,iLONwSubnetMask):
        self.__iLONwSubnetMask = iLONwSubnetMask
    
    def GetiLONwSubnetMask(self):
        return self.__iLONwSubnetMask
    
    def SetiLONwGateway(self,iLONwGateway):
        self.__iLONwGateway = iLONwGateway
    
    def GetiLONwGateway(self):
        return self.__iLONwGateway

    def SetiLONwDNS(self,iLONwDNS):
        self.__iLONwDNS = iLONwDNS
    
    def GetiLONwDNS(self):
        return self.__iLONwDNS


class DiscoverHostsObj:
    def  __init__(self):

        self.__switch_cmd = ""
        self.__search_string = ""
        self.__hostModList = ""
        self.__hostSrNoList = ""
        self.__hstFactUsrName = ""
        self.__hstFactPwd = ""
        self.__bmc_vlan_id = ""
        self.__host_type = ""
        self.__switch_ip = ""
        self.__switch_username = ""
        self.__switch_password = ""
        self.__switch_type = ""
        self.__switch_delimiter = ""
        self.__switch_footer = ""
        self.__switch_MAC_field_number = 0
        self.__ilo_network = ""
        self.__ipv6_interface = ""
        self.__swDlmter = ""
        self.__swMACFldNo = 0
    
    # Disallow the user to set switch command, search string and delimiter
    # Instead let us set that depends on switch type

    def get_switch_cmd(self):
        return self.__switch_cmd
        
    def get_search_string(self):
        return self.__search_string

    def SetHostModList(self,hostModList):
        self.__hostModList = hostModList
    
    def GetHostModList(self):
        return self.__hostModList

    def SetHostSrNoList(self,hostSrNoList):
        self.__hostSrNoList = hostSrNoList
    
    def GetHostSrNoList(self):
        return self.__hostSrNoList

    def SetHostFactRstUsername(self,hstFactUsrName):
        self.__hstFactUsrName = hstFactUsrName
    
    def GetHostFactRstUsername(self):
        return self.__hstFactUsrName
  
    def SetHostFactRstPassword(self,hstFactPwd):
        self.__hstFactPwd = hstFactPwd
    
    def GetHostFactRstPassword(self):
        return self.__hstFactPwd  
    
    def set_bmc_vlan_id(self,bmc_vlan_id):
        self.__bmc_vlan_id = bmc_vlan_id

    def get_bmc_vlan_id(self):
        return self.__bmc_vlan_id  

    def set_host_type(self,host_type):
        self.__host_type = host_type
    
    def get_host_type(self):
        return self.__host_type

    def set_switch_ip(self,switch_ip):
        self.__switch_ip = switch_ip
    
    def get_switch_ip(self):
        return self.__switch_ip
    
    def set_switch_username(self,switch_username):
        self.__switch_username = switch_username
    
    def get_switch_username(self):
        return self.__switch_username

    def set_switch_password(self,switch_password):
        self.__switch_password = switch_password
    
    def get_switch_password(self):
        return self.__switch_password

    def set_switch_type(self,switch_type):
        if switch_type == "ARUBA":
            self.__switch_cmd = "show mac-address-table port {port_number}"
            self.__search_string = "--------------------------------------------------------------"
            self.__switch_delimiter = ":"
            self.__switch_footer = ""
            self.__switch_MAC_field_number = 0
        else:
            logging.error(f"Error setting switch type with unsupported switch type {switch_type}")
            return

        self.__switch_type = switch_type
    
    def get_switch_type(self):
        return self.__switch_type    
    
    def get_switch_delimiter(self):
        return self.__switch_delimiter
    
    def get_switch_footer(self):
        return self.__switch_footer

    def get_MAC_field_number(self):
        return self.__switch_MAC_field_number

    def set_ilo_network(self, ilo_network_id, ilo_network_mask):
        try:
            self.__ilo_network = ipaddress.IPv4Network(ilo_network_id + '/' + ilo_network_mask)
        except ipaddress.AddressValueError as e:
            logging.exception(f"IP address error setting iLO network {ilo_network_id}/{ilo_network_mask}. Error: {e}")
            raise
        except ipaddress.NetmaskValueError as e:
            logging.exception(f"Netmask error setting iLO network: {ilo_network_id}/{ilo_network_mask}. Error: {e}")
            raise
        except ValueError as e:
            logging.exception(f"Value error setting iLO network {ilo_network_id}/{ilo_network_mask}. Error: {e}")
            raise
        except Exception as e:
            logging.exception(f"Error setting iLO network {ilo_network_id}/{ilo_network_mask}. Error: {e}")
            raise

    def set_ipv6_interface(self):
        if sys.platform == 'linux':
            ipv6_dev_cmd = "ip -br a show scope global | awk '{print $1, $3}' | awk -F / '{print $1}'"
            process = subprocess.Popen(ipv6_dev_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                stdout, stderr = process.communicate(timeout=5)
                interfaces_ipaddresses = stdout.decode().splitlines()
            except Exception as e:
                process.kill()
                logging.exception(f"Error running ip command to discover IPv6 interface. Error: {e}")
                raise
            
            try:
                for network in interfaces_ipaddresses:
                    network_details = network.split()
                    logging.info(network_details)
                    if len(network_details) == 2:
                        if ipaddress.ip_address(network_details[1]) in self.__ilo_network:
                            self.__ipv6_interface = network_details[0]
                            logging.debug(f"{network_details[1]} in {self.__ilo_network}")
                            logging.debug(f"IPv6 interface: {self.__ipv6_interface}")
                    else:
                        continue

            except Exception as e:
                logging.exception(f"Error in determining IPv6 interface. Error: {e}")
                raise

    def get_ilo_network(self):
        return self.__ipv6_interface

    def get_ipv6_interface(self):
        return self.__ipv6_interface
    
    def GetMACFieldNo(self):
        return self.__swMACFldNo

    def GetSwcDlmter(self):
        return self.__swDlmter

def GetServerModel(host):
    svrmodel = None

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(host)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {host}.")
        return ERROR_INVALID_SESSION

    try:
        headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[host]
        }    
        
        res = MakeRestRequest((serverModelURL % host),"GET",headers,"")

        svrModel = res[0]['Model']
    except Exception as e:
        logging.error(f"Exception in retrieving the server model {host}. Exception: {e}.")
        
    return svrModel    

def GetiLOGen(host):
    ilogen = None

    try:
        headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[host]
        }   

        serviceRoot = MakeRestRequest((ServiceRootURL % host),"GET",headers,"")

        gencompany = next(iter(serviceRoot[0].get("Oem", {}).keys()), None) in ('Hpe', 'Hp')
        comp = 'Hp' if gencompany else None
        comp = 'Hpe' if serviceRoot[0].get("Oem", {}).get('Hpe', None) else comp
        if comp and next(iter(serviceRoot[0].get("Oem", {}).get(comp, {}).get("Manager", {}))).get('ManagerType', None):
            ilogen = next(iter(serviceRoot[0].get("Oem", {}).get(comp, {}).get("Manager", {}))).get("ManagerType")
            #ilover = next(iter(serviceRoot[0].get("Oem", {}).get(comp, {}).get("Manager", {}))).get("ManagerFirmwareVersion")
            if ilogen.split(' ')[-1] == "CM":
                # Assume iLO 4 types in Moonshot
                ilogen = 4
            else:
                ilogen = ilogen.split(' ')[1]

    except Exception as e:
        logging.error(f"Exception in retrieving iLO generation for {host}. Exception: {e}.")

    return ilogen


def GetSerialNumber(iLOHost):
    serialNo = None

    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    try:
        headers = {
            'content-type': "application/json",
            'X-Auth-Token': authCodeMap[iLOHost]
        }

        res = MakeRestRequest((biosURL % iLOHost), "GET", headers, "")
        serialNo = res[0]['Attributes']['SerialNumber']

    except Exception as e:

        logging.error(f"Exception in retrieving the serial number {iLOHost}. Exception: {e}.")

    return serialNo


def SystemReset(host):
    retVal = 0

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(host)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {host}.")
        return ERROR_INVALID_SESSION

    try:
        headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[host]
        }    
        
        compRes = MakeRestRequest((computerSystem1URL % host),"GET",headers,"")
        if (compRes[0]['PowerState'] == 'On'):
            resetType = "ForceRestart"
        else:
            resetType = "On"

        systemResetBody = {
            "ResetType": resetType
        }

        MakeRestRequest((systemResetURL % host),"POST",headers,systemResetBody)
        
    except Exception as e:
        logging.error(f"Exception in resetting/power cycling the system {host}. Exception: {e}.")
        retVal = 1
    
    return retVal  

def SystemPowerStatus(host):

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(host)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {host}.")
        return ERROR_INVALID_SESSION

    try:     
        headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[host]
        }    

        compRes = MakeRestRequest((computerSystem1URL % host),"GET",headers,"")
        retVal = compRes[0]['PowerState']

    except Exception as e:        
        logging.error(f"Exception in powering on system {host}. Exception: {e}.")
        retVal = 1

    return retVal 

def SystemPowerOn(host):
    
    retVal = 0

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(host)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {host}.")
        return ERROR_INVALID_SESSION

    try:     
        headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[host]
        }    

        compRes = MakeRestRequest((computerSystem1URL % host),"GET",headers,"")
        if (compRes[0]['PowerState'] == 'On'):
            logging.info("System %s is already powered on." % (host))
            retVal = 0

        else:
            resetType = "On"

            systemResetBody = {
                "ResetType": resetType
            }

            MakeRestRequest((systemResetURL % host),"POST",headers,systemResetBody)
    
    except Exception as e:        
        logging.error(f"Exception in powering on system {host}. Exception: {e}.")
        retVal = 1

    return retVal 

def SystemPowerOff(host):
    
    retVal = 0

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(host)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {host}.")
        return ERROR_INVALID_SESSION

    try:     
        headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[host]
        }    

        compRes = MakeRestRequest((computerSystem1URL % host),"GET",headers,"")
        if (compRes[0]['PowerState'] == 'Off'):
            logging.info("System %s is already powered off." % (host))
            retVal = 0

        else:
            resetType = "ForceOff"

            systemResetBody = {
                "ResetType": resetType
            }

            MakeRestRequest((systemResetURL % host),"POST",headers,systemResetBody)
    
    except Exception as e:        
        logging.error(f"Exception in powering off system {host}. Exception: {e}.")
        retVal = 1

    return retVal 

def ILOReset(host):
    retVal = 0
    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(host)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {host}.")
        
        return ERROR_INVALID_SESSION

    try:
        headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[host]
        }    
        
        iLOResetBody = {}      

        MakeRestRequest((iLOResetURL % host),"POST",headers,iLOResetBody)
        
    except Exception as e:
        logging.error(f"Exception in resetting/power cycling the iLO {host}. Exception: {e}.")
        retVal = 1
    return retVal  


def ILOLogin(host,userName, password):
    
    global authCodeMap
    global logoffURL
    loginRes = None
    loginHdr = None
    retVal = 0

    
    try:
            
        headers = {
            'content-type': "application/json"
        }
        payload = {
            "UserName": userName, 
            "Password": password    
        }
        loginRes, loginHdr = MakeRestRequest((iLORstLoginURL % host),"POST",headers,payload)
        authCodeMap[host] = loginHdr['X-Auth-Token']
        logoffURL[host] = loginHdr['Location']
        
    except Exception as e:
        logging.error(f"Exception logging in to host {host}. Exception: {e}.")
        retVal = 1
        
    return retVal


def ILOLogoff(iLOHost):

    retVal = 0

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    try:
        MakeRestRequest(logoffURL[iLOHost],"DELETE",headers,"")
        authCodeMap[iLOHost] = None
        logoffURL[iLOHost] = None
    except Exception as e:
        logging.error("Exception in logging off. iLO URL: %s" % logoffURL[iLOHost])
        retVal = 1
    return retVal


def Configure_iLO_Network(iLOHost, nwConfigObj):
    
    retVal = 0
    ilogen = None

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        #logging.info("Ensure valid iLO session is there for the host %s" % iLOHost)
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    fqdn = "%s.%s" % (nwConfigObj.GetiLOHostName(),nwConfigObj.GetiLONwdomainName())

    ilogen = GetiLOGen(iLOHost)

    if ilogen == '4':
        nwConfigBody = {
      
            "IPv4Addresses": [
                {
                    "Address": nwConfigObj.GetiLOHostIP(),            
                    "Gateway": nwConfigObj.GetiLONwGateway(),
                    "SubnetMask": nwConfigObj.GetiLONwSubnetMask()
                }
            ],
            "Oem": {
                "Hp": {            
                    "DHCPv4": {
                        "Enabled": False,
                        "UseDNSServers": False,
                        "UseDomainName": False,
                        "UseGateway": False,
                        "UseNTPServers": False,
                        "UseStaticRoutes": False,
                        "UseWINSServers": False
                    },
                    "DHCPv6": {
                        "StatefulModeEnabled": False,
                        "StatelessModeEnabled": False,
                        "UseDNSServers": False,
                        "UseDomainName": False,
                        "UseNTPServers": False,
                        "UseRapidCommit": False
                    },
                    
                    "DomainName": nwConfigObj.GetiLONwdomainName(),
                    "HostName": nwConfigObj.GetiLOHostName(),
                    "IPv4": {
                        "DDNSRegistration": True,
                        "DNSServers": [
                            nwConfigObj.GetiLONwDNS(),
                            "0.0.0.0",
                            "0.0.0.0"
                        ],                
                        "WINSRegistration": False
                    }
                }
            }
        }
    elif ilogen == '5':
        nwConfigBody = {
            
            "DHCPv4": {
                "DHCPEnabled": False,
                "UseGateway": False
                
            },
            "FQDN": fqdn,    
            "HostName": nwConfigObj.GetiLOHostName(),
            "IPv4Addresses": [
                {
                    "Address": nwConfigObj.GetiLOHostIP(),            
                    "Gateway": nwConfigObj.GetiLONwGateway(),
                    "SubnetMask": nwConfigObj.GetiLONwSubnetMask()
                }
            ],
            "Oem": {
                "Hpe": {            
                    "DHCPv4": {
                        "ClientIdType": "Default",
                        "Enabled": False,
                        "UseDNSServers": False,
                        "UseDomainName": False,
                        "UseGateway": False,
                        "UseNTPServers": False,
                        "UseStaticRoutes": False,
                        "UseWINSServers": False
                    },
                    "DHCPv6": {
                    "StatefulModeEnabled": False,
                    "StatelessModeEnabled": False,
                    "UseDNSServers": False,
                    "UseDomainName": False,
                    "UseNTPServers": False,
                    "UseRapidCommit": False
                },
                    
                    "DomainName": nwConfigObj.GetiLONwdomainName(),
                    "HostName": nwConfigObj.GetiLOHostName(),
                    "IPv4": {
                        "DDNSRegistration": True,
                        "DNSServers": [
                            nwConfigObj.GetiLONwDNS(),
                            "0.0.0.0",
                            "0.0.0.0"
                        ],                
                        "WINSRegistration": False
                    }
                }
            }
            
        }

    try:       
       nwConfigRes = MakeRestRequest( (iLONetworkURL % iLOHost),"PATCH",headers,nwConfigBody) 
       
    except Exception as e:
        logging.error(f"Exception in performing iLO network configuration {iLOHost} in iLO. Exception: {e}.")
        retVal = 1

    return retVal         

def Configure_iLO_Network_new(iLOHost, nwConfigObj, iloMode="dedicated"):
    
    retVal = 0
    ilogen = None

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    fqdn = "%s.%s" % (nwConfigObj.GetiLOHostName(),nwConfigObj.GetiLONwdomainName())

    ilogen = GetiLOGen(iLOHost)

    if ilogen == '4':
        nwConfigBody = {
      
            "IPv4Addresses": [
                {
                    "Address": nwConfigObj.GetiLOHostIP(),            
                    "Gateway": nwConfigObj.GetiLONwGateway(),
                    "SubnetMask": nwConfigObj.GetiLONwSubnetMask()
                }
            ],
            "Oem": {
                "Hp": {            
                    "DHCPv4": {
                        "Enabled": False,
                        "UseDNSServers": False,
                        "UseDomainName": False,
                        "UseGateway": False,
                        "UseNTPServers": False,
                        "UseStaticRoutes": False,
                        "UseWINSServers": False
                    },
                    "DHCPv6": {
                        "StatefulModeEnabled": False,
                        "StatelessModeEnabled": False,
                        "UseDNSServers": False,
                        "UseDomainName": False,
                        "UseNTPServers": False,
                        "UseRapidCommit": False
                    },
                    
                    "DomainName": nwConfigObj.GetiLONwdomainName(),
                    "HostName": nwConfigObj.GetiLOHostName(),
                    "IPv4": {
                        "DDNSRegistration": True,
                        "DNSServers": [
                            nwConfigObj.GetiLONwDNS(),
                            "0.0.0.0",
                            "0.0.0.0"
                        ],                
                        "WINSRegistration": False
                    }
                }
            }
        }
    elif ilogen == '5':
        nwConfigBody = {
            
            "DHCPv4": {
                "DHCPEnabled": False,
                "UseGateway": False
                
            },
            "FQDN": fqdn,    
            "HostName": nwConfigObj.GetiLOHostName(),
            "IPv4Addresses": [
                {
                    "Address": nwConfigObj.GetiLOHostIP(),            
                    "Gateway": nwConfigObj.GetiLONwGateway(),
                    "SubnetMask": nwConfigObj.GetiLONwSubnetMask()
                }
            ],
            "Oem": {
                "Hpe": {            
                    "DHCPv4": {
                        "ClientIdType": "Default",
                        "Enabled": False,
                        "UseDNSServers": False,
                        "UseDomainName": False,
                        "UseGateway": False,
                        "UseNTPServers": False,
                        "UseStaticRoutes": False,
                        "UseWINSServers": False
                    },
                    "DHCPv6": {
                    "StatefulModeEnabled": False,
                    "StatelessModeEnabled": False,
                    "UseDNSServers": False,
                    "UseDomainName": False,
                    "UseNTPServers": False,
                    "UseRapidCommit": False
                },
                    
                    "DomainName": nwConfigObj.GetiLONwdomainName(),
                    "HostName": nwConfigObj.GetiLOHostName(),
                    "IPv4": {
                        "DDNSRegistration": True,
                        "DNSServers": [
                            nwConfigObj.GetiLONwDNS(),
                            "0.0.0.0",
                            "0.0.0.0"
                        ],                
                        "WINSRegistration": False
                    }
                }
            }
            
        }

    try:
        dedicatediLOdata = MakeRestRequest((iLONetworkURL % iLOHost),"GET",headers,"")
        #logging.info("Dedicated iLO data: ", dedicatediLOdata)
        sharediLOdata = MakeRestRequest((SharediLONetworkURL % iLOHost),"GET",headers,"")
        #logging.info("Shared iLO data: ", sharediLOdata)
        if dedicatediLOdata[0]['LinkStatus'] =="LinkUp":
            #logging.info("Configuring Dedicated iLO interface")
            logging.info("Configuring Dedicated iLO interface")
            nwConfigRes = MakeRestRequest( (iLONetworkURL % iLOHost),"PATCH",headers,nwConfigBody)
        elif sharediLOdata[0]['LinkStatus'] =="LinkUp":
            #logging.info("Configuring Shared iLO interface")
            logging.info("Configuring Shared iLO interface")
            nwConfigRes = MakeRestRequest( (SharediLONetworkURL % iLOHost),"PATCH",headers,nwConfigBody)
        else:
            nwConfigRes = MakeRestRequest( (iLONetworkURL % iLOHost),"PATCH",headers,nwConfigBody) #Defaulting to dedicated mde if none of the iLO ports are enabled.

    except Exception as e:
        logging.error(f"Exception in performing iLO network configuration {iLOHost} in iLO. Exception: {e}.")
        retVal = 1

    return retVal,nwConfigRes


def AddUser(iLOHost,user,passw):
    
    retVal = 0
    flag = 0
    ilogen = None

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }

    ilogen = GetiLOGen(iLOHost)

    if ilogen == '4':
        addUserBody = {
        "UserName": user,
        "Password": passw,
        "Oem": {
            "Hp": {
                "LoginName": user,
                "Privileges": {
                    "LoginPriv": True,
                    "RemoteConsolePriv": True,                    
                    "UserConfigPriv": True,
                    "VirtualMediaPriv": True,
                    "VirtualPowerAndResetPriv": True,
                    "iLOConfigPriv": True
                    }
                }
            }
        }
    elif ilogen == '5':
        addUserBody = {
            "UserName": user,
            "Password": passw,
            "Oem": {
                "Hpe": {
                    "LoginName": user,
                    "Privileges": {
                        "HostBIOSConfigPriv": True,
                        "HostNICConfigPriv": True,
                        "HostStorageConfigPriv": True,
                        "LoginPriv": True,
                        "RemoteConsolePriv": True,                    
                        "UserConfigPriv": True,
                        "VirtualMediaPriv": True,
                        "VirtualPowerAndResetPriv": True,
                        "iLOConfigPriv": True
                    }
                }
            }
        }

    try:
        UsrRes = MakeRestRequest( (iLOUserAccountURL % iLOHost),"GET",headers,"")
        accounts = UsrRes[0]['Members']
        
        for account in accounts:
            USRurl = account['@odata.id']
            UserURL = "https://%s"+USRurl
            UsrRes = MakeRestRequest( (UserURL % iLOHost),"GET",headers,"")
            if UsrRes[0]['UserName'] == user:
                flag = 1
                acc_url = UsrRes[0]['@odata.id']

        if flag:
            account_url = "https://%s"+acc_url
            payload = {
                    "Password": passw
                }
            Res = MakeRestRequest( (account_url % iLOHost),"PATCH",headers,payload)
            retVal = 4
        else:
            addUsrRes = MakeRestRequest( (iLOUserAccountURL % iLOHost),"POST",headers,addUserBody) 
    except Exception as e:
        logging.error(f"Exception in adding the user account {user} in iLO. Exception: {e}.")
        retVal = 1

    return retVal         
    

def ChangeTimeZone(iLOHost,timeZoneName):

    timeZoneIdx = None
    retVal = 0


    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION


    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    
    try:
        iLOFormatTz = Convert2iLOFormat(timeZoneName,"iLOFormat")
        
        tmzBody = {
                "Attributes": {
                "TimeZone": iLOFormatTz
            }            
        }    
        tzRes = MakeRestRequest( (iLOTimeZoneURL % iLOHost),"PATCH",headers,tmzBody)


    except Exception as e:
        logging.error(f"Exception in setting the timezone {timeZoneName}. Exception: {e}.")
        retVal = 1

    return retVal


def generateCSR(iLOIP,iLOHost):
    retVal = 0

    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOIP)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOIP}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOIP]
    }

    try:
        subjectList = FetchSubjectDetails()
        logging.info("SubjectList=", subjectList)
        csrBody = {
            "Action": "HpeHttpsCert.GenerateCSR",
            "CommonName": iLOHost,
            "Country": subjectList[0],
            "State": subjectList[1],
            "City": subjectList[2],
            "OrgName": subjectList[3],
            "OrgUnit": subjectList[4],
            "IncludeIP": subjectList[5]
        }		

        nicRes = MakeRestRequest((genCSRURL % iLOIP), "POST", headers, csrBody)
        
    except Exception as e:
        logging.error("Exception in generating CSR.")
        retVal = 1
    return retVal


def downloadCSR(iLOHost, csr_filePath):
    retVal = 0
    time.sleep(5)
    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }

    try:
        nicRes = MakeRestRequest((dwnldCSRURL % iLOHost), "GET", headers, "")
        svrSerialNumber = GetSerialNumber(iLOHost)
        SSL_Certificate = nicRes[0]['CertificateSigningRequest']
        filename = svrSerialNumber + ".csr"
        CSRfile = os.path.join(csr_filePath, filename)
        f = open(CSRfile, "w+")
        f.write(SSL_Certificate)
        f.close()

    except Exception as e:
        logging.error("Exception in downloading CSR.")
        retVal = 1

    return retVal


def importCertificate(iLOHost, signed_cert_file_location):
    retVal = 0

    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }

    try:
        f = open(signed_cert_file_location, "r")
        SSL_certificate = f.read()
        csrBody = {
            "Action": "HpeHttpsCert.ImportCertificate",
            "Certificate": SSL_certificate
        }
        nicRes = MakeRestRequest((importCertURL % iLOHost), "POST", headers, csrBody)
        #logging.info(nicRes)
    except Exception as e:
        logging.error("Exception in importing signed iLO certificate.")
        retVal = 1

    return retVal


def viewCertificate(iLOHost):
    retVal = 0

    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }

    try:

        nicRes = MakeRestRequest((viewCertURL % iLOHost), "GET", headers, "")
        #logging.info(nicRes)
    except Exception as e:
        logging.error("Exception in viewing certificate.")
        retVal = 1

    return retVal


def GenerateCert(dataFilePath, csr_filepath,iLOPassword):
    retVal = 0
    try:
        cmd1 = "openssl genrsa -aes256 -passout pass:" + iLOPassword + " -out rootCA.key 4096"
        #stream = os.popen('openssl genrsa -aes256 -passout pass:"Password!234" -out rootCA.key 4096')
        stream = os.popen(cmd1)
        output = stream.read()
        subjectList = FetchSubjectDetails()
        subject = "/C=" + subjectList[0] + "/ST=" + subjectList[1] + "/L=" + subjectList[2] + "/O=" + subjectList[3]
        cmd2 = "openssl req -x509 -new -nodes -key rootCA.key -days 1024 -out rootCA.pem -passin pass:" + iLOPassword + " -subj " + subject
        #stream = os.popen('openssl req -x509 -new -nodes -key rootCA.key -days 1024 -out rootCA.pem -passin pass:"Password!234" -subj "/C=IN/ST=KAR/L=Bangalore/O=HPE"')
        stream = os.popen(cmd2)
        output = stream.read()
        csr = csr_filepath.split("/")
        csrfilename = csr[len(csr) - 1]
        certfilename = csrfilename.replace(".csr", ".crt")

        certfilename = os.path.join(dataFilePath, certfilename)
        csrfilename = str(csrfilename)
        csr_filepath = csr_filepath.replace(" ", "\ ")
        certfilename = certfilename.replace(" ", "\ ")
        csr_filepath = csr_filepath.replace("(", "\(")
        csr_filepath = csr_filepath.replace("(", "\)")
        certfilename = certfilename.replace("(", "\(")
        certfilename = certfilename.replace(")", "\)")

        cmd3 = "openssl x509 -req -in " + csr_filepath + " -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out " + certfilename + " -days 500 -passin pass:" + iLOPassword
        stream = os.popen(cmd3)
        output = stream.read()

    except Exception as e:
        logging.error(f"Exception while generating certificate {e}.")
        retVal = 1

    return retVal

def FetchSubjectDetails():
    sub_data = None
    iv = None
    retval = 0
    subjectFilePath = os.path.join(os.path.dirname(os.path.abspath(__file__)),"..","..","data","SSL_Certificate.json")

    try:
        with open(subjectFilePath,'r') as sub_file:
            sub_data = json.load(sub_file)
            country = sub_data['Country']
            state = sub_data['State']
            city = sub_data['City']
            orgName =  sub_data['OrgName']
            orgUnit = sub_data['OrgUnit']
            includeIP = bool(sub_data['IncludeIP'])
    except Exception as e:
        logging.info("Error in Json file extraction. Error: %s" % e)
        retval = 1
    return (country,state,city,orgName,orgUnit,includeIP)


def EnableEncryption(iLOHost):
    retVal = 0

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION


    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    
    try:
        serviceRoot = MakeRestRequest((ServiceRootURL % iLOHost),"GET",headers,"")
        if float(serviceRoot[0]['Oem']['Hpe']['Manager'][0]['ManagerFirmwareVersion'])<2.55:
            logging.info("iLO firmware is not at the required version. The supported version is 2.55 or later")
            retval=1
            return retval
        else:
            logging.info("Valid Firmware Version - %s, Proceeding to enable Encryption" %(serviceRoot[0]['Oem']['Hpe']['Manager'][0]['ManagerFirmwareVersion']))
        
        payload = {
            "EncryptionConfiguration": "ExpressLocal",
            "EncryptionEULA": "Accept"
            }
        Res = MakeRestRequest( (EncryptionURL % iLOHost),"PATCH",headers,payload)

    except Exception as e:
        logging.error("Exception in Enabling Encryption in SmartArray Controller.")
        retVal = 1

    return retVal      

def EnableVirtualNic(iLOHost):

    retVal = 0

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION


    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    
    try:
        
        VnBody = {
                "Oem": {
                "Hpe": {
                "VirtualNICEnabled": True
                }
            }            
        }    
        vnRes = MakeRestRequest( (VirtualNicURL % iLOHost),"PATCH",headers,VnBody)


    except Exception as e:
        logging.error("Exception in Enabling the Virtual NIC.")
        retVal = 1

    return retVal

def DisableVirtualNic(iLOHost):

    retVal = 0

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION


    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    
    try:
        
        VnBody = {
                "Oem": {
                "Hpe": {
                "VirtualNICEnabled": False
                }
            }            
        }    
        vnRes = MakeRestRequest( (VirtualNicURL % iLOHost),"PATCH",headers,VnBody)


    except Exception as e:
        logging.error("Exception in Disabling the Virtual NIC.")
        retVal = 1

    return retVal

def Enable1GBNic(iLOHost,PCIslot):

    retVal = 0

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION


    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    
    try:
        
        nicBody = {
                "Attributes": {
                PCIslot: "Auto"
                }
            }            
        nicRes = MakeRestRequest( (hostNicURL % iLOHost),"PATCH",headers,nicBody)


    except Exception as e:
        logging.error("Exception in Enabling the 1 GB NIC.")
        retVal = 1

    return retVal

def Disable1GBNic(iLOHost,PCIslot):

    retVal = 0

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION


    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    
    try:
        
        nicBody = {
                "Attributes": {
                PCIslot: "Disabled"
                }
            }            
        nicRes = MakeRestRequest( (hostNicURL % iLOHost),"PATCH",headers,nicBody)


    except Exception as e:
        logging.error("Exception in Disabling the 1 GB NIC.")
        retVal = 1

    return retVal

def queryPCIslot(iLOHost):
    retVal = 0
    flag = 0
    i = 1
    PCIslot = ""

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION


    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    while 1:
        iss=str(i)
        response = MakeRestRequest((NicURL % (iLOHost,iss)),"GET",headers,"")
        ress = response[0]
        i = i+1
        try:
            if (ress)['error']['@Message.ExtendedInfo'][0]['MessageId'] == 'Base.1.4.ResourceMissingAtURI':
                break
        except Exception as e:
            pass
        nic_name = ress['Name']
        try:
            uefiPath = ress['UEFIDevicePath']
        except Exception as e:
            continue
        response0 = MakeRestRequest((ServiceRootURL % iLOHost),"GET",headers,"")
        if re.search( "Gen10 Plus", response0[0]['Product'] ):
            response1 = MakeRestRequest((BiosMapURLgen10P % iLOHost),"GET",headers,"")
        else:
            response1 = MakeRestRequest((BiosMapURL % iLOHost),"GET",headers,"")
        ress1 = response1[0]
        try:
            if (ress1)['error']['@Message.ExtendedInfo'][0]['MessageId'] == 'Base.1.4.ResourceMissingAtURI':
                break
        except Exception as e:
            pass
        biosMap = ress1['BiosPciSettingsMappings']
        count = len(biosMap)
        for i1 in range(0,count):
            if uefiPath == biosMap[i1]['CorrelatableID']:
                PCIslot = biosMap[i1]['Associations'][0]
            elif len(biosMap[i1]['Subinstances']) != 0:
                for i2 in range(0,len(biosMap[i1]['Subinstances'])):
                    if uefiPath == biosMap[i1]['Subinstances'][i2]['CorrelatableID']:
                        PCIslot = biosMap[i1]['Associations'][0]
        logging.info(nic_name," ",PCIslot)
        
    return retVal


def check4InvalidSession(iLOHost):
    # Check for valid session
    bInvalidSession = False
    try:
        if (len(authCodeMap) == 0) or (authCodeMap[iLOHost] == None):  
            bInvalidSession = True
    except Exception as expObj:        
        bInvalidSession = True
        
    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
    return bInvalidSession 
    

def BootVolumeCreation(iLOHost,volName,raidLevel):

    retVal = 0
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION


    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    

    try:
        volBody = {    
            "LogicalDrives": [
                {
                    "Accelerator": "ControllerCache",            
                    "CapacityGiB": 558,
                    "DataDrives": [
                        "1I:1:1",
                        "1I:1:2"
                    ],            
                    "LogicalDriveName": volName,            
                    "Raid": raidLevel,            
                    "StripSizeBytes": 262144
                }
            ]
        }
        
        volRes = MakeRestRequest( (logicalDriveURL % iLOHost),"PUT",headers,volBody)

    except Exception as e:
        logging.info(f"Exception in creating logical drive for volume {volName}. Exception: {e}.")
        retVal = 1

    return retVal

  

def MakeRestRequest(URL, type, headers, body):
    res = None
    hdr = None
    try:
        logging.debug(f"Request URL: {URL} headers: {headers} body: {body} HttpType: {type}")
        rslt = requests.request(type, URL, headers=headers, data=json.dumps(body), verify=False, timeout=5)
        hdr = rslt.headers

        if (hdr['Content-Type'].startswith("text/xml")):
            res = rslt.text
        else:
            res = rslt.json()

        if str(rslt.status_code).startswith("2") == False:
            error = "Unable to complete the request"
            logging.error(f"Error Response {res}.")
            raise Exception(f"Error Response: {res['error']['@Message.ExtendedInfo']}")
          
    except Exception as e:
        logging.debug(f"Connection error while trying to fire the http request for {URL}. Exception: {e}.")
        raise

    return res, hdr

def DiscoverHosts_ports(discover_obj,rack_key):

    swDet = discover_obj.get_switch_ip()
    swUN = discover_obj.get_switch_username()
    swPwd = discover_obj.get_switch_password()
    swCmd = discover_obj.get_switch_cmd()
    srchStr = discover_obj.get_search_string()
    dlmt = discover_obj.GetSwcDlmter()
    footer = discover_obj.get_switch_footer()
    fieldNo = discover_obj.GetMACFieldNo()
    BMCvlanID = discover_obj.get_bmc_vlan_id()
    ipv6_interface = discover_obj.get_ipv6_interface()

    logging.info(ipv6_interface)

    retVal = 0
    bNumber = 0
    ipv6data = {}
    sshRef = ssh_connect(swDet,swUN,swPwd)
    if sshRef == None:
        logging.error(f"SSH Connection to the switch: {swDet} failed.")
    output = ssh_run_command(sshRef,swCmd)

    portsFilePath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "oobmConfig.json")
    ipv6List = {}
    chasisBayList = []
    try:
        with open(portsFilePath,'r') as port_file:
            port_data = json.load(port_file)

    except Exception as e:
        retVal = 1
        logging.info(f"Error loading server_switch_ports JSON {portsFilePath}. oobmConfig.json file not found in the data folder. Exception: {e}.")
        return retVal, ipv6List, chasisBayList

    for port in port_data[rack_key]:
        if (('uplinkType' in port and port['uplinkType'] == "ilo") and str(BMCvlanID) == port['vlan'] and ('type' in port and port['type'] == 'access')):                 
            swCmd = "show mac-address-table port {}".format(port['port'])
            output = ssh_run_command(sshRef,swCmd)
            rsltList = extract_data(srchStr,footer,fieldNo,output)
            if re.search("svr", port['description']):
                server = port['description'].split('-')[2].replace('svr', 'server-')
            elif re.search("chs", port['description']):
                serverl = port['description'].split('-')[2].replace('chs', 'chas-')
                bNumber = port['description'].split('-')[4]
                server = serverl + '-%s' % (bNumber)
            chList = []
            
            if len(rsltList)>1:
                count = 1
                for rslt in rsltList:
                    chList.append(rslt)
                    ipv6addr = DeduceLinkLocal_ports(chList,ipv6_interface)
                    logging.info(ipv6addr)
                    ipv6List["chas-001-%s" %(count)]=ipv6addr
                    count +=1
            else : 
                ipv6addr = DeduceLinkLocal_ports(rsltList,ipv6_interface)
                if ipv6addr is not None:
                    ipv6List[server]=ipv6addr
            chasisBayList.append(bNumber)
            logging.info(ipv6List)
    if (sshRef):
        sshRef.close()
    return retVal, ipv6List ,chasisBayList

def discover_ilo_by_port(discover_obj, rack_key):
    """
    Discover server iLO by connection to switch ports identified by generated oobmConfig.json file
    converting MAC address seen on port to link-local IPv6 address for iLO
    Args:
        discover_obj: object of type DiscoverHostsObj with switch information from SCID
        rack_key: rack key to oobm configuration information extracted from oobmConfig.json file
    Returns:
        dictionary of link-local IPv6 addresses using iLO hostname as key
    """

    switch_ip = discover_obj.get_switch_ip()
    switch_username = discover_obj.get_switch_username()
    switch_password = discover_obj.get_switch_password()
    search_string = discover_obj.get_search_string()
    switch_footer = discover_obj.get_switch_footer()
    mac_field_number = discover_obj.get_MAC_field_number()
    bmc_vlan_id = discover_obj.get_bmc_vlan_id()
    ipv6_interface = discover_obj.get_ipv6_interface()
    
    link_local_ipv6_addresses = {}
    ssh_ref = ssh_connect(switch_ip, switch_username, switch_password)
    if ssh_ref is None:
        logging.error(f"SSH connection to switch at IP address {switch_ip} failed")
        return link_local_ipv6_addresses

    oobmconfig_filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       "..", "..", "data", "oobmConfig.json")
    try:
        with open(oobmconfig_filepath, 'r') as port_file:
            port_data = json.load(port_file)

    except Exception as e:
        logging.exception(f"Error loading {oobmconfig_filepath} file. Error: {e}")
        if ssh_ref:
            ssh_ref.close()
        return link_local_ipv6_addresses

    logging.debug(f"Rack key: {rack_key}")
    logging.debug(f"oobmConfig for {rack_key}: {port_data[rack_key]}")

    try:
        for port in port_data[rack_key]:
            logging.debug(f"port['description']: {port['description']}")
            if ('uplinkType' in port and port['uplinkType'] == "ilo")\
                    and str(bmc_vlan_id) == port['vlan']\
                    and ('type' in port and port['type'] == 'access'):
                switch_cmd = discover_obj.get_switch_cmd().format(port_number=port['port'])
                logging.debug(f"In discover_ilo_by_port - checking mac address table with command: {switch_cmd}")
                output = ssh_run_command(ssh_ref, switch_cmd)
                port_mac_address = extract_data(search_string, switch_footer, mac_field_number, output)
                logging.debug(f"server: {port['port']}")

                if len(port_mac_address) == 1:
                    ipv6addr = deduce_link_local_port(port_mac_address[0], ipv6_interface)
                    if ipv6addr:
                        try:
                            res, hdr = MakeRestRequest((XMLDataURL % ipv6addr), "GET", "", "")
                            logging.debug(f"Discovered iLO for host: {port['description']}"
                                          f" connected to port {port['port']}")
                            link_local_ipv6_addresses[port['description']] = ipv6addr
                        except Exception as e:
                            logging.exception(f"iLO host: {port['description']} connected to port {port['port']}"
                                              f" not responding to iLO query. Error: {e}")
                else:
                    logging.info(f"Expected one iLO MAC address for host: {port['description']}"
                                 f" connected to port {port['port']}")
                    logging.info(f"Discovered {len(port_mac_address)} MAC addresses - Check that cabling is correct")
    except Exception as e:
        logging.exception(f"Error discovering iLO by port. Exception: {e}.")

    if ssh_ref:
        ssh_ref.close()

    return link_local_ipv6_addresses


def Convert2iLOFormat(timeZone,formatVal):
    tz_data = None
    tz = None

    tzFilePath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "timezoneFormat.json")

    try:
        with open(tzFilePath,'r') as tz_file:
            tz_data = json.load(tz_file)

        exp = parse('$.utcList[?(@.UTC =="'+timeZone+'")]')
        tzVal  = exp.find(tz_data)
        
        tz = tzVal[0].value[formatVal]

    except Exception as e:
        logging.error(f"Error loading Timezone JSON {tzFilePath}. Exception: {e}.")

    return tz

def ssh_connect(hostname, username, password):
    port = 22
    ssh_host = paramiko.SSHClient()
    ssh_host.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh_host.connect(hostname=hostname, port=port, username=username, password=password)
     
    except paramiko.ssh_exception.AuthenticationException as e:
        ssh_host = None
        logging.exception(f"Error authenticating SSH connection for {username}@{hostname}:{port}. Error: {e}")
    except paramiko.BadAuthenticationType as e:
        ssh_host = None
        logging.exception(f"Error authenticating SSH connection for {username}@{hostname}:{port}. Error: {e}")
    except Exception as e:
        ssh_host = None
        logging.exception(f"Error with SSH connection for {username}@{hostname}:{port}. Error: {e}")
    return ssh_host


def ssh_run_command(ssh_ref, cmd):
    lines = []
    try:
        stdin, stdout, stderr = ssh_ref.exec_command(cmd)
        
        for line in iter(stdout):
            lines.append(line)
    except Exception as e:
        logging.exception(f"Error running command {cmd} with SSH. Exception: {e}.")
        lines = None
        
    return lines


def extract_data(header, footer, field_number, data):
    header_found = 0
    extracted_data = []
    
    for line in iter(data):
        if (header_found == 0) and (str(line).find(header) != -1):
            header_found = 1
        elif header_found == 1:    
            if len(footer) > 0 and str(line).find(footer) != -1:
                break
            fields = line.split()
            extracted_data.append((fields[field_number]).strip())

    return extracted_data           

def DeduceLinkLocal_ports(list,ipv6Dev):
    newList=None
    for mac in list:
        temp = mac2eui64(mac)

        if (ipv6Dev):
            ipv6 = "[fe80::"+temp+"%"+ipv6Dev+"]"
        else:
            ipv6 = "[fe80::"+temp+"]"
        newList = ipv6
    return newList

def deduce_link_local_port(mac, ipv6_dev):
    """
    Convert MAC address to link-local IPv6 address
    Args:
        mac: MAC address to be converted to link-local IPv6 address
        ipv6_dev: interface for link-local IPv6 address on Linux
                  on Windows this is an empty string as not needed
    Returns:
        link-local IPv6 address associated with MAC address
    """

    link_local_ipv6_address = None
    logging.info(f"In deduce_link_local_port with MAC address: {mac}")
    temp = mac2eui64(mac)

    if ipv6_dev:
        link_local_ipv6_address = "[fe80::"+temp+"%"+ipv6_dev+"]"
    else:
        link_local_ipv6_address = "[fe80::"+temp+"]"

    return link_local_ipv6_address


def Convert2LinkLocal(mac,dlmt):
    # only accept MACs separated by a colon
    fields = mac.split(dlmt)
    parts = []

    indx = 0
    for field in fields:        
        parts.insert(indx,(field)[0:2])
        parts.insert(indx+1,(field)[2:4])
        indx += 2

    # modify parts to match IPv6 value
    parts.insert(3, "ff")
    parts.insert(4, "fe")
    parts[0] = parts[0] = "%x" % (int(parts[0], 16) ^ 2)

    # format output
    ipv6Parts = []
    for i in range(0, len(parts), 2):
        ipv6Parts.append("".join(parts[i:i+2]))
    ipv6 = "[fe80::%s]" % (":".join(ipv6Parts))
    return ipv6   


def mac2eui64(mac, prefix=None):

    eui64 = re.sub(r'[.:-]', '', mac).lower()
    eui64 = eui64[0:6] + 'fffe' + eui64[6:]
    eui64 = hex(int(eui64[0:2], 16) ^ 2)[2:].zfill(2) + eui64[2:]

    if prefix is None:
        return ':'.join(re.findall(r'.{4}', eui64))
    else:
        try:
            net = ipaddress.ip_network(prefix, strict=False)
            euil = int('0x{0}'.format(eui64), 16)

            return str(net[euil])

        except Exception as e:
            logging.exception(f"Error converting MAC Address to EUI-64 format. Exception: {e}.")

            return    


def UpdateServerInfo(iLOHost,ServerName,ServerAssetTag,AssetTagProtection,ServerPrimaryOs,ServerOtherInfo):
    retVal = 0
    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.info("Ensure valid iLO session is there for the host %s" % iLOHost)
        return ERROR_INVALID_SESSION
    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    svrInfo = {}
    try:
        Res = MakeRestRequest( (iLOTimeZoneURL % iLOHost),"GET",headers,svrInfo)
        svrInfo = {
                "Attributes": {
                "ServerName": ServerName,
                "ServerAssetTag": ServerAssetTag,
                "AssetTagProtection": AssetTagProtection,
                "ServerPrimaryOs": ServerPrimaryOs,
                "ServerOtherInfo": ServerOtherInfo
            }
        }
        Res = MakeRestRequest( (iLOTimeZoneURL % iLOHost),"PATCH",headers,svrInfo)
    except Exception as e:
        logging.info(f"Exception in setting the server info. Exception: {e}. ")
        retVal = 1
    return retVal


def genITtag(host, userName, password):

    try:

        retVal = 0
        ilogen = None

        loginRetVal = ILOLogin(host,userName,password)
        if loginRetVal:
            logging.error("ILO login failure with the host %s" %host)
            retVal = 1
        else:
            logging.info("ILO login to %s" %host)

            ilogen = GetiLOGen(host)

            # Collect server information to determine Instance Type
            headers = {
                'content-type': "application/json",
                'X-Auth-Token': authCodeMap[host] 
            }

            compRes = MakeRestRequest((computerSystem1URL % host),"GET",headers,"")

            TotSysMemGB = compRes[0]['MemorySummary']['TotalSystemMemoryGiB']
            sysMod = compRes[0]['Model']
            NumCPU = compRes[0]['ProcessorSummary']['Count']

            # calculate number of vCPUs as total of hyperthreads for all processors
            vCPUs = 0
            cnt = 1
            while cnt <= NumCPU:
                procRes = MakeRestRequest((processorURL %(host, cnt)),"GET",headers,"")
                vCPUs += procRes[0]['TotalThreads']
                cnt += 1

            # Calculate ratio of vCPUs to Memory to determine Instance Type
            memToCPUratio = TotSysMemGB // vCPUs
            logging.info("Memory to vCPU ratio is %s:1" %memToCPUratio)

            # Check for GPU, Mellanox, and Pensando PCI devices
            hasMellanox = False
            hasPensando = False
            hasGPU = False
            GPUdict = dict()
            GPUmodelDict = dict()
            GPUmodelDict = {4766:'RTX8000', 4794:'RTX6000', 7605:'V100', 7857:'RTX4000', 7864:'T4'}
            if ilogen == '4':
                pciRes = MakeRestRequest((pciDevicesURL % host),"GET",headers,"")
                numPCIDevices = pciRes[0]['Members@odata.count']

                cnt = 1
                while cnt <= numPCIDevices:
                    pciRes = MakeRestRequest((pciMemberDevicesURL %(host, cnt)),"GET",headers,"")
                    if 'VendorID' in pciRes[0]:
                        if pciRes[0]['VendorID'] == 5555:
                            hasMellanox = True
                        elif pciRes[0]['VendorID'] == 7640:
                            hasPensando = True
                        elif pciRes[0]['VendorID'] == 4318:
                            hasGPU = True
                            model = ''
                            deviceID = 0
                            if 'DeviceID' in pciRes[0]:
                                logging.info("GPU device ID: %s" %pciRes[0]['DeviceID'])
                                if pciRes[0]['DeviceID'] == 7728:
                                    if 'SubsystemDeviceID' in pciRes[0]:
                                        logging.info("GPU Subsystem device ID: %s" %pciRes[0]['SubsystemDeviceID'])
                                        deviceID = pciRes[0]['SubsystemDeviceID']
                                else:
                                    deviceID = pciRes[0]['DeviceID']
                            if deviceID in GPUmodelDict:
                                model = GPUmodelDict[deviceID]
                            if model:
                                if model not in GPUdict:
                                    GPUdict[model] = 1
                                else:
                                    GPUdict[model] = GPUdict[model] + 1
                    cnt += 1
            elif ilogen == '5':
                chassisDevRes = MakeRestRequest((chassis1DevicesURL % host),"GET",headers,"")
                numChassisDevices = chassisDevRes[0]['Members@odata.count']

                cnt = 1
                while cnt <= numChassisDevices:
                    devRes = MakeRestRequest((chassisMemberDevicesURL %(host, cnt)),"GET",headers,"")
                    if devRes[0]['DeviceType'] == 'LOM/NIC':
                        if devRes[0]['Manufacturer'] == 'Mellanox':
                            hasMellanox = True
                        elif 'Pensando' in devRes[0]['Name']:
                            hasPensando = True
                    elif devRes[0]['DeviceType'] == 'GPU' and devRes[0]['Status']['State'] == 'Enabled':
                        hasGPU = True
                        gpuMod = devRes[0]['Name']
                        modelWords = gpuMod.split()
                        if len(modelWords) >= 3:
                            model = modelWords[2]
                            if model == 'RTX' and len(modelWords) > 3:
                                model += modelWords[3]
                            if model not in GPUdict:
                                GPUdict[model] = 1
                            else:
                                GPUdict[model] = GPUdict[model] + 1
                    cnt += 1

            if hasMellanox:
                logging.info("Server has Mellanox PCI device.")
            if hasPensando:
                logging.info("Server has Pensando PCI device.")
            if hasGPU:
                logging.info("Server has GPU.")

            logging.info(f"genNstampIT() found NumCPU: {NumCPU}, vCPUs: {vCPUs}, and TotalSystemMemory: {TotSysMemGB} in {sysMod}.")

            # parse Model to generate server component of Element Platform Element Module name
            words = sysMod.split()
            instanceType = ''
            if words[0] == 'ProLiant':
                if words[1].startswith("XL"):
                    instanceType = "A"
                elif words[1].startswith("DL"):
                    instanceType = "D"
                elif words[1].startswith("e") or words[1].startswith("m"):
                    instanceType = "E"
            elif words[0] == 'Synergy':
                instanceType = "S"

            if instanceType:
                instanceType += re.sub("[a-zA-Z]","",words[1])
                if not (instanceType.startswith("E")):
                    instanceType += "G" + words[2][3:]
                    if len(words) > 3:
                        if words[3] == "Plus":
                            instanceType += "+"
                if memToCPUratio <= 2:
                    instanceType += "co"
                elif memToCPUratio <= 4:
                    instanceType += "b"
                else:
                    instanceType += "mo"

                if hasGPU and len(GPUdict) == 1:
                    instanceType += "v"

                if hasMellanox or hasPensando:
                    instanceType += "-"
                    if hasMellanox:
                        instanceType += "m"
                    if hasPensando:
                        instanceType += "p"

                if hasGPU:
                    if len(GPUdict) == 0:
                        logging.info("No supported GPUs enabled.")
                    elif len(GPUdict) == 1:
                        GPUdictKey = list(GPUdict.keys())[0]
                        instanceType += "-" + GPUdictKey
                        if GPUdict[GPUdictKey] > 1:
                            instanceType += "." + str(GPUdict[GPUdictKey])
                    else:
                        logging.info("More than one GPU model.")
            else:
                logging.error("Not a valid iMRA server type.")

            # write Element Instance Type to BIOS
            logging.info("Instance Type is %s" %instanceType)
            if ilogen == '4':
                BIOSsettingsBody = {
                    "ServerOtherInfo": instanceType
                }
            elif ilogen == '5':
                BIOSsettingsBody = {
                    "Attributes": {
                    "ServerOtherInfo": instanceType
                    }
                }

            MakeRestRequest( (BIOSsettingsURL % host),"PATCH", headers, BIOSsettingsBody)

            logoffRetVal = ILOLogoff(host)
            if logoffRetVal:
                logging.error(f"ILO logoff failure with the host {host}.")
                retVal = 1
            else:
                logging.info(f"Successfully logged off {host}.")


    except Exception as e:
        logging.info(f"Generate Instance Type and BIOS tag failed. Exception: {e}.")
        retVal = 1

    return retVal
    
def ResetFactoryDefaults(iLOHost):
    
    retVal = 0

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:        
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION


    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    
    try:                
        resetBody = {
            "ResetType": "Default"
        }
               
        resetRes = MakeRestRequest( (iLOFactoryDefaultsURL % iLOHost),"POST",headers,resetBody)

    except Exception as e:        
        logging.error(f"Exception in resetting to factory defaults. Exception: {e}.")
        retVal = 1

    return retVal

def DisableTPM(iLOHost):    
    retVal = 0
    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(iLOHost)
    if bInvalidSession:        
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    try: 
        biosRes = MakeRestRequest((BIOSsettingsURL % iLOHost),"GET",headers,"")
        tpmState = biosRes[0]['Attributes']['TpmState']
        tpmType = biosRes[0]['Attributes']['TpmType']
        
        if tpmState == "NotPresent":
            logging.error(f"TPM Module is not present for the host {iLOHost}.")
            return 1

        if tpmState == "PresentDisabled" and tpmType == "Tpm20":
            logging.info(f"TPM 2.0 Module is already present and disabled for the host {iLOHost}.")
            return 0
        BIOSsettingsBody = {
            "Attributes": {  
                "TpmModeSwitchOperation": "Tpm20",
                "TpmVisibility": "Hidden"
            }
        }
                        
        MakeRestRequest( (BIOSsettingsURL % iLOHost),"PATCH",headers,BIOSsettingsBody)

    except Exception as e:        
        logging.error(f"Exception in enabling TPM. Exception: {e}.")

        retVal = 1

    return retVal
    
def validateDHCPv4(iLOHost):
    retVal = 0
    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }

    try:
        logging.info("Validating enable DHCP API")
        serviceRoot = MakeRestRequest((DedicatediLONetworkURL % iLOHost),"GET",headers,"")
        if serviceRoot[0]['DHCPv4']['DHCPEnabled']:
            logging.info("DHCP is enabled.")
            retVal = 0
        else:
            logging.info("DHCP is disabled.")
            retVal = 1
    except Exception as e:
        logging.error(f"Exception in enabling DHCP. Exception: {e}.")
        retVal = 1
    return retVal

def EnableTPM(iLOHost):
    
    retVal = 0

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:        
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION


    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    
    try: 

        biosRes = MakeRestRequest((BIOSsettingsURL % iLOHost),"GET",headers,"")
        tpmState = biosRes[0]['Attributes']['TpmState']
        if tpmState == "NotPresent":
            logging.info(f"TPM Module is not present for the host {iLOHost}.")
            return 1
               
        if tpmState == "PresentEnabled":
            logging.info(f"TPM 2.0 Module is already enabled for the host {iLOHost}.")
            return 0
        BIOSsettingsBody = {
            "Attributes": {  
                "TpmState": "PresentEnabled",
                "TpmVisibility": "Visible"
            }
        }

        MakeRestRequest( (BIOSsettingsURL % iLOHost),"PATCH",headers,BIOSsettingsBody)

    except Exception as e:        
        logging.error(f"Exception in enabling TPM. Exception: {e}.")
        retVal = 1

    return retVal

def EnableSecureBoot(iLOHost):
    retVal = 0
    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }

    try:
        secureBoot = MakeRestRequest((SecureBootURL % iLOHost),"GET",headers,"")
        if secureBoot[0]['SecureBootEnable']:
            logging.info(f"Secure Boot is already enabled for the host {iLOHost}.")
            logging.info("Secure boot is %s" %secureBoot[0]['SecureBootEnable'])
            return 0
        secureBootBody = {
            "SecureBootEnable": True
        }
        MakeRestRequest( (SecureBootURL % iLOHost),"PATCH",headers,secureBootBody)
        secureBoot = MakeRestRequest((SecureBootURL % iLOHost),"GET",headers,"")
        if not secureBoot[0]['SecureBootEnable']:
            logging.info(f"Failed to enable Secure Boot for the host {iLOHost}.")
            retVal = 1
    except Exception as e:
        logging.error(f"Exception in enabling Secure Boot. Exception: {e}.")
        retVal = 1

    return retVal

def DisableSecureBoot(iLOHost):
    retVal = 0
    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }

    try:
        secureBoot = MakeRestRequest((SecureBootURL % iLOHost),"GET",headers,"")
        if not secureBoot[0]['SecureBootEnable']:
            logging.info(f"Secure Boot is already disabled for the host {iLOHost}.")
            return 0
        secureBootBody = {
            "SecureBootEnable": False
        }
        MakeRestRequest( (SecureBootURL % iLOHost),"PATCH",headers,secureBootBody)
    except Exception as e:
        logging.error(f"Exception in disabling Secure Boot. Exception: {e}.")
        retVal = 1

    return retVal

def flashDIMELicensefile(host,filepath):
    retVal = 0
    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(host)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {host}.")

        return ERROR_INVALID_SESSION

    try:
        if (filepath != None):
            dime_filepath = filepath
        else:
            logging.error("Provide valid file path.")
            exit(-1)

        headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[host]
        }
        serviceRoot = MakeRestRequest((ServiceRootURL % host),"GET",headers,"")

        iLOversion= GetiLOGen(host)
        logging.info(f"iLO{iLOversion} found on server {host}.")

        if iLOversion == 5: 
            if float(serviceRoot[0]['Oem']['Hpe']['Manager'][0]['ManagerFirmwareVersion'])<2.55:
                logging.info("iLO firmware is not at the required version. The supported version is 2.55 or later")
                retval=1
                return retval
        else:
            logging.info("Valid Firmware Version,Proceeding to enable HPETOS.")
        logging.info(serviceRoot[0]['Oem']['Hpe']['Manager'][0]['ManagerFirmwareVersion'])

        iLOFlashUpdateBody = {"ImageURI":dime_filepath}

        MakeRestRequest((flashDIMELicensefile1 % host),"POST",headers,iLOFlashUpdateBody)
        
        logging.info("iLO is going for an automatic reset.")
        time.sleep(40)
        
    except Exception as e:
        logging.error(f"Exception in in Updating a flash file {host}. Exception: {e}.")
        retVal = 1
    return retVal 

def validateDIMELicense(host):
    svrmodel = None
    returnval=0
    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(host)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {host}.")
        return ERROR_INVALID_SESSION

    try:
        headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[host]
        }

        res = MakeRestRequest((validateDIMELicense1 % host),"GET",headers,"")
        logging.info(res)
        if res[0]['Description']!="iLO Trusted OS Security Modules Collection":
            returnval=1
    except Exception as e:
        returnval=1
        logging.error(f"Exception in retrieving the server model {host}. Exception: {e}.")

    return returnval

### get status of Virtual Media (CD, DVD)
def VirtualMediaStatus(host):

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(host)

    if bInvalidSession:
        logging.error("Ensure valid iLO session is there for the host %s." % host)
        return ERROR_INVALID_SESSION

    statusVirtualMedia= None

    try:
        headers = {
            'content-type': "application/json",
            'X-Auth-Token': authCodeMap[host]
        }   

        virtualMediainsertstatus= MakeRestRequest((virtualMediaURL % host),"GET", headers,"")
        
        if (virtualMediainsertstatus [0] ['Inserted'] == False):
            logging.info(f"No virtual media image inserted on server/host {host}.")
            statusVirtualMedia= False

        else:
            logging.info(f"Virtual media image is inserted on server/host {host}.")
            statusVirtualMedia= True

    except Exception as e:
        logging.error(f"Exception in verifying virtual media status from server/host {host}. Exception: {e}.")
        
    return statusVirtualMedia 

### Insert Virtual Media (CD, DVD)
def MountVirtualMedia(iLOHost, image, boot = True):
    
    retVal = 0

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    
    try:     

        baseUrl = virtualMediaURL % iLOHost

        #unmount virtual media
        url = baseUrl + "/Actions/VirtualMedia.EjectMedia" 
        body = ""
        res = MakeRestRequest(url, "POST", headers, body)                  
        
        #mount virtual media
        url = baseUrl + "/Actions/VirtualMedia.InsertMedia" 
        body = { "Image": image}
        res = MakeRestRequest(url, "POST", headers, body)    
        
        #set BootOnNextServerReset if needed
        if boot:
            url = baseUrl
            body = {
                "Oem": {
                    "Hpe": {
                        "BootOnNextServerReset": True
                    }
                }     
            }
            res = MakeRestRequest(url, "PATCH", headers, body)       
            
    except Exception as e:        
        logging.error(f"Exception in mounting virtual media. Exception: {e}.")
        retVal = 1

    return retVal

# Follow similar format in S-Validate attributes.json (Command, Instructions) 
# to get attribute value via iLO REST API
def GetAttribute(iLOHost, command, instructions):
    
    retVal = None

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:        
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    
    try:     

        url = "https://%s" % iLOHost + command
        
        body = ""
        res = MakeRestRequest(url, "GET", headers, body)                          
        
        fields = instructions.split(".")        
        retVal = res[0]
        for f in fields[:len(fields)-1]:
            if f in retVal:
                retVal = retVal[f]
            else:
                return None
        
        key = fields[-1]
        if key in retVal:
            retVal = retVal[key]
        else:
            return None
        
    except Exception as e:        
        logging.error(f"Exception in getting attribute {command} with instruction {instructions}. Exception: {e}.")

    return retVal

def OneButtonSecureErase(iLOHost):

    retVal = 0

    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION


    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }

    try:
        resetBody = {
            "SystemROMAndiLOErase": True,
            "UserDataErase": True
        }

        resetRes = MakeRestRequest( (iLOSecureEraseURL % iLOHost),"POST",headers,resetBody)

    except Exception as e:
        logging.error(f"Exception in One-button secure erase. Exception: {e}.")
        retVal = 1

    return retVal


def RestoreDefaultManufacturingSettings(iLOHost):
    retVal = 0
    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    try:
        
        logging.info("Restoring Manufacturing defaults for host %s." % iLOHost)
        response0 = MakeRestRequest((BIOSsettingsURL % iLOHost),"GET",headers,"")
        response0[0]['Attributes']['RestoreManufacturingDefaults'] = "Yes"

        response = MakeRestRequest((BIOSsettingsURL % iLOHost),"PATCH",headers,response0[0])
            
    except Exception as e:
        logging.error(f"Exception in setting iLO security. Exception: {e}.")
        retVal = 1

    return retVal

def iLOSecurityState(iLOHost,security_state):
    retVal = 0
    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    try:
        response = MakeRestRequest((SecurityStateURL % iLOHost),"GET",headers,"")
        if response[0]["SecurityState"] == security_state:
            logging.info("Security State is already in the requested state %s" %(security_state))
        elif response[0]["SecurityState"] == "FIPS":
            logging.error("Transition from current security state %s to %s is not allowed on %s.\
                To disable the FIPS security state,set iLO to the factory default settings." %(response[0]["SecurityState"],security_state,iLOHost))
            retVal = 1
        else:
            logging.info("Setting Security state to %s for host %s" %(security_state,iLOHost))
            payload = {
                "SecurityState": security_state
                }
            MakeRestRequest((SecurityStateURL % iLOHost),"PATCH",headers,payload)
    except Exception as e:
        logging.error(f"Exception in setting iLO security. Exception: {e}.")
        retVal = 1

    return retVal

def iLO_enable_RequireHostAuthentication(iLOHost):
    retVal = 0
    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    try:
        logging.info(f"Enabling Require Host Authentication for host {iLOHost}.")
        payload = {
            "Oem": {
                "Hpe": {
                    "RequireHostAuthentication": True,
                    }
                }
            }
        MakeRestRequest((ManagerURL % iLOHost),"PATCH",headers,payload)
    except Exception as e:
        logging.error(f"Exception in enabling iLO RequireHostAuthentication. Exception: {e}.")
        retVal = 1

    return retVal

def iLO_disable_RequireHostAuthentication(iLOHost):
    retVal = 0
    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    try:
        logging.info(f"Disabling Require Host Authentication for host {iLOHost}.")
        payload = {
            "Oem": {
                "Hpe": {
                    "RequireHostAuthentication": False,
                    }
                }
            }
        MakeRestRequest((ManagerURL % iLOHost),"PATCH",headers,payload)
    except Exception as e:
        logging.error(f"Exception in disabling iLO RequireHostAuthentication. Exception: {e}.")
        retVal = 1

    return retVal

def UEFIsecuritySettings(iLOHost):
    """
    This task will configure UEFI security settings in the iLO. Upon successful response the server has to be rebooted and call the SystemReset API to reboot subsequent to this.
    :param iLOHost: The ip address of the iLO
    """
    retVal = 0
    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    try:
        logging.info(f"Enabling UEFI Optimized boot and UEFI Option ROM measurement for host {iLOHost}.")
        payload = {
            "Attributes": {
                "UefiOptimizedBoot": "Enabled",
                "TpmUefiOpromMeasuring": "Enabled"
            }
        }
        MakeRestRequest((BIOSsettingsURL % iLOHost), "PATCH", headers, payload)

    except Exception as e:
        logging.error(f"Exception in configuring UEFI security settings. Exception: {e}.")
        retVal = 1

    return retVal

def ConfigureiLOSerialPort(iLOHost,serialPort):
    """
    This task will configure Virtual Serial Port in the iLO. Upon successful response the server has to be rebooted and call the SystemReset API to reboot subsequent to this.
    :param iLOHost: The ip address of the iLO
    :param serialPort: Enable or Disable the virtual serial port
    """
    retVal = 0
    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    try:
        if serialPort == "Disable":
            payload = {
                "Attributes": {
                    "VirtualSerialPort": "Disabled"
                }
            }
            logging.info(f"Disabling virtual serial port for {iLOHost}.")
        else:
            payload = {
            "Attributes": {
                "VirtualSerialPort": "Com2Irq3"
                }
            }
            logging.info(f"Enabling virtual serial port [Com2Irq3] for host {iLOHost}.")
        
        
        MakeRestRequest((BIOSsettingsURL % iLOHost), "PATCH", headers, payload)

        
        
    except Exception as e:
        logging.error(f"Exception in configuring iLO serial port. Exception: {e}.")
        retVal = 1

    return retVal

def SetAutoPowerON(iLOHost,AutoPowerValue):
    """
    This task will configure AutoPowerOn settings in the iLO. Upon successful response the server has to be rebooted and call the SystemReset API to reboot subsequent to this.
    :param iLOHost: The ip address of the iLO
    :param AutoPowerValue: Sets the AutoPowerOn to AlwaysPowerOn or AlwaysPowerOff or RestoreLastState
    """
    retVal = 0
    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    try:
        
        if AutoPowerValue == "AlwaysPowerOn":
            payload = {
                "Attributes": {
                    "AutoPowerOn": "AlwaysPowerOn"
                }
            }
            logging.info(f"Setting Auto Power ON value to 'AlwaysPowerOn' for host {iLOHost}.")
        elif AutoPowerValue == "AlwaysPowerOff":
            payload = {
                "Attributes": {
                    "AutoPowerOn": "AlwaysPowerOff"
                }
            }
            logging.info(f"Setting Auto Power ON value to 'AlwaysPowerOff' for host {iLOHost}.")
        elif AutoPowerValue == "RestoreLastState":
            payload = {
                "Attributes": {
                    "AutoPowerOn": "RestoreLastState"
                }
            }
            logging.info(f"Setting Auto Power ON value to 'RestoreLastState' for host {iLOHost}.")
            
        MakeRestRequest((BIOSsettingsURL % iLOHost), "PATCH", headers, payload)
        
    except Exception as e:
        logging.error(f"Exception in setting Auto Power ON value. Exception: {e}.")
        retVal = 1

    return retVal

def iLOSecurityHardening(iLOHost):
    """
    This task will enable/disable various Security features in the iLO. Upon successful response the server has to be rebooted and iLO has to be reset.
    :param iLOHost: The ip address of the iLO
    """
    retVal = 0
    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    try:
        res = MakeRestRequest((BIOSsettingsURL % iLOHost), "GET", headers, "")
        if 'WorkloadProfile' in res[0]['Attributes'].keys():
            payload = {
                "Attributes": {
                    "WorkloadProfile": "Virtualization-MaxPerformance"
                }
            }
            logging.info("Setting WorkloadProfile for host %s" % iLOHost)
            MakeRestRequest((BIOSsettingsURL % iLOHost), "PATCH", headers, payload)

        payload = {"Attributes":{}}
        logging.info("Disabling embedded serial port,USB ports and networkboot for network cards on host %s" % iLOHost)
        res = MakeRestRequest((BIOSsettingsURL % iLOHost), "GET", headers, "")
        if "EmbeddedSerialPort" in res[0]['Attributes'].keys():
            payload['Attributes']['EmbeddedSerialPort'] = "Disabled"
        if "UsbControl" in res[0]['Attributes'].keys():
            payload['Attributes']['UsbControl'] = "UsbDisabled"
        slot_boot = re.compile("Slot\d+NicBoot\d+")
        nic_boot = re.compile("NicBoot\d+")
        for key in res[0]["Attributes"].keys():
            if slot_boot.match(key) or nic_boot.match(key):
                payload["Attributes"][key] = "Disabled"
        MakeRestRequest((BIOSsettingsURL % iLOHost),"PATCH",headers,payload)
        res = MakeRestRequest((ManagerURL % iLOHost), "GET", headers, "")
        payload = {"Oem": { "Hpe": {"FederationConfig":{},'iLOServicePort':{}}}}
        if 'MulticastDiscovery' in res[0]['Oem']['Hpe']['FederationConfig'].keys():
            payload['Oem']['Hpe']['FederationConfig']['MulticastDiscovery'] = "Disabled"
            logging.info("Disabling multicast discovery for host %s" % iLOHost)
        if 'iLOFederationManagement' in res[0]['Oem']['Hpe']['FederationConfig'].keys():
            payload['Oem']['Hpe']['FederationConfig']['iLOFederationManagement'] = "Disabled"
            logging.info("Disabling iLO federation management for host %s" % iLOHost)
        if 'RequiredLoginForiLORBSU' in res[0]['Oem']['Hpe'].keys():
            payload['Oem']['Hpe']['RequiredLoginForiLORBSU'] = True
            logging.info("Enabling Require Login for iLO RBSU for host %s" % iLOHost)
        if 'MassStorageAuthenticationRequired' in res[0]['Oem']['Hpe']['iLOServicePort'].keys():
            payload['Oem']['Hpe']['iLOServicePort']['MassStorageAuthenticationRequired'] = True
            logging.info("Enabling Require authentication for iLO Service Port for host %s" % iLOHost)

        MakeRestRequest((ManagerURL % iLOHost), "PATCH", headers, payload)

        payload = {"Oem": { "Hpe": {'FirmwareIntegrity':{}}}}
        res = MakeRestRequest((UpdateServiceURL % iLOHost), "GET", headers, "")
        if 'DowngradePolicy' in res[0]['Oem']['Hpe'].keys():
            payload['Oem']['Hpe']['DowngradePolicy'] = 'RecoveryDowngrade'
            logging.info("Setting the Downgrade Policy to Downgrade requires Recovery Set privilege for host %s" % iLOHost)
        if 'EnableBackgroundScan' in res[0]['Oem']['Hpe']['FirmwareIntegrity'].keys():
            payload['Oem']['Hpe']['FirmwareIntegrity']['EnableBackgroundScan'] = True
            logging.info("Enabling Firmware Verification Background Scan for host %s" % iLOHost)

        MakeRestRequest((UpdateServiceURL % iLOHost), "PATCH", headers, payload)

        payload = {"Oem": { "Hpe": {}}}
        res = MakeRestRequest((AccountServiceURL % iLOHost), "GET", headers, "")
        if 'AuthFailureLoggingThreshold' in res[0]['Oem']['Hpe'].keys():
            payload['Oem']['Hpe']['AuthFailureLoggingThreshold'] = 3
            logging.info("Enable Authentication Failure Logging for host %s" % iLOHost)
        if 'EnforcePasswordComplexity' in res[0]['Oem']['Hpe'].keys():
            payload['Oem']['Hpe']['EnforcePasswordComplexity'] = True
            logging.info("Enable Password Complexity setting for host %s" % iLOHost)
        if 'MinPasswordLength' in res[0]['Oem']['Hpe'].keys():
            payload['Oem']['Hpe']['MinPasswordLength'] = 14
            logging.info("Set Min. password length for host %s" % iLOHost)

        MakeRestRequest((AccountServiceURL % iLOHost), "PATCH", headers, payload)

        payload = {"SSH":{}}
        res = MakeRestRequest((NetworkProtocolURL % iLOHost),"GET",headers,payload)
        if 'ProtocolEnabled' in res[0]['SSH'].keys():
            payload['SSH']['ProtocolEnabled'] = False
            logging.info("Disable Secure Shell access for host %s" % iLOHost)
        MakeRestRequest((NetworkProtocolURL % iLOHost),"PATCH",headers,payload)
        
        payload = {'IPMI':{},'KVMIP':{}}
        response = MakeRestRequest((NetworkProtocolURL % iLOHost),"GET",headers,"")
        if 'Port' in response[0]['IPMI'].keys():
            payload['IPMI']['Port'] = 623
        if 'ProtocolEnabled' in response[0]['IPMI'].keys():
            payload['IPMI']['ProtocolEnabled'] = True
        if 'Port' in response[0]['KVMIP'].keys():
            payload['KVMIP']['Port'] = 17990
        if 'ProtocolEnabled' in response[0]['KVMIP'].keys():
            payload['KVMIP']['ProtocolEnabled'] = True

        if response[0]['Oem']['Hpe']['XMLResponseEnabled'] == True:
            logging.info("Ensuring Anonymous data is enabled for host %s" % iLOHost)
            logging.info("Enable Remote Console and IPMI/DCMI over LAN for host %s" % iLOHost)
            MakeRestRequest((NetworkProtocolURL % iLOHost),"PATCH",headers,payload)
            
    except Exception as e:
        logging.error(f"Exception in setting iLO security. Exception: {e}.")
        retVal = 1

    return retVal

def Validate_iLOSecurityHardening(iLOHost,report_file):
    """
    This task will validate if the ILO security requirements are enabled/disabled as per the standard security guidelines
    :param iLOHost: The ip address of the iLO
    """
    retVal = 0
    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    try:
        o1 = MakeRestRequest((BIOSsettingsURL % iLOHost), "GET", headers, "")
        
        if o1[0]['Attributes']['EmbeddedSerialPort'] == "Disabled":
            logging.info(f"Successfully validated Embedded Serial Port for host {iLOHost}.")
            line = (" " + "\t" + "EmbeddedSerialPort" + "\t" + "Disabled" + "\t" + o1[0]['Attributes'][
                'EmbeddedSerialPort'] + "\t" + "Pass")
            report_file.write(line + "\n")
        else:
            logging.info("Error: Attribute in BIOS settings(EmbeddedSerialPort) is not set to the correct value")
            retVal = 1
            line = (" " + "\t" + "EmbeddedSerialPort" + "\t" + "Disabled" + "\t" + o1[0]['Attributes'][
                'EmbeddedSerialPort'] + "\t" + "Fail")
            report_file.write(line + "\n")
            
        if o1[0]['Attributes']['UsbControl'] == "UsbDisabled":
            logging.info(f"Successfully validated USB ports for host {iLOHost}.")
            line = (" " + "\t" + "UsbControl" + "\t" + "UsbDisabled" + "\t" + o1[0]['Attributes'][
                'UsbControl'] + "\t" + "Pass")
            report_file.write(line + "\n")
        else:
            logging.info("Error: Attribute in BIOS settings(UsbControl) is not set to the correct value")
            retVal = 1
            line = (" " + "\t" + "UsbControl" + "\t" + "UsbDisabled" + "\t" + o1[0]['Attributes'][
                'UsbControl'] + "\t" + "Fail")
            report_file.write(line + "\n")
            
        slot_boot = re.compile("Slot\d+NicBoot\d+")
        nic_boot = re.compile("NicBoot\d+")
        for key in o1[0]["Attributes"].keys():
            if slot_boot.match(key) or nic_boot.match(key):
                if o1[0]["Attributes"][key] == "Disabled":
                    logging.info(f"Successfully validated Network boot for network cards on host {iLOHost}.")
                    line = (" " + "\t" + key + "\t" + "Disabled" + "\t" + o1[0]['Attributes'][key] + "\t" + "Pass")
                    report_file.write(line + "\n")
                else:
                    logging.info("Error: Attribute in BIOS settings(Network boot) is not set to the correct value")
                    retVal = 1
                    line = (" " + "\t" + key + "\t" + "Disabled" + "\t" + o1[0]['Attributes'][key] + "\t" + "Fail")
                    report_file.write(line + "\n")
        
        if o1[0]['Attributes']['UefiOptimizedBoot'] == "Enabled":
            logging.info(f"Successfully validated UEFI Optimized boot for host {iLOHost}.")
            line = (" " + "\t" + "UefiOptimizedBoot" + "\t" + "Enabled" + "\t" + o1[0]['Attributes'][
                'UefiOptimizedBoot'] + "\t" + "Pass")
            report_file.write(line + "\n")
        else:
            logging.info("Error: Attribute in BIOS settings(UefiOptimizedBoot) is not set to the correct value")
            retVal = 1
            line = (" " + "\t" + "UefiOptimizedBoot" + "\t" + "Enabled" + "\t" + o1[0]['Attributes'][
                'UefiOptimizedBoot'] + "\t" + "Fail")
            report_file.write(line + "\n")

        if o1[0]['Attributes']['TpmUefiOpromMeasuring'] == "Enabled":
            logging.info(f"Successfully validated UEFI Option ROM measurement for host {iLOHost}.")
            line = (" " + "\t" + "TpmUefiOpromMeasuring" + "\t" + "Enabled" + "\t" + o1[0]['Attributes'][
                'TpmUefiOpromMeasuring'] + "\t" + "Pass")
            report_file.write(line + "\n")
        else:
            logging.info("Error: Attribute in BIOS settings(TpmUefiOpromMeasuring) is not set to the correct value")
            retVal = 1
            line = (" " + "\t" + "TpmUefiOpromMeasuring" + "\t" + "Enabled" + "\t" + o1[0]['Attributes'][
                'TpmUefiOpromMeasuring'] + "\t" + "Fail")
            report_file.write(line + "\n")

        if o1[0]['Attributes']['WorkloadProfile'] == "Virtualization-MaxPerformance":
            logging.info(f"Successfully validated Workload Profile for host {iLOHost}.")
            line = (" " + "\t" + "WorkloadProfile" + "\t" + "Virtualization-MaxPerformance" + "\t" +
                    o1[0]['Attributes']['WorkloadProfile'] + "\t" + "Pass")
            report_file.write(line + "\n")
        else:
            logging.info("Error: Attribute in BIOS settings(WorkloadProfile) is not set to the correct value")
            retVal = 1
            line = (" " + "\t" + "WorkloadProfile" + "\t" + "Virtualization-MaxPerformance" + "\t" +
                    o1[0]['Attributes']['WorkloadProfile'] + "\t" + "Fail")
            report_file.write(line + "\n")

        o2 = MakeRestRequest((ManagerURL % iLOHost), "GET", headers, "")
        if o2[0]['Oem']['Hpe']['FederationConfig']['MulticastDiscovery'] == "Disabled":
            logging.info(f"Successfully validated multicast discovery for {iLOHost}.")
            line = (" " + "\t" + "MulticastDiscovery" + "\t" + "Disabled" + "\t" +
                    o2[0]['Oem']['Hpe']['FederationConfig']['MulticastDiscovery'] + "\t" + "Pass")
            report_file.write(line + "\n")
        else:
            logging.info("Error: FederationConfig settings(MulticastDiscovery) is not set to the correct value")
            retVal = 1
            line = (" " + "\t" + "MulticastDiscovery" + "\t" + "Disabled" + "\t" +
                    o2[0]['Oem']['Hpe']['FederationConfig']['MulticastDiscovery'] + "\t" + "Fail")
            report_file.write(line + "\n")

        if o2[0]['Oem']['Hpe']['FederationConfig']['iLOFederationManagement'] == "Disabled":
            logging.info(f"Successfully validated iLO federation management for host {iLOHost}.")
            line = (" " + "\t" + "iLOFederationManagement" + "\t" + "Disabled" + "\t" +
                    o2[0]['Oem']['Hpe']['FederationConfig']['iLOFederationManagement'] + "\t" + "Pass")
            report_file.write(line + "\n")
        else:
            logging.info("Error: FederationConfig settings(iLOFederationManagement) is not set to the correct value")
            retVal = 1
            line = (" " + "\t" + "iLOFederationManagement" + "\t" + "Disabled" + "\t" +
                    o2[0]['Oem']['Hpe']['FederationConfig']['iLOFederationManagement'] + "\t" + "Fail")
            report_file.write(line + "\n")

        if o2[0]['Oem']['Hpe']['RequiredLoginForiLORBSU'] == True:
            logging.info(f"Successfully validated Require Login for iLO RBSU for host {iLOHost}.")
            line = (" " + "\t" + "RequiredLoginForiLORBSU" + "\t" + "True" + "\t" + str(
                o2[0]['Oem']['Hpe']['RequiredLoginForiLORBSU']) + "\t" + "Pass")
            report_file.write(line + "\n")
        else:
            logging.info("Error: iLO RBSU settings(RequiredLoginForiLORBSU) is not set to the correct value")
            retVal = 1
            line = (" " + "\t" + "RequiredLoginForiLORBSU" + "\t" + "True" + "\t" + str(
                o2[0]['Oem']['Hpe']['RequiredLoginForiLORBSU']) + "\t" + "Fail")
            report_file.write(line + "\n")

        if o2[0]['Oem']['Hpe']['iLOServicePort']['MassStorageAuthenticationRequired'] == True:
            logging.info(f"Successfully validated Require authentication for iLO Service Port for host {iLOHost}.")
            line = (" " + "\t" + "MassStorageAuthenticationRequired" + "\t" + "True" + "\t" + str(
                o2[0]['Oem']['Hpe']['iLOServicePort']['MassStorageAuthenticationRequired']) + "\t" + "Pass")
            report_file.write(line + "\n")
        else:
            logging.info(
                "Error: iLO Service Port settings(MassStorageAuthenticationRequired) is not set to the correct value")
            retVal = 1
            line = (" " + "\t" + "MassStorageAuthenticationRequired" + "\t" + "True" + "\t" + str(
                o2[0]['Oem']['Hpe']['iLOServicePort']['MassStorageAuthenticationRequired']) + "\t" + "Fail")
            report_file.write(line + "\n")

        o5 = MakeRestRequest((UpdateServiceURL % iLOHost), "GET", headers, "")
        if o5[0]['Oem']['Hpe']['DowngradePolicy'] == "RecoveryDowngrade":
            logging.info(f"Successfully validated the Downgrade Policy to Downgrade requires Recovery Set privilege for host {iLOHost}.")
            line = (" " + "\t" + "DowngradePolicy" + "\t" + "RecoveryDowngrade" + "\t" + o5[0]['Oem']['Hpe'][
                'DowngradePolicy'] + "\t" + "Pass")
            report_file.write(line + "\n")
        else:
            logging.info("Error: FirmwareIntegrity settings(DowngradePolicy) is not set to the correct value")
            retVal = 1
            line = (" " + "\t" + "DowngradePolicy" + "\t" + "RecoveryDowngrade" + "\t" + o5[0]['Oem']['Hpe'][
                'DowngradePolicy'] + "\t" + "Fail")
            report_file.write(line + "\n")

        if o5[0]['Oem']['Hpe']['FirmwareIntegrity']['EnableBackgroundScan'] == True:
            logging.info(f"Successfully validated Firmware Verification Background Scan for host {iLOHost}.")
            line = (" " + "\t" + "EnableBackgroundScan" + "\t" + "True" + "\t" + str(
                o5[0]['Oem']['Hpe']['FirmwareIntegrity']['EnableBackgroundScan']) + "\t" + "Pass")
            report_file.write(line + "\n")
        else:
            logging.info("Error: FirmwareIntegrity settings(EnableBackgroundScan) is not set to the correct value")
            retVal = 1
            line = (" " + "\t" + "EnableBackgroundScan" + "\t" + "True" + "\t" + str(
                o5[0]['Oem']['Hpe']['FirmwareIntegrity']['EnableBackgroundScan']) + "\t" + "Fail")
            report_file.write(line + "\n")

        o3 = MakeRestRequest((AccountServiceURL % iLOHost), "GET", headers, "")
        if o3[0]['Oem']['Hpe']['AuthFailureLoggingThreshold'] == 3:
            logging.info(f"Successfully validated Authentication Failure Logging for host {iLOHost}.")
            line = (" " + "\t" + "AuthFailureLoggingThreshold" + "\t" + "3" + "\t" + str(
                o3[0]['Oem']['Hpe']['AuthFailureLoggingThreshold']) + "\t" + "Pass")
            report_file.write(line + "\n")
        else:
            logging.info(
                "Error: Password Authentication settings(AuthFailureLoggingThreshold) is not set to the correct value")
            retVal = 1
            line = (" " + "\t" + "AuthFailureLoggingThreshold" + "\t" + "3" + "\t" + str(
                o3[0]['Oem']['Hpe']['AuthFailureLoggingThreshold']) + "\t" + "Fail")
            report_file.write(line + "\n")

        if o3[0]['Oem']['Hpe']['EnforcePasswordComplexity'] == True:
            logging.info(f"Successfully validated Password Complexity setting for host {iLOHost}.")
            line = (" " + "\t" + "EnforcePasswordComplexity" + "\t" + "True" + "\t" + str(
                o3[0]['Oem']['Hpe']['EnforcePasswordComplexity']) + "\t" + "Pass")
            report_file.write(line + "\n")
        else:
            logging.info(
                "Error: Password Authentication settings(EnforcePasswordComplexity) is not set to the correct value")
            retVal = 1
            line = (" " + "\t" + "EnforcePasswordComplexity" + "\t" + "True" + "\t" + str(
                o3[0]['Oem']['Hpe']['EnforcePasswordComplexity']) + "\t" + "Fail")
            report_file.write(line + "\n")

        if o3[0]['Oem']['Hpe']['MinPasswordLength'] == 14:
            logging.info(f"Successfully validated Min. password length for host {iLOHost}.")
            line = (" " + "\t" + "MinPasswordLength" + "\t" + "14" + "\t" + str(o3[0]['Oem']['Hpe']['MinPasswordLength']) + "\t" + "Pass")
            report_file.write(line + "\n")
        else:
            logging.info("Error: Password Authentication settings(MinPasswordLength) are not set to the correct value")
            retVal = 1
            line = (" " + "\t" + "MinPasswordLength" + "\t" + "14" + "\t" + str(o3[0]['Oem']['Hpe']['MinPasswordLength']) + "\t" + "Fail")
            report_file.write(line + "\n")
        

        o4 = MakeRestRequest((NetworkProtocolURL % iLOHost), "GET", headers, "")
        if (o4[0]['IPMI']['Port'] == 623 and o4[0]['IPMI']['ProtocolEnabled'] == True):
            logging.info(f"Successfully validated IPMI/DCMI over LAN for host {iLOHost}.")
            line = (" " + "\t" + "IPMI" + "\t" + "True, 623" + "\t" + str(o4[0]['IPMI']['ProtocolEnabled']) + ", " + str(o4[0]['IPMI']['Port']) + "\t" + "Pass")
            report_file.write(line + "\n")
        else:
            logging.info("Error: Network Protocol settings(IPMI) are not set to the correct value")
            retVal = 1
            line = (" " + "\t" + "IPMI" + "\t" + "True, 623" + "\t" + str(o4[0]['IPMI']['ProtocolEnabled']) + ", " + str(o4[0]['IPMI']['Port']) + "\t" + "Fail")
            report_file.write(line + "\n")
            
        if (o4[0]['KVMIP']['Port'] == 17990 and o4[0]['KVMIP']['ProtocolEnabled'] == True):
            logging.info(f"Successfully validated Remote Console for host {iLOHost}.")
            line = (" " + "\t" + "KVMIP" + "\t" + "True, 17990" + "\t" + str(o4[0]['KVMIP']['ProtocolEnabled']) + ", " + str(o4[0]['KVMIP']['Port']) + "\t" + "Pass")
            report_file.write(line + "\n")
        else:
            logging.info("Error: Network Protocol settings(KVMIP) is not set to the correct value")
            retVal = 1
            line = (" " + "\t" + "KVMIP" + "\t" + "True, 17990" + "\t" + str(o4[0]['KVMIP']['ProtocolEnabled']) + ", " + str(o4[0]['KVMIP']['Port']) + "\t" + "Fail")
            report_file.write(line + "\n")
            
        if o4[0]['SSH']['ProtocolEnabled'] == False:
            logging.info(f"Successfully validated Secure Shell access for host {iLOHost}.")
            line = (" " + "\t" + "SSH" + "\t" + "False" + "\t" + str(o4[0]['SSH']['ProtocolEnabled']) + "\t" + "Pass")
            report_file.write(line + "\n")
        else:
            logging.info("Error: SSH settings(SSH) are not set to the correct value")
            retVal = 1
            line = (" " + "\t" + "SSH" + "\t" + "False" + "\t" + str(o4[0]['SSH']['ProtocolEnabled']) + "\t" + "Fail")
            report_file.write(line + "\n")
    except Exception as e:
        logging.error(f"Exception in validating iLO security. Exception: {e}.")
        retVal = 1

    return retVal, report_file

def addLicenseKey(iLOHost):
    retVal = 0
    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    lk_data = None
    lkFilePath = os.path.join(os.path.dirname(os.path.abspath(__file__)),"..","..","data","LicenseKey.json")
    try:
        with open(lkFilePath,'r') as lk_file:
            lk_data = json.load(lk_file)

        license_key = lk_data['LicenseKey']
    except Exception as e:
        logging.error("Error loading LicenseKey JSON %s. Error: %s" %(lkFilePath,e))

    try:
        logging.info("Adding license key for host %s" % iLOHost)
        payload = {
            "LicenseKey": license_key
            }
        MakeRestRequest((LicenseKeyURL % iLOHost),"POST",headers,payload)
    except Exception as e:
        logging.error(f"Exception in adding license. Exception: {e}.")
        retVal = 1


    return retVal

def countDublicates(dub_list):
    if(dub_list != None):
        mapped_dict = {i: dub_list.count(i) for i in dub_list}
        logging.info(mapped_dict)
        return mapped_dict

def trimModuleID(moduleID_without_trim):
    trimmedModuleID = ""
    if len(moduleID_without_trim) > 0:
        try:
            if len(moduleID_without_trim) >= 62:
                logging.info(f"Before trim {moduleID_without_trim}")
                trimmedModuleID = moduleID_without_trim[0 : 62]
                logging.info(f"After trim {trimmedModuleID}")
            else:
                trimmedModuleID = moduleID_without_trim
        except Exception as e:
            logging.info(f"Exception in {e}")
    return trimmedModuleID

def getModuleID(param_mtype,param_manf,param_vcpu,param_mem,param_freq,param_nic,param_boot,param_storage,param_pci):
    """
    This task will massage the parameters and form the Module ID.
    :param param_mtype: model type
    :param param_manf : manufacturing type
    :param param_vcpu : No. virtual  cpu's
    :param param_mem  : Memory
    :param param_freq : CPU frequency
    :param param_nic  : nic card details
    :param param_boot : boot disk details
    :param param_storage : storage details like HDD, SDD, and NVME
    :param param_pci : pci card details (FC HBA and GPU)
    :return: final generated Module ID.
    """
    dic_type = { "DL360" : "D", "DL325" : "B", "DL380" : "F", "DL385" : "F", "Superdome Flex 280" : "S", "e910" : "E", "XL675d" : "M", "XL225n" : "D"}
    dic_cpu = { "Intel" : "N", "AMD" : "A", "ARM" : "M"}
    temp_mtype, temp_mver, temp_manftype, temp_freq, temp_vcpu, temp_nic1_no, temp_nic1_gb, temp_nic1_port, temp_nic1_type, temp_nic2_no, temp_nic2_gb, temp_nic2_port, temp_nic2_type, temp_port1no, temp_pic1name, temp_pic1gb, temp_pic1port, temp_port2no, temp_pic2name, temp_pic2gb, temp_pic2port = "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", ""
    final_module_type, final_manf, final_mem, final_nic1, final_nic2, final_boot, final_storage, final_port1, final_port2 = "", "", "", "", "", "", "", "", ""

    if param_mtype:
        try:
            mtype = param_mtype.split()
            for mKey in dic_type:
                if(mtype[1] in mKey):
                    temp_mtype = dic_type[mtype[1]]
                    break
            if("+ v2" in param_mtype or "Plus v2" in param_mtype):
                temp_mver = 3
            elif("+" in param_mtype or "Plus" in param_mtype):
                temp_mver = 2
            else:
                temp_mver = 1
            final_module_type = temp_mtype + str(temp_mver)
        except Exception as e:
            logging.exception(f"Exception in getting Module Type. Exception: {e}.")
    else:
        final_module_type = "0"

    if param_manf:
        try:
            manf_type = param_manf.split()
            for manfKey in dic_cpu:
                if(manfKey in manf_type[0]):
                    temp_manftype = dic_cpu[manfKey]
                    break
        except Exception as e:
            logging.exception(f"Exception in getting frequency. Exception: {e}.")
        else:
            temp_freq = "0"

        if param_vcpu:
            temp_vcpu = param_vcpu
        else:
            temp_vcpu = "0"

        if param_freq:
            if (param_freq <= 2600):
                temp_freq = 'S'
            else:
                temp_freq = 'P'
    else:
        logging.info("Manufacturing details not found.")

    final_manf = temp_manftype + temp_freq + str(temp_vcpu)

    if param_mem:
        final_mem = str(param_mem)
    else:
        final_mem = "0"

    # param_nic is dictionary sorted in reverse order, i.e. fastest adapter first
    #      key is speed.ports
    #      value is number of adapters
    #      for example: {'25.2': 1} represents one 25GbE dual port adapter
    # module ID fields are Nic1 (fastest adapter) and Nic2 (second fastest adapter)
    # naming convention is number of adapters 'xE' adapter speed '-' number of ports
    # for example: 1xE25-2 represents one 25GbE dual port adapter
    # if no network adapter module ID field is '0'
    if param_nic:
        nic_list =  []
        for nics in param_nic:
            nic_list.append(str(param_nic[nics]) + "xE" + nics.replace(".", "-"))

        try:
            final_nic1 = nic_list[0]
        except IndexError:
            final_nic1 = "0"

        try:
            final_nic2 = nic_list[1]
        except IndexError:
            final_nic2 = "0"
    else:
        final_nic1 = "0"
        final_nic2 = "0"

    # param_boot is dictionary with one key-value pair
    #      key is boot drive capacity in GB represented as a string
    #      value is number of boot drives
    # module ID field is Boot
    # naming convention is number of boot drives 'x' boot drive capacity
    # for example: 2x480 represents two 480GB boot drives
    # if no boot drives module ID field is '0'
    if param_boot:
        for boot_details in param_boot:
            try:
                final_boot = str(param_boot[boot_details]) + 'x' + str(boot_details)
            except KeyError:
                final_boot = "0"
    else:
        final_boot = "0"

    # param_storage is a nested dictionary containing media type
    # and corresponding drive capacity and counts sorted in reverse order by capacity, i.e. largest drive first
    #      key for outer level is media types in order HDD, SSD, and NVMe
    #      value is dictionary with key-value pair of drive capacity in GB (represented as a string) and number of drives
    # module ID field is Storage
    # naming convention is number of drives 'x' <media type initial> drive capacity
    # if more than one drive capacity and/or media type the fields in Storage are separated by ','
    # storage drives are listed in order by media type HDD followed by SSD followed by NVMe
    # within media type drives are listed from largest capacity to smallest capacity
    # for example: 2xH600,4xS1920 represents two 600GB HDD drives and four 1.92TB SSD drives
    # if no storage drives module ID field is '0'
    if param_storage:
        final_storage = ""
        for media in param_storage:
            for disk in param_storage[media]:
                if len(final_storage) > 0:
                    final_storage += ','
                final_storage += str(param_storage[media][disk]) + 'x' + str(media)[:1] + str(disk)
                #break here to limit ephemeral storage to max of one drive capacity per media type
        if len(final_storage) == 0:
            final_storage = "0"
    else:
        final_storage = "0"

    # PCI information not currently supported so set to "0" in module ID
    if param_pci:
        final_pci1 = "0"
        final_pci2 = "0"
    else:
        final_pci1 = "0"
        final_pci2 = "0"

    return final_module_type + '.' + final_manf + '.' + final_mem + '.' + final_nic1 + '.' + final_nic2 + '.' + final_boot + '.' + final_storage + '.' + final_pci1 + '.' + final_pci2

def chassis_network_adapters(iLOHost):
    """
    This task gathers list of chassis network adapters.
    :param host: The ip address of the iLO
    """

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }

    retVal = []

    try: 
        chassisnetadapterRes = MakeRestRequest((chassisNetAdaptersURL % iLOHost),"GET",headers,"")
        nicDevices = chassisnetadapterRes[0]['Members@odata.count']
        logging.info("Number of network adapter members found: %s" %nicDevices)

        cnt = 0
        while cnt < nicDevices:
            #Get network adapter member id
            memberidRequest = chassisnetadapterRes[0]["Members"][cnt]["@odata.id"]
            chassisnetadptmemberid= (memberidRequest.split("/")[6])
            logging.info("Network adapter member id: %s" %chassisnetadptmemberid)

            #Get network adapter model
            nicReq = MakeRestRequest((baseURL % (iLOHost, memberidRequest)), "GET", headers, "")
            modelRequest = nicReq[0]["Model"]
            logging.info("Network adapter model: %s" %modelRequest)
            fwversionRequest = nicReq[0]["Controllers"][0]["FirmwarePackageVersion"]
            logging.info("Firmware version: %s" %fwversionRequest)

            tpl = (chassisnetadptmemberid, modelRequest, fwversionRequest)
            cnt += 1
            retVal.append(tpl)

    except Exception as e:
        logging.error(f"Exception in obtaining network adapters on server {iLOHost}.")
        retVal = 1
    return retVal

def CheckRestartComplete(iLOHost, chassisnetadptmemberid, port):
    """
    This task will change Mellanox CX6 network adapter to ethernet mode.
    :param host: The ip address of the iLO
    """
    netDevFuncType = ''

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    try:
        requestReturn = MakeRestRequest((chassisNetAdapterfunctionURL % (iLOHost, chassisnetadptmemberid ,port)),"GET",headers,"")
        if 'error' in requestReturn.keys():
            return False
        else:
            return True

        
    except Exception as e:
        logging.error(f"Exception in retrieving Mellanox CX6 ethernet mode on server {iLOHost}.")

    return netDevFuncType


def CheckMellonoxEthernetMode(iLOHost, chassisnetadptmemberid, port):
    """
    This task will change Mellanox CX6 network adapter to ethernet mode.
    :param host: The ip address of the iLO
    """
    netDevFuncType = ''

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    try:

        cx6functionstatRequest = MakeRestRequest((chassisNetAdapterfunctionURL % (iLOHost, chassisnetadptmemberid ,port)),"GET",headers,"")

        netDevFuncType = cx6functionstatRequest[0]['NetDevFuncType'].strip()
        
    except Exception as e:
        logging.error(f"Exception in retrieving Mellanox CX6 ethernet mode on server {iLOHost}.")

    return netDevFuncType

def Mellanox_CX6_ethernetmode (iLOHost, chassisnetadptmemberid, port):
    """
    This task will change Mellanox CX6 network adapter to ethernet mode.
    :param host: The ip address of the iLO
    """
    retVal = 0

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error("Ensure valid iLO session is there for the host %s" % iLOHost)
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    try:

        cx6functionstatRequest= MakeRestRequest((chassisNetAdapterfunctionURL % (iLOHost, chassisnetadptmemberid ,port)),"GET",headers,"")
        cx6functionstat = cx6functionstatRequest[0]["NetDevFuncType"]
        logging.info(cx6functionstat)
        if cx6functionstat == "InfiniBand":
            devfunction = {
                 "NetDevFuncType": "Ethernet"
                }
            logging.info(chassisnetadptmemberid)
            logging.info(port)
            MakeRestRequest((chassisNetAdapterfunctionURL % (iLOHost, chassisnetadptmemberid ,port)),"PATCH",headers,devfunction)

            port = 1

            MakeRestRequest((chassisNetAdapterfunctionURL % (iLOHost, chassisnetadptmemberid ,port)),"PATCH",headers,devfunction)

    except Exception as e:
        logging.error(f"Exception in setting Mellanox CX6 ethernet mode on server {iLOHost}.")
        retVal = 1
    return retVal

def genModuleID_stampBios(host, username, password):
    """
    This task will generate Module ID and stamp it to the BIOS CustomPostMessage field
    :param host: The ip address of the iLO
    :param username : username to log in to iLO
    :param password : password for authentication
    Function will stamp the Module ID to BIOS 'CustomPostMessage' with Max 62 chars
    """
    # TODO - need to fix exception handling
    try:
        # Set default for iLO generation to iLO 5
        final_module_id = ""
        ilogen = None
        login_retval = ILOLogin(host,username,password)
        if login_retval:
            logging.error(f"ILO login failure with the host {host}.")
        else:
            logging.info(f"ILO login to {host}.")

            ilogen = GetiLOGen(host)

            # Collect server information to determine Instance Type
            headers = {
                'content-type': "application/json",
                'X-Auth-Token': authCodeMap[host]
            }

            comp_res, _ = MakeRestRequest((computerSystem1URL % host),"GET",headers,"")

            total_sys_mem_gb = comp_res['MemorySummary']['TotalSystemMemoryGiB']
            sys_model = comp_res['Model']
            num_cpu = comp_res['ProcessorSummary']['Count']
            manf = comp_res["ProcessorSummary"]["Model"]

            # calculate number of vCPUs as total of hyperthreads for all processors
            num_vcpu = 0
            cnt = 1
            while cnt <= num_cpu:
                proc_res, _ = MakeRestRequest((processorURL %(host, cnt)),"GET",headers,"")
                num_vcpu += proc_res['TotalThreads']
                cnt += 1

            param_freq = proc_res['Oem']['Hpe']['RatedSpeedMHz']
            param_mtype = sys_model
            param_mem = total_sys_mem_gb
            param_vcpu =  num_vcpu
            param_manf = manf

            if ilogen == '5':
                # Collect information on all network adapters and store in a dictionary
                # dictionary key-value pair defined as
                #      key is speed.ports
                #      value is number of adapters
                #      for example: {'25.2': 1} represents one 25GbE dual port adapter
                # speed is determined by parsing Name field returned by Redfish API (SpeedMbps field not reliable)
                # number of ports is determined by PhysicalPorts returned by Redfish API
                # param_nic is dictionary sorted in reverse order, i.e. fastest adapter first
                try:
                    nic_res, _ = MakeRestRequest((nicDevicesURL % host),"GET",headers,"")
                    nic_devices = nic_res['Members@odata.count']
                    nic_adapters = defaultdict(int)
                    param_nic = defaultdict(int)
                    cnt = 0
                    while cnt < nic_devices:
                        dynamic_request = nic_res["Members"][cnt]["@odata.id"]
                        nic_req, _ = MakeRestRequest((baseURL % (host, dynamic_request)), "GET", headers, "")
                        nic_speed = None
                        for word in nic_req["Name"].split():
                            if re.search('Gb?E?$', word):
                                if "/" in word:
                                    word = word.split('/')[1]
                                nic_speed = word.split('G')[0]
                                break
                        num_nic_ports = len(nic_req["PhysicalPorts"])
                        nic_adapters[str(nic_speed) + '.' + str(num_nic_ports)] += 1
                        cnt += 1
                    if len(nic_adapters) > 0:
                        param_nic = {i: nic_adapters[i] for i in sorted(nic_adapters, reverse=True, key=float)}
                except Exception as e:
                    logging.exception("Exception in Getting Nic card details.")

                # Collect information on all FC HBA and GPU PCI devices
                # this section needs to be updated to collect and parse desired information
                try:
                    chassis_dev_res, _ = MakeRestRequest((chassis1DevicesURL % host), "GET", headers, "")
                    num_chassis_devices = chassis_dev_res['Members@odata.count']
                    pci_slot = defaultdict(int)
                    param_pci = {}
                    cnt = 1
                    while cnt <= num_chassis_devices:
                        dev_res, _ = MakeRestRequest((chassisMemberDevicesURL % (host, cnt)), "GET", headers, "")
                        dev_location = dev_res["Location"]
                        if ("PCI" in dev_location):
                            if ("Slot" in dev_location):
                                    pci_slot[dev_res["Name"]] += 1
                        cnt += 1
                    param_pci = {i: pci_slot[i] for i in pci_slot}
                except Exception as e:
                    logging.exception(f"Exception in getting PCI card details. Exception: {e}.")

                # Collect information on all boot and storage drives and store in separate dictionaries
                # boot and storage drives are stored in a nested dictionary containing media type
                # and corresponding drive capacity and counts
                #      key for outer level is media types in order HDD, SSD, and NVMe
                #      value is dictionary with key-value pair of drive capacity in GB and number of drives
                # for example: {'HDD': {'480': 2}, 'SSD': {'800': 4}, 'NVMe': {}}
                # represents two 480GB HDD drives and four 800GB SSD drives
                try:
                    boot_drives = defaultdict(lambda: defaultdict(int))
                    storage_drives = defaultdict(lambda: defaultdict(int))
                    controllers = defaultdict(lambda: defaultdict(int))
                    boot_strings =[]
                    param_boot = {}
                    param_storage = {}
                    for media in ['HDD', 'SSD', 'NVMe']:
                        boot_drives[media]
                        storage_drives[media]

                    # get list of boot strings for HD and NVMe devices
                    # boot strings will be used to determine all potential boot drives
                    bios_res, _ = MakeRestRequest((biosURL % host), "GET", headers, "")
                    boot_request = bios_res["Oem"]["Hpe"]["Links"]["Boot"]["@odata.id"]
                    boot_res, _ = MakeRestRequest((baseURL %(host, boot_request)), "GET", headers, "")
                    cnt = 0
                    boot_sources = boot_res["BootSources"]
                    while cnt < len(boot_sources):
                        structured_boot_string = boot_sources[cnt]["StructuredBootString"]
                        if structured_boot_string.startswith("HD") or structured_boot_string.startswith("NVMe"):
                            boot_strings.append(boot_sources[cnt]["BootString"])
                        cnt += 1
 
                    # Collect information on all boot and storage drives and store in separate dictionaries
                    # boot drives will be determined by checking if storage controller contained in a boot string
                    # Collect Smart Array Controller drives first and then Redfish Storage
                    # Use controller model and serial number to determine if storage is reported by both Redfish APIs
                    # to eliminate counting the same drives twice
                    # get storage from Smart Array Controller
                    storage_res, _ = MakeRestRequest((smartStorageURL % host),"GET",headers,"")
                    num_chassis_devices = storage_res['Members@odata.count']
                    cnt = 0
                    while cnt < num_chassis_devices:
                        dynamic_request = storage_res["Members"][cnt]["@odata.id"]
                        sto_req, _ = MakeRestRequest((baseURL %(host, dynamic_request)),"GET",headers,"")
                        controller_model = sto_req["Model"]
                        controller_srno = sto_req["SerialNumber"]
                        controllers[controller_model][controller_srno] += 1
                        logging.debug("Smart Array Controller: %s" %controller_model)
                        if controllers[controller_model][controller_srno] == 1:
                            dynamic_request = sto_req["Links"]["PhysicalDrives"]['@odata.id']
                            sto_req, _ = MakeRestRequest((baseURL %(host, dynamic_request)),"GET",headers,"")
                            num_devicecount = sto_req["Members@odata.count"]
                            dev_cnt = 0
                            while dev_cnt < num_devicecount:
                                dynamic_request_device = sto_req["Members"][dev_cnt]["@odata.id"]
                                device_req, _ = MakeRestRequest((baseURL %(host, dynamic_request_device)), "GET", headers, "")
                                if device_req['Status']['State'] == 'Enabled' and device_req['Status']['Health'] == 'OK':
                                    if device_req["InterfaceType"].upper() == 'NVME':
                                        media_type = 'NVMe'
                                    else:
                                        media_type = device_req["MediaType"]
                                    if controller_model in str(boot_strings):
                                        boot_drives[media_type][str(device_req["CapacityGB"])] += 1
                                    else:
                                        storage_drives[media_type][str(device_req["CapacityGB"])] += 1
                                else:
                                    disk_location = device_req['Location']
                                    disk_status = device_req['Status']['State']
                                    disk_health = device_req['Status']['Health']
                                    logging.info(f"Disk Drive at Location: {disk_location} Status: {disk_status} Health: {disk_health}")
                                dev_cnt += 1
                        cnt += 1
                    
                    # get storage supporting DMTF Redfish Storage Model
                    storage_res, _ = MakeRestRequest((storageURL % host),"GET",headers,"")
                    num_storage_devices = storage_res['Members@odata.count']
                    cnt = 0
                    while cnt < num_storage_devices:
                        dynamic_request = storage_res["Members"][cnt]["@odata.id"]
                        sto_req, _ = MakeRestRequest((baseURL %(host, dynamic_request)),"GET",headers,"")
                        if 'StorageControllers' in sto_req:
                            controller_req = sto_req["StorageControllers"][0]
                        elif 'Controllers' in sto_req:
                            dynamic_request = sto_req["Controllers"]["@odata.id"]
                            controller_req, _ = MakeRestRequest((baseURL %(host, dynamic_request)),"GET",headers,"")
                            dynamic_request = controller_req["Members"][0]["@odata.id"]
                            controller_req, _ = MakeRestRequest((baseURL %(host, dynamic_request)),"GET",headers,"")
                        else:
                            logging.info("Storage controller information not found.")
                        controller_model = controller_req["Model"]
                        controller_srno = controller_req["SerialNumber"]
                        controllers[controller_model][controller_srno] += 1
                        logging.debug("Smart Array Controller: %s" %controller_model)
                        if controllers[controller_model][controller_srno] == 1:
                            num_devicecount = sto_req["Drives@odata.count"]
                            dev_cnt = 0
                            while dev_cnt < num_devicecount:
                                dynamic_request_device = sto_req["Drives"][dev_cnt]["@odata.id"]
                                device_req, _ = MakeRestRequest((baseURL %(host, dynamic_request_device)), "GET", headers, "")
                                if device_req['Status']['State'] == 'Enabled' and device_req['Status']['Health'] == 'OK':
                                    if device_req["Protocol"].upper() == 'NVME':
                                        media_type = 'NVMe'
                                    else:
                                        media_type = device_req["MediaType"]
                                    if controller_model in str(boot_strings):
                                        boot_drives[media_type][str((device_req["CapacityBytes"]) // 1000000000)] +=1
                                    else:
                                        storage_drives[media_type][str((device_req["CapacityBytes"]) // 1000000000)] +=1
                                else:
                                    disk_location = device_req['PhysicalLocation']['PartLocation']['ServiceLabel']
                                    disk_status = device_req['Status']['State']
                                    disk_health = device_req['Status']['Health']
                                    logging.info(f"Disk Drive at Location: {disk_location} Status: {disk_status} Health: {disk_health}")
                                dev_cnt += 1
                        cnt += 1

                    logging.debug("Unsorted boot drives: {boot_drives}")
                    logging.debug("Unsorted storage drives: {storage_drives}")

                    # Sort boot disk drives dictionary in ascending order,
                    #    i.e. smallest capacity disk first for each media type
                    # media type order in dictionary is HDD, SSD, NVMe
                    # Select boot drive by determining the smallest capacity drive from all media types
                    # Allow maximum of two boot drives
                    # decrement count of boot drives in dictionary if drives are selected
                    # add drive count back to dictionary if smaller drive found in another media type
                    for media in boot_drives:
                        boot_drives[media] = {i: boot_drives[media][i] for i in sorted(boot_drives[media], reverse=False, key=float)}

                    logging.debug(f"Sorted boot drives: {boot_drives}")
                    boot_disk_media = None
                    boot_disk_capacity = 0
                    num_boot_disks = 0
                    for media in boot_drives:
                        for disk in boot_drives[media]:
                            if boot_disk_capacity == 0 or int(disk) < boot_disk_capacity:
                                if boot_disk_media:
                                    boot_drives[boot_disk_media][str(boot_disk_capacity)] += num_boot_disks
                                boot_disk_media = media
                                boot_disk_capacity = int(disk)
                                num_boot_disks = 2 if boot_drives[media][disk] >= 2 else boot_drives[media][disk]
                                boot_drives[media][disk] -= num_boot_disks
                            break
            
                    # param_boot is dictionary with one key-value pair
                    #      key is boot drive capacity in GB represented as a string
                    #      value is number of boot drives
                    #      for example: {'480':2} represents two 480GB boot drives
                    param_boot[str(boot_disk_capacity)] = num_boot_disks

                    # After selecting boot drive
                    # Add remaining drives in boot_drives dictionary to storage_drives dictionary
                    # exclude any drives with count of zero (drive with count of zero would be boot drive)
                    for media in boot_drives:
                        for disk in boot_drives[media]:
                            if boot_drives[media][disk] > 0:
                                storage_drives[media][disk] += boot_drives[media][disk]

                    # param_storage is a nested dictionary containing media type
                    # and corresponding drive capacity and counts sorted in reverse order by capacity, i.e. largest drive first
                    #      key for outer level is media types in order HDD, SSD, and NVMe
                    #      value is dictionary with key-value pair of drive capacity in GB (represented as a string) and number of drives
                    # storage drives are listed in order by media type HDD followed by SSD followed by NVMe
                    # within media type drives are listed from largest capacity to smallest capacity
                    # for example: {'HDD':{'600':2, '480': 2}, 'SSD': {'1920': 4}, 'NVMe': {}}
                    # represents two 600GB and two 480 GB HHD drives and four 1.92TB SSD drives
                    for media in storage_drives:
                        param_storage[media] = {i:storage_drives[media][i] for i in sorted(storage_drives[media], reverse=True, key=float)}

                    logging.debug(f"Sorted storage drives: {param_storage}")
                except Exception as e:
                    logging.exception(f"Exception in getting storage details. Exception: {e}.")

        try:
            logging.info(f"Module Type and version: {param_mtype}")
            logging.info(f"Module manufacturing: {param_manf}")
            logging.info(f"No. of vCPUs: {param_vcpu}")
            logging.info(f"Memory size: {param_mem}")
            logging.info(f"CPU Frequency: {param_freq}")
            logging.info(f"NIC card details: {param_nic}")
            logging.debug(f"Boot Strings: {boot_strings}")
            logging.info(f"Boot disk details: {param_boot}")
            logging.info(f"Storage disk details: {param_storage}")
            logging.info(f"PCI details: {param_pci}")
            temp_module_id = getModuleID(param_mtype, param_manf, param_vcpu, param_mem, param_freq, param_nic, param_boot, param_storage, param_pci)
            logging.info("Generated Module ID: %s" % temp_module_id)
            final_module_id = trimModuleID(temp_module_id)

            if ilogen == '4':
                BIOSsettingsBody = {
                    "CustomPostMessage": final_module_id
                }
            elif ilogen == '5':
                BIOSsettingsBody = {
                    "Attributes": {
                    "CustomPostMessage": final_module_id 
                    }
                }
            bios_res, _ = MakeRestRequest((BIOSsettingsURL % host), "GET", headers, "")
            logging.info("BIOS CustomPostMessage before updating with Module ID: %s" %(bios_res['Attributes']['CustomPostMessage']))
            logging.info("Patching Module ID in BIOS CustomPostMessage")
            patch_request, _ = MakeRestRequest( (BIOSsettingsURL % host),"PATCH", headers, BIOSsettingsBody)
            logging.info(f"Patch response: {patch_request['error']['@Message.ExtendedInfo']}")
            bios_res, _ = MakeRestRequest((BIOSsettingsURL % host), "GET", headers, "")
            logging.info("BIOS CustomPostMessage after patching with Module ID: %s" %(bios_res['Attributes']['CustomPostMessage']))

            logoff_retval = ILOLogoff(host)
            if logoff_retval:
                logging.error(f"ILO logoff failure with the host {host}.")
            else:
                logging.info(f"Successfully logged off {host}.")

        except Exception as e:
            logging.exception(f"Generate getModuleID failed. Exception: {e}.")

    except Exception as e:
        logging.exception(f"Generate ModuleID failed. Exception: {e}.")


    return final_module_id

def stampSMBIOS_productID(iLOHost):
    """
    This task will  stamp SMBIO's ProductIdS.
    :param host: The ip address of the iLO
    It will stamp the SMBIO's 'ProductId' attribute
    """
    retVal = 0
    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)
    BIOSsettingsBody =""
    prodid = None

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }

    try:

        compRes = MakeRestRequest((computerSystem1URL % iLOHost),"GET",headers,"")
        sysMod = compRes[0]['Model']
        #sysMod = 'ProLiant DL326 Gen10 Plus'
        logging.info(f"system model is {sysMod}")
        if (sysMod != None):
            try:
                mtype = sysMod.strip()
                if ("+ v2" in mtype or "Plus v2" in mtype):
                    prodid = getProductID("Gen10+V2")
                    BIOSsettingsBody = {
                        "Attributes": {
                            "ProductId": prodid
                        }
                    }
                    logging.info(f"Updating SMBIOS's ProductID to : {prodid}")
                    patchRequest = MakeRestRequest((BIOSsettingsURL % iLOHost), "PATCH", headers, BIOSsettingsBody)
                    logging.info(f"Patch response : {patchRequest[0]['error']['@Message.ExtendedInfo']}")
                    retVal = 0

                elif ("+" in mtype or "Plus" in mtype ):
                    prodid = getProductID("Gen10+")
                    BIOSsettingsBody = {
                        "Attributes": {
                            "ProductId": prodid
                        }
                    }
                    logging.info(f"Updating SMBIOS's ProductID to : {prodid}")
                    patchRequest = MakeRestRequest((BIOSsettingsURL % iLOHost), "PATCH", headers, BIOSsettingsBody)
                    logging.info(f"Patch response : {patchRequest[0]['error']['@Message.ExtendedInfo']}")
                    retVal = 0
                else:
                    logging.info(f"No changes in SMBIOS.")
                    retVal = 0

                logging.info(f"validating SMBIO's")
                getRequest = MakeRestRequest((BIOSsettingsURL % iLOHost), "GET", headers, "")
                logging.info(f"Attribute ProductID : {getRequest[0]['Attributes']['ProductId']}")
            except Exception as e:
                logging.error(f"Exception is stamping SMBIOS. Exception: {e}.")
        else:
            logging.info("System model not found.")
            retVal = 1
    except Exception as e:
        logging.error(f"Exception in stamping SMBIOS. Exception: {e}.")
        retVal = 1
    return retVal

def disableSNMPv1(iLOHost):
    """
    This task will disable SNMPv1 in the iLO and the iLO has to be reset for the change to take effect.
    :param iLOHost: The ip address of the iLO
    :return: if successful then 0 else 1 if an error occurs.
    """
    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        # logging.info("Ensure valid iLO session is there for the host %s" % iLOHost)
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }

    try:
        snmpBody = {
            "SNMPv1Enabled": False
        }

        patchRequest = MakeRestRequest((snmpConfigURL % iLOHost), "PATCH", headers, snmpBody)
        logging.info(f"Patch response : {patchRequest[0]['error']['@Message.ExtendedInfo']}")
    except Exception as e:
        logging.error(f"Exception in disabling SNMPv1 on {iLOHost}.")

def validatedisableSNMPv1(iLOHost):
    """
    This task will validate disable SNMPv1 in the iLO.
    :param iLOHost: The ip address of the iLO
    :return: if successful then 0 else 1 if an error occurs.
    """
    retVal = 0

    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }

    try:
        logging.info("Validating disable SNMPv1 settings")
        serviceGetRoot = MakeRestRequest((snmpConfigURL % iLOHost), "GET", headers, '')
        if not serviceGetRoot[0]['SNMPv1Enabled']:
            logging.info("SNMP is disabled")
            retVal = 0
        else:
            logging.info("SNMP is not disabled")
            retVal = 1
    except Exception as e:
        logging.error("Exception in validating disable SNMPv1")
        retVal = 1
    return retVal

def enableSNMP(iLOHost,TargetPort):
    """
    This task will enable SNMPv1 in the iLO .
    :param iLOHost: The ip address of the iLO
    :param TargetPort: port number of Targetport
    :return: if successful then 0 else 1 if an error occurs.
    """
    retVal = 0

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    
    try:
        
        snmpBody = {
				"SNMP": {"Port": TargetPort, "ProtocolEnabled": True}
            }         
        
        MakeRestRequest((snmpURL % iLOHost),"PATCH",headers,snmpBody)

    except Exception as e:
        logging.error("Exception in enabling SNMP")
        retVal = 1

    return retVal 

def enableSNMPconfig(iLOHost, snmp_dict):
    """
    This task will configure SNMP i.e create user, contact, location, AlertDestinations, AlertDestinationAssociations in the iLO .
    :param iLOHost: The ip address of the iLO
    :param snmp_dict: list of snmp configuration
    """
    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        # logging.info("Ensure valid iLO session is there for the host %s" % iLOHost)
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }

    try:
        snmpConfigBody = {
            "AlertDestinationAssociations": [
                {"SNMPAlertProtocol": snmp_dict['version'],
                 "SecurityName": snmp_dict['securityName']}
            ],
            "AlertDestinations": [
                snmp_dict['targetIPAddress']
            ],
            "Contact": snmp_dict['contact'],
            "Location": snmp_dict['location'],
            "Users": [
                {
                    "AuthProtocol": snmp_dict['authenticationType'],
                    "AuthPassphrase": snmp_dict['authenticationPassPhrase'],
                    "PrivacyProtocol": snmp_dict['encryptionType'],
                    "PrivacyPassphrase": snmp_dict['authenticationPassPhrase'],
                    "SecurityName": snmp_dict['securityName'],
                }
            ],
        }
        patchRequest = MakeRestRequest((snmpConfigURL % iLOHost), "PATCH", headers, snmpConfigBody)
        logging.info(f"Patch response : {patchRequest[0]['error']['@Message.ExtendedInfo']}")
    except Exception as e:
        logging.error("Exception in configuring SNMP")

def validateSNMP(iLOHost):
    """
    This task will validate SNMP v3 in the iLO.
    :param iLOHost: The ip address of the iLO
    :return: if successful then 0 else 1 if an error occurs.
    """
    retVal = 0

    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }

    try:
        logging.info("Validating SNMP settings")
        serviceGetRoot = MakeRestRequest((snmpURL % iLOHost), "GET", headers, '')
        if serviceGetRoot[0]['SNMP']['ProtocolEnabled']:
            logging.info("SNMP is enabled")
            retVal = 0
        else:
            logging.info("SNMP is disabled")
            retVal = 1
    except Exception as e:
        logging.error("Exception in enabling SNMP")
        retVal = 1
    return retVal

def ConfigureNTP(iLOHost,ntpServer1):

    retVal = 0

    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION


    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }
    
    try:
        logging.info("Disabling DHCPv6 Supplied Time Settings for the host %s" % iLOHost)
        dhcp_body = {
                    "Oem": {
                        "Hpe": {            
                            "DHCPv4": {
                                "UseNTPServers": False
                            },
                            "DHCPv6": {
                                "UseNTPServers": False
                            }
                        }
                    }
                }
                
        MakeRestRequest( (DedicatediLONetworkURL % iLOHost),"PATCH",headers,dhcp_body)  
        
        logging.info("Configuring Static NTP servers for the host %s" % iLOHost)
        ntpBody = {
            "StaticNTPServers": [
                ntpServer1
            ]
        }
        Res = MakeRestRequest( (NtpURL % iLOHost),"PATCH",headers,ntpBody)

    except Exception as e:
        logging.error("Exception in configuring NTP")
        retVal = 1

    return retVal
    
def OneButtonSecureErase(iLOHost):

    retVal = 0

    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION


    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }

    try:
        resetBody = {
            "SystemROMAndiLOErase": True,
            "UserDataErase": True
        }

        resetRes = MakeRestRequest( (iLOSecureEraseURL % iLOHost),"POST",headers,resetBody)

    except Exception as e:
        logging.error("Exception in One-button secure erase. Exception: %s " % e)
        retVal = 1

    return retVal

def getProductID(version):
    prod_id = None
    try:
        prodIDFilePath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "ProductID.json")
        with open(prodIDFilePath,'r') as prodid_file:
            productid_data = json.load(prodid_file)
        exp = parse('$.Products')
        valist  = exp.find(productid_data)
        vallist = valist[0].value
        prod_id = next((val['ProductID'] for val in vallist if val['Version'] == version),None)
    except Exception as e:
        logging.error("Error loading ProuctID JSON %s. Error: %s" %(prodIDFilePath,e))
    return prod_id

def enableDHCPv4(iLOHost):
    """
    This task will Enable DHCPv4 in the iLO and the iLO has to be reset for the changes to take effect.
    :param host: The ip address of the iLO
    """
    retVal = 0
    # Check for valid session
    bInvalidSession = False
    bInvalidSession = check4InvalidSession(iLOHost)

    if bInvalidSession:
        #logging.info("Ensure valid iLO session is there for the host %s" % iLOHost)
        logging.error(f"Ensure valid iLO session is there for the host {iLOHost}.")
        return ERROR_INVALID_SESSION

    headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[iLOHost]
    }

    try:
        dhcpBody = {
                "DHCPv4": {
                    "DHCPEnabled": True,
                    "UseDNSServers": True,
                    "UseDomainName": True,
                    "UseGateway": True,
                    "UseNTPServers": True,
                    "UseStaticRoutes": True
                }
            }
        logging.info("Executing enable DHCP API")
        patchRequest = MakeRestRequest((DedicatediLONetworkURL % iLOHost),"PATCH",headers,dhcpBody)
        logging.info(f"Patch response : {patchRequest[0]['error']['@Message.ExtendedInfo']}")
    except Exception as e:
        logging.error(f"Exception in enabling DHCP : ${e}")

def SystemPSUHealth(host):
    retVal = 0
        # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(host)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {host}.")
        return ERROR_INVALID_SESSION

    try:
        headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[host]
        }    
        
        compRes = MakeRestRequest((chassisPowerURL % host),"GET",headers,"")
        # print (compRes)
        
        #We can be smarter than this, but for now, we will just assume 2 power supplies
        for i in 0,1:
            status = compRes[0]['PowerSupplies'][i]['Oem']['Hpe']['PowerSupplyStatus']['State']
            if status != "Ok":
                retVal = 1
                logging.error(f"Power Supply {i} has reported the status of {status}")
                #print(status)
        
    except Exception as e:
        logging.error(f"Exception in checking the PSU status of the system {host}. Exception: {e}.")
        retVal = 1
    
    return retVal  

def SystemMemoryHealth(host):
    retVal = 0
        # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(host)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {host}.")
        return ERROR_INVALID_SESSION

    try:
        headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[host]
        }    
        
        compRes = MakeRestRequest((computerSystem1URL % host),"GET",headers,"")
        # print (compRes)
                
        status = compRes[0]['MemorySummary']['Status']['HealthRollup']
        if status != "OK":
            retVal = 1
            logging.error(f"Memory health has reported the status of {status}")
            print(status)
        
    except Exception as e:
        logging.error(f"Exception in checking the memory health in the system {host}. Exception: {e}.")
        retVal = 1
    
    return retVal 

def SystemCPUHealth(host):
    retVal = 0
        # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(host)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {host}.")
        return ERROR_INVALID_SESSION

    try:
        headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[host]
        }    
        
        compRes = MakeRestRequest((computerSystem1URL % host),"GET",headers,"")
        #print (compRes)
                
        status = compRes[0]['ProcessorSummary']['Status']['HealthRollup']
        if status != "OK":
            retVal = 1
            logging.error(f"Processor health has reported the status of {status}")
            print(status)
        
    except Exception as e:
        logging.error(f"Exception in checking the Processor health in the system {host}. Exception: {e}.")
        retVal = 1
    
    return retVal 

def SystemStorageHealth(host):
    retVal = 0
    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(host)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {host}.")
        return ERROR_INVALID_SESSION

    try:
        headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[host]
        }    
        
        compRes = MakeRestRequest((arrayControllerURL % host),"GET",headers,"")
        #print (compRes)
                
        status = compRes[0]['Status']['Health']
        if status != "OK":
            retVal = 1
            logging.error(f"Storage health has reported the status of {status}")
            print(status)
        
    except Exception as e:
        logging.error(f"Exception in checking the Storage health in the system {host}. Exception: {e}.")
        retVal = 1
    
    return retVal 

#
# Check iDevID.  We will need to make this work later once we start using Gen10+ or later
# and have access to the origonal certificate
#
def ValidateIDevIDCert(host,idevId):
    retVal = 0
    # Check for valid session
    bInvalidSession = False    
    bInvalidSession = check4InvalidSession(host)

    if bInvalidSession:
        logging.error(f"Ensure valid iLO session is there for the host {host}.")
        return ERROR_INVALID_SESSION

    try:
        headers = {
        'content-type': "application/json",
        'X-Auth-Token': authCodeMap[host]
        }    
        
        compRes = MakeRestRequest((IDevIDURL % host),"GET",headers,"")
        # print (compRes[0]['SerialNumber'])
        # print (compRes[0]['CertificateString'])
        status = compRes[0]['SerialNumber']
        if status != idevId:
            retVal = 1
            logging.error(f"---ERROR: IDevID of server does not match that of what shipped from the HPE Factory.---")
            print(status)
        
    except Exception as e:
        logging.error(f"Exception in checking the IDevID in the system {host}. Exception: {e}.")
        retVal = 1

    return retVal 
