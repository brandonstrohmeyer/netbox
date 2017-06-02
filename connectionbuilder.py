#!/usr/bin/python
#
# Netbox Connections Script v1.0
#
# "site" and "role" input dictate which device roles in what data center are processed.
# Script will check ARP table in "core-switch" role to get MAC address and then
# will iterate though all devices in "access-switch" role to correlate MAC address to
# physical port. Will check Netbox for existing records before making a write API call.
#
# Install requirements via pip:
#  pysnmp
#  pysnmp-mibs
#  netaddr
#

# SNMP community string
snmpcommunity = 'community'

# Base URL for netbox API
apiBaseUrl    = 'https://netbox.example.com/api'

# Netbox slug for physical site
site          = 'abc'

# Netbox slug for device role
role          = 'server'

# Netbox API authentication token
token         = 'Token abc123'

### End of Configuration ###

import subprocess
import re
import time
import requests
from netaddr import *
from pysnmp.hlapi import *

headers = {
                   'Content-Type':'application/json',
                   'Accept':'application/json',
                   'Authorization': token
                  }

ipList = []
switchList = []

# Get IP of site core switch for ARP lookup
def get_coreswitch(site):
    resp = requests.get(apiBaseUrl + '/dcim/devices/?role=core-switch&site='+ site,
                        headers=headers).json()
    return resp['results'][0]['primary_ip']['address']

# Get IP of site access switches for MAC lookup
def get_accessswitch(site):
    resp = requests.get(apiBaseUrl + '/dcim/devices/?role=access-switch&site='+ site,
                        headers=headers).json()
    for i in resp['results']:
        if i['primary_ip4'] != None:
            switchList.append((re.sub(r'/.+$', '', i['primary_ip4']['address'])))

get_accessswitch(site)

# Strip VLSM from IP Address
coreHost = (re.sub(r'/.+$', '', get_coreswitch('clt')))

# Get list of IP addresses for Netbox role
def get_iplist(role):
    resp = requests.get(apiBaseUrl + '/dcim/devices/?limit=2&role=' + role,
                        headers=headers).json()
    for i in resp['results']:
        if i['primary_ip4'] != None:
            ipList.append(i['primary_ip4']['address'])
        else:
            print "Host has no IP Address: " + i['name']

    while resp['next'] != None:
        resp = requests.get(re.sub('http', 'https', resp['next']),
                            headers=headers).json()

        for i in resp['results']:
            if i['primary_ip4'] != None:
                ipList.append(i['primary_ip4']['address'])
            else:
                print "Host has no IP Address: " + i['name']

get_iplist(role)

# Iterate over IP addresses in Netbox role to find MAC address and switchport connection
for hostIP in ipList:
    start = time.time()

    # Get vlan ID for IP address
    def get_vlanid(prefix):
        resp = requests.get(apiBaseUrl + '/ipam/prefixes/?q=' + prefix,
                            headers=headers).json()
        return resp['results'][0]['vlan']['vid']

    snmpindex = get_vlanid(str(IPNetwork(hostIP).network) + '/' + str(IPNetwork(hostIP).prefixlen))

    # Strip VLSM from IP Address once get_vlanid is finished
    hostIP = (re.sub(r'/.+$', '', hostIP))

    print "Processing host " + hostIP

    # Ping target to populate ARP and CAM table
    try:
        subprocess.check_output(['ping', '-c', '2', '-i', '.2', hostIP])
    except:
        print " - ICMP check failed"

    ifList = []
    arpOidList = []
    arpValList = []

    # Get ARP table from core host
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in bulkCmd(SnmpEngine(),
                              CommunityData(snmpcommunity, mpModel=1),
                              UdpTransportTarget((coreHost, 161)),
                              ContextData(),
                              0, 100,
                              ObjectType(ObjectIdentity('IP-MIB', 'ipNetToMediaPhysAddress')),
                              lexicographicMode=False):
        if errorIndication:
            print(errorIndication)
            break
        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
            break
        else:
            for oid, val in varBinds:
                oid = oid.prettyPrint()
                val = val.prettyPrint()
                arpOidList.append(re.sub('IP-MIB::ipNetToMediaPhysAddress\.[^.]*\.', '', oid))
                arpValList.append(val)
    arpDict = dict(zip(arpOidList, arpValList))
    hostMAC = arpDict.get(hostIP)
    if hostMAC == None:
        print " - No MAC address found, skipping"
        print ""
        continue

    for poolHost in switchList:
        macList = []
        portList = []
        portIndexVal = []
        portIndexOid = []
        ifNameOid = []
        ifNameVal = []

        # Get hostname from host
        for (errorIndication,
             errorStatus,
             errorIndex,
             varBinds) in bulkCmd(SnmpEngine(),
                                  CommunityData(snmpcommunity, mpModel=1),
                                  UdpTransportTarget((poolHost, 161)),
                                  ContextData(),
                                  0, 100,
                                  ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName')),
                                  lexicographicMode=False):
            if errorIndication:
                print(errorIndication)
                break
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),
                                    errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
                break
            else:
                for oid, val in varBinds:
                    val = val.prettyPrint()
            hostName = re.sub(r'\..+$', '', val)

    # Get list of MAC addresses from host
        for (errorIndication,
             errorStatus,
             errorIndex,
             varBinds) in bulkCmd (SnmpEngine(),
                              CommunityData( snmpcommunity + "@" + str(snmpindex), mpModel=1),
                              UdpTransportTarget((poolHost, 161)),
                              ContextData(),
                              0, 100,
                              ObjectType(ObjectIdentity('BRIDGE-MIB', 'dot1dTpFdbAddress')),
                              lexicographicMode=False):
            if errorIndication:
                print(errorIndication)
                break
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
                break
            else:
                for oid, val in varBinds:
                    macList.append(val.prettyPrint())

    # Get bridge port table from host
        for (errorIndication,
             errorStatus,
             errorIndex,
             varBinds) in bulkCmd (SnmpEngine(),
                              CommunityData( snmpcommunity + "@" + str(snmpindex), mpModel=1),
                              UdpTransportTarget((poolHost, 161)),
                              ContextData(),
                              0, 100,
                              ObjectType(ObjectIdentity('BRIDGE-MIB', 'dot1dTpFdbPort')),
                              lexicographicMode=False):
            if errorIndication:
                print(errorIndication)
                break
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
                break
            else:
                for oid, val in varBinds:
                    portList.append(val.prettyPrint())
        try:
            bridgePort = portList[macList.index(hostMAC)]

        # If MAC address is not found in CAM table, stop and continue with next switch.
        except:
            continue

        # Get interface index from host
        for (errorIndication,
             errorStatus,
             errorIndex,
             varBinds) in bulkCmd (SnmpEngine(),
                              CommunityData( snmpcommunity + "@" + str(snmpindex), mpModel=1),
                              UdpTransportTarget((poolHost, 161)),
                              ContextData(),
                              0, 100,
                              ObjectType(ObjectIdentity('BRIDGE-MIB', 'dot1dBasePortIfIndex')),
                              lexicographicMode=False):
            if errorIndication:
                print(errorIndication)
                break
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
                break
            else:
                for oid, val in varBinds:
                    oid = oid.prettyPrint()
                    oid = re.sub('BRIDGE-MIB::dot1dBasePortIfIndex\.', '', oid)
                    portIndexOid.append(oid)
                    portIndexVal.append(val.prettyPrint())
        portIndexDict = dict(zip(portIndexOid, portIndexVal))
        indexMap = portIndexDict.get(bridgePort)

        # Get interface name table from host
        for (errorIndication,
             errorStatus,
             errorIndex,
             varBinds) in bulkCmd (SnmpEngine(),
                              CommunityData( snmpcommunity + "@" + str(snmpindex), mpModel=1),
                              UdpTransportTarget((poolHost, 161)),
                              ContextData(),
                              0, 100,
                              ObjectType(ObjectIdentity('IF-MIB', 'ifName')),
                              lexicographicMode=False):
            if errorIndication:
                print(errorIndication)
                break
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
                break
            else:
                for oid, val in varBinds:
                    oid = oid.prettyPrint()
                    oid = re.sub('IF-MIB::ifName\.', '', oid)
                    ifNameOid.append(oid)
                    ifNameVal.append(val.prettyPrint())
        ifNameDict = dict(zip(ifNameOid, ifNameVal))
        ifList.append(ifNameDict.get(indexMap))
        ifDict = dict(zip(switchList, ifList))
        ifDict= {key: val for key, val in ifDict.iteritems() if not val.startswith( 'Po' )}

        # Break if needed
        if len(ifDict) > 0:
            break

    # Update Netbox records
    for key, val in ifDict.items():

        print "  Updating Netbox..."

        # Get PK of host interface
        def get_hostInterfaceId(ip4):
            resp = requests.get(apiBaseUrl + '/ipam/ip-addresses/?q=' + ip4,
                                headers=headers).json()
            return resp['results'][0]['interface']['id']

        # Get PK of uplink switch interface
        def get_switchportId(switchName, switchPort):
            resp = requests.get(apiBaseUrl + '/dcim/devices/?q=' + switchName,
                                headers=headers).json()
            resp = requests.get(apiBaseUrl + '/dcim/interfaces/?device_id=' + str(resp['results'][0]['id'])
                                + '&name=' + switchPort,
                                headers=headers).json()
            return resp['results'][0]['id']

        # Set MAC address
        def set_mac(macAddress, interfaceId, existing=False):
            json = {'mac_address': macAddress}

            if existing == False:
                requests.patch(apiBaseUrl + '/dcim/interfaces/' + interfaceId + '/',
                               headers=headers, json=json )
                print"   - Added MAC address"

            elif existing == True:
                requests.patch(apiBaseUrl + '/dcim/interfaces/' + interfaceId + '/',
                               headers=headers, json=json )
                print"   - Updated MAC address"

        # Set interface connection
        def set_connection(intA, intB, connection_status='True', existing=False):
            json = {'connection_status': connection_status,
                    'interface_a': intA,
                    'interface_b': intB
                    }
            if existing == False:
                requests.post(apiBaseUrl + '/dcim/interface-connections/',
                              headers=headers, json=json).json()
                print"   - Added new connection"
            elif existing == True:
                requests.patch(apiBaseUrl + '/dcim/interface-connections/',
                               headers=headers, json=json).json()
                print "   - Updated existing interface"

        # Check to see if correct MAC address exists, update if false
        resp = requests.get(apiBaseUrl + '/dcim/interfaces/' + str(get_hostInterfaceId(hostIP)),
                            headers=headers).json()
        if resp['mac_address'] == None:
            set_mac(hostMAC, str(get_hostInterfaceId(hostIP)))

        elif resp['mac_address'].lower() != hostMAC:
            set_mac(hostMAC, str(get_hostInterfaceId(hostIP)), existing=True)

        else:
            print "   - No MAC update required!"


        # Check to see if correct interface connection exists, update if false
        if resp['connected_interface'] == None:
            set_connection(str(get_switchportId(hostName, val)), str(get_hostInterfaceId(hostIP)))

        elif resp['connected_interface']['id'] != get_switchportId(hostName, val):
            set_connection(str(get_switchportId(hostName, val)), str(get_hostInterfaceId(hostIP)), existing=True)

        else:
            print "   - No interface update required!"

        end = time.time()
        print "  Summary:"
        print "  Host MAC Address:", hostMAC
        print "  Uplink Switch:", hostName
        print "  Uplink Port:", val
        print "  Execution time:", (end - start)
        print ""