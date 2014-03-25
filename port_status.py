#!/usr/bin/python

# Get server and port list from controller and
# extract IP addresses from the response.
# Then send ping to these IPs to check if the port is active.
# With this test, we can test if routing is correct.
# Result shows servers and ports failed getting ping response.
# Reference http://four-eyes.net/2012/11/openstack-api-python-script-example/

import argparse
import getopt
import json
import sys
import urllib2
import os
import environment as env
import datetime

def sendRequest(url, token=None, payload=None):

    """
    Make a request and send request.
    headers will be list of {key, value} dict.
    Returns response.
    """
    request = urllib2.Request(url)
    request.add_header("Content-type", "application/json")
    if token != None:
        request.add_header("X-Auth-Token", token)

    request = urllib2.urlopen(request, payload) 
    json_data = json.loads(request.read())

    request.close()
    return json.dumps(json_data)

def getToken(url, user, tenant, password):

    """
    Returns a token to the user given a tenant,
    user name, password, and OpenStack API URL.
    """
    url = url + '/tokens'
    data = { 
        "auth":{
            "tenantName": tenant,
            "passwordCredentials":{
                 "username": user,
                 "password": password
          }
       }
    }
    jsonPayload = json.dumps(data)
    return sendRequest(url, payload=jsonPayload)

def getPorts(url, token):

    """
    Returns ports for the given tenant.
    """
    url = url + '/v2.0/ports'
    return sendRequest(url, token)

def getNetworks(url, token):

    """
    Returns networks
    """
    url = url + '/v2.0/networks'
    return sendRequest(url, token)
    

def getNetworkNames(networks, interface):
    """
    Returns network name list
    """
    def _return_net_type(network):
        if network['name'].split('.')[-1] =='private':
            return 'eth1'
        return 'eth0'

    networkNames = []
    for network in networks['networks']:
        net_type = _return_net_type(network)
        if interface == None or interface == net_type:
            networkNames.append(network['name'])
    return networkNames

def getServers(url, token, hostname):

    """
    Returns instances for the given tenant.
    """
    url = url + '/servers/detail?all_tenants=1'
    if hostname != None:
        url = url + ('&host=%s') % hostname
    return sendRequest(url, token)

def getHypervisors(url, token):

    """
    Returns hypervisor list.
    """
    url = url + '/os-hypervisors'
    return sendRequest(url, token)

def isValidHypervisor(hypervisors, hostname):

    """
    Returns if the given hostname is valid.
    """
    for hypervisor in hypervisors['hypervisors']:
        if hypervisor['hypervisor_hostname'] == hostname:
            return True 
    return False

def checkPortStatus(ip):
    
    """
    Returns port active status with ping test.
    """
    cmd = 'ping -c 1 -W 2 ' + ip
    if os.system(cmd) == 0:
        return "ACTIVE"
    else:
        return "DOWN"

def getPortStatus(ports, downPorts):

    """
    Returns status of all ports.
    """
    for port in ports['ports']:
        for ip in port['fixed_ips']:
            status = checkPortStatus(ip['ip_address'])
            if status == "DOWN":
                downPorts.append({'id': port['id'], 'ip': ip['ip_address']})

def getServerPortStatus(servers, networks, interface, downServers):

    """
    Returns server port active status with ping test.
    """
    networks = getNetworkNames(networks, interface)
    for server in servers['servers']:
        for network in networks:
            try:
                for ip in server['addresses'][network]:
                    status = checkPortStatus(ip['addr'])
                    if status == "DOWN":
                        downServers.append({"id": server['id'], "name": server['name'], "ip": ip['addr']})
            except KeyError:
                # Pass if the network is not allocated for the VM
                continue

# Build our required arguments list
parser = argparse.ArgumentParser()
parser.add_argument("-c", "--cnode", help="Full hostname of cnode to check,\
                                     all ports will be return if not specified.", type=str)
parser.add_argument("-i", "--interface", help="Full hostname of cnode to check.", type=str)
args = parser.parse_args()

# Get admin token
adminToken = json.loads(getToken(env.AUTH_URL, env.USERNAME, env.TENANT, env.PASSWORD))
adminTokenID = adminToken['access']['token']['id']
adminTokenTenantID = adminToken['access']['token']['tenant']['id']

# Get Quantum service endpoint
for item in adminToken['access']['serviceCatalog']:
    if item['name'] == "quantum":
        adminQuantumURL = item['endpoints'][0]['adminURL']
    if item['name'] == "nova":
        adminNovaURL = item['endpoints'][0]['adminURL']

# Validate arugments were given
hypervisors = json.loads(getHypervisors(adminNovaURL, adminTokenID))
if args.cnode != None and (type(args.cnode) != type(str()) or
   isValidHypervisor(hypervisors, args.cnode) == False):
    sys.stderr.write('Invalid conde: %s\n\n' % args.cnode)
    parser.print_help()
    sys.exit(2)
if args.interface != None and (args.interface != 'eth0' and
                               args.interface != 'eth1'):
    sys.stderr.write('Invalid interface name: %s\n\n' % args.interface)
    parser.print_help()
    sys.exit(2)
    

# Get servers for given tenant
servers = json.loads(getServers(adminNovaURL, adminTokenID, args.cnode))
networks = json.loads(getNetworks(adminQuantumURL, adminTokenID))
#ports = json.loads(getPorts(adminQuantumURL, adminTokenID))

portDownServers = []
getServerPortStatus(servers, networks, args.interface, portDownServers)

#downPorts = []
#getPortStatus(ports, downPorts)
print ""
print "==================== PORT DOWN SERVERS: ", args.cnode, "======================="
f = open('port_status.log', 'a')
for server in portDownServers:
    data = "[%s] Server ID:%s  Name:%s  IP:%s\n" % (datetime.datetime.now(), server['id'], server['name'], server['ip'])
    print data
    f.write(data)
f.close()
print ""
#print "==================== DOWN PORTS:", args.cnode, "======================="
#for port in downPorts:
#    print "Port ID:", port['id'], "IP address:", port['ip']
