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

def getToken(url, user, tenant, password):

    """
    Returns a token to the user given a tenant,
    user name, password, and OpenStack API URL.
    """
    url = url + '/tokens'
    tokenRequest = urllib2.Request(url)
    tokenRequest.add_header("Content-type", "application/json")
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
   
    request = urllib2.urlopen(tokenRequest, jsonPayload)
    json_data = json.loads(request.read())
   
    request.close()
    return json.dumps(json_data)

def getPorts(url, token):

    """
    Returns ports for the given tenant.
    """
    url = url + '/v2.0/ports'
    portRequest = urllib2.Request(url)
    portRequest.add_header("Content-type", "application/json")
    portRequest.add_header("X-Auth-Token", token)

    request = urllib2.urlopen(portRequest)
    json_data = json.loads(request.read())

    request.close()
    return json.dumps(json_data)

def getNetworks(url, token):

    """
    Returns networks
    """
    url = url + '/v2.0/networks'
    networkRequest = urllib2.Request(url)
    networkRequest.add_header("Content-type", "application/json")
    networkRequest.add_header("X-Auth-Token", token)

    request = urllib2.urlopen(networkRequest)
    json_data = json.loads(request.read())

    request.close()
    return json.dumps(json_data)

def getNetworkNames(networks):
    """
    Returns network name list
    """
    networkNames = []
    for network in networks['networks']:
        networkNames.append(network['name'])
    return networkNames

def getServers(url, token):

    """
    Returns instances for the given tenant.
    """
    url = url + '/servers/detail?all_tenants=1'
    serverRequest = urllib2.Request(url)
    serverRequest.add_header("Content-type", "application/json")
    serverRequest.add_header("X-Auth-Token", token) 

    request = urllib2.urlopen(serverRequest)
    json_data = json.loads(request.read())

    request.close()
    return json.dumps(json_data)


def checkPortStatus(ip):
    
    """
    Returns port active status with ping test.
    """
    cmd = 'ping -c 1 -W 3 ' + ip
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

def getServerPortStatus(servers, networks, downServers):

    """
    Returns server port active status with ping test.
    """
    networks = getNetworkNames(networks)
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
mandatory = parser.add_argument_group("mandatory")
mandatory.add_argument("-n", "--username", help="The administrative user for your OpenStack installation", type=str)
mandatory.add_argument("-p", "--password", help="The administrative user's password", type=str)
mandatory.add_argument("-t", "--tenant", help="The administrative user's tenant / project", type=str)
mandatory.add_argument("-u", "--url", help="The Keystone API endpoint from running, 'nova endpoints'", type=str)
args = parser.parse_args()

# Validate arugments were given
if type(args.url) != type(str()):
    sys.stderr.write('Invalid URL: %s\n' % args.url)
    parser.print_help()
    sys.exit(2)
if type(args.tenant) != type(str()):
    sys.stderr.write('Invalid tenant: %s\n' % args.tenant)
    parser.print_help()
    sys.exit(2)
if type(args.password) != type(str()):
    sys.stderr.write('Invalid password: %s\n' % args.password)
    parser.print_help()
    sys.exit(2)
if type(args.username) != type(str()):
    sys.stderr.write('Invalid username: %s\n' % args.username)
    parser.print_help()
    sys.exit(2)
   
adminToken = json.loads(getToken(args.url, args.username, args.tenant, args.password))
adminTokenID = adminToken['access']['token']['id']
adminTokenTenantID = adminToken['access']['token']['tenant']['id']

# Get Quantum service endpoint
for item in adminToken['access']['serviceCatalog']:
    if item['name'] == "quantum":
        adminQuantumURL = item['endpoints'][0]['adminURL']
    if item['name'] == "nova":
        adminNovaURL = item['endpoints'][0]['adminURL']

# Get servers for given tenant
servers = json.loads(getServers(adminNovaURL, adminTokenID))
networks = json.loads(getNetworks(adminQuantumURL, adminTokenID))
ports = json.loads(getPorts(adminQuantumURL, adminTokenID))

portDownServers = []
getServerPortStatus(servers, networks, portDownServers)
downPorts = []
getPortStatus(ports, downPorts)

print ""
print "====================PORT DOWN SERVERS======================="
for server in portDownServers:
    print "Server ID:", server['id'], "Name:", server['name'], "IP address:", server['ip']
print ""
print "====================DOWN PORTS======================="
for port in downPorts:
    print "Port ID:", port['id'], "IP address:", port['ip']
