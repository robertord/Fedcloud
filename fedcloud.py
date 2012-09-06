#!/usr/bin/python

import sys
import os
import json
import urllib2
import re
import commands
import getpass
from stratuslab.Exceptions import InputException, ExecutionException
from stratuslab.ManifestInfo import ManifestInfo
import stratuslab.Util as Util

###
### Define this variables to get your certificates
#path for usercert.pem and userkey.pem files
certpath="~/.globus"
#path for CA's files
capath="/etc/grid-security/certificates/"
###
###

etree = Util.importETree()

NS_DCTERMS = 'http://purl.org/dc/terms/'

def _parseXml(xmlAsString):
    return etree.fromstring(xmlAsString)


def _extractMetadataInfos(manifestRootElement):
    manifestElements = manifestRootElement.findall('{http://www.w3.org/1999/02/22-rdf-syntax-ns#}RDF')
    manifests = []
    infos = []

    for e in manifestElements:
	manifest = ManifestInfo()
	manifest.parseManifestFromXmlTree(e)
	if len(manifest.locations)>0:
	    info = {'md5': manifest.md5, 'os': manifest.os, 'os-version':manifest.osversion,'os-arch':manifest.arch, 'location':manifest.locations[0], 'creator':manifest.creator, 'valid':manifest.valid.replace("T"," "), 'description':manifest.comment, 'publisher':manifest.publisher, 'identifier':manifest.identifier}
	    #parse extra attributes
	    requires = getattr(e.find('.//{%s}requires' % NS_DCTERMS), 'text','')
	    if requires:
		info['requires'] = requires
		infos.append(info)
	print info
    return infos


def _getMetadataInfo(endpoint):
    url = '%s/metadata' % endpoint 
    metadataEntries = ''
    try:
	metadataEntries = Util.wstring(url)
    except urllib2.HTTPError:
	raise InputException('Failed to find metadata entries: %s' % url)

    return _extractMetadataInfos(_parseXml(metadataEntries))


def menuMain():
    os.system('clear')
    print ("\n\n\n")
    print "\t[1] List Running Machines"
    print "\t[2] Launch Machine"
    print "\t[3] Delete Machine"
    print "\t[4] Exit"
	
	
def menuLaunch(dataList):
    os.system('clear')
    print ("\n\n")
    i=0
    for machine in dataList:
	print "\n\t[",i,"] ",machine["publisher"]," |-| ",machine["description"]
	print "\t\tMachine created by",machine["creator"]," with",machine["os"],machine["os-version"],machine["os-arch"]," is valid until",machine["valid"]
	print "\t\tMachine location: ",machine["location"]
	i+=1
    print "\n\t[",i,"] Back."
    return i


def menuMachines(machines):
    os.system('clear')
    print "\n\n\n"
    i=0
    for machine in machines:
	if 'title' in machine:
	    print "\t[",i,"] ",machine['title']," running in ",machine['endpoint']
	if 'summary' in machine:
	    print "\t\t",machine['summary']
	if 'ip' in machine:
	    print "\t\tIP:",machine['ip']
	print "\t\tNumber of cores:",machine['cores']," Memory:",machine['memory']," Architecture:",machine['architecture']
	if 'status' in machine:
	    print "\t\tStatus: ",machine['status']
	if 'vncweb' in machine:
	    print "\t\tVNC web link: ",machine['vncweb']
	if 'vnc' in machine:
	    print "\t\tVNC link: ",machine['vnc']
	if 'occi_id' in machine:
	    print "\t\tOCCI id: ",machine['occi_id']
	print "\n"
	i+=1
    if len(machines)==0:
	print "\n\t\tThere is not any machine running yet."
    return i
    

def machineLaunch(metadataList):
    numberMachines=menuLaunch(metadataList)
    key=-1
    #while 1:	
        #try:
	    #key=int(raw_input('\n\t - Input one option above: '))
	#except ValueError:
	    #print "\n\t\t*-*-* You must enter a number *-*-*"
    numList=[]
    numbs=raw_input("\n\t - Enter a list of number machine separated by commas (,) : ").split(",")
    for i in numbs:
	try:
	    numbs2=int(i)
	    numList.append(numbs2)
	except ValueError:
	    print "\n\t - Value ",i," is incorrect. Ignoring ..."  
	    raw_input('\n\n\n\tPress enter to continue...')

    for key in numList:
	if key>=0 and key<numberMachines:
	    os.system('clear')
	    print "\n\n ****** Launching machine ",metadataList[key]["location"],"\n"
	    print " ****** Network ",metadataList[key]["requires"],"\n"
	    #compute value is not present in xml info, so it must be calculate from location or requires
	    pat = re.compile(r'http[s]{0,1}://[a-z].[a-z][a-z.0-9]*:[0-9]+')
	    endpoint = re.findall(pat,metadataList[key]["location"])
	    print " ****** Compute: ",endpoint[0]
		
	    #create necessary values for curl command
	    comCategory = 'compute;scheme="http://schemas.ogf.org/occi/infrastructure#";class="kind";'	    
	    comAttribute = "occi.core.title="+"\"FedCloud Testing:"+metadataList[key]["identifier"]+"\","
	    comAttribute += "occi.core.summary=\""+metadataList[key]["description"]+"\","
	    comAttribute += "occi.compute.architecture=\"x64\","
	    comAttribute += "occi.compute.cores=1,"
	    comAttribute += "occi.compute.memory=2"

	    comLink = "<"+metadataList[key]["requires"].replace(endpoint[0],'')+">"+";rel=\"http://schemas.ogf.org/occi/infrastructure#network\";category=\"http://schemas.ogf.org/occi/core#link\";,"
	    comLink += "<"+metadataList[key]["location"].replace(endpoint[0],'')+">"+";rel=\"http://schemas.ogf.org/occi/infrastructure#storage\";category=\"http://schemas.ogf.org/occi/core#link\";"
	    
	    found=0
	    if len(insecures) > 0:
		for site in insecures:
		    if endpoint[0].find(site) != -1:
			instantiate="curl -s --sslv3 --insecure --cert "+certpath+"/usercert.pem:"+passwd+" --key "+certpath+"/userkey.pem -X POST -v "+endpoint[0]+"/compute/ --header \'Link: "+comLink+"\' --header \'X-OCCI-Attribute: "+comAttribute+"\' --header \'Category: "+comCategory+"\'"
			found = 1
			break
	    if found == 0:
		instantiate="curl -s --sslv3 --cert "+certpath+"/usercert.pem:"+passwd+" --key "+certpath+"/userkey.pem -X POST -v "+endpoint[0]+"/compute/ --capath "+capath+" --header \'Link: "+comLink+"\' --header \'X-OCCI-Attribute: "+comAttribute+"\' --header \'Category: "+comCategory+"\'"
	    
	    if debug == 1: print "Launched:",instantiate.replace(passwd,"xxxxxx")
	    status, result = commands.getstatusoutput(instantiate)
	    
	    if result.find('Status: 200') != -1:
		if debug == 1: print result
		print "\n\n ****** Machine ",metadataList[key]["identifier"]," launched in ",endpoint[0]," correctly."
		pat = re.compile(r'http[s]{0,1}://[a-z].[a-z][a-z.0-9]*:[0-9]+[a-z.0-9/\-]*')
		link = re.findall(pat,result)
		print "\t  Link to machine: ",link[0]
	    else: 
		if debug == 1: print result
		print "\n\t\tError launching selected machine."
	    raw_input('\n\n\n\tPress enter to continue...')
		
	if key==numberMachines: 
	    break
	    

def machineList(metadataList):
    os.system('clear')
    print "\n\n\n"
    print "\t\tLooking for valid fedcloud machines running....\n"
    validMachines = []
    info = []
    for machine in metadataList:
	pat = re.compile(r'http[s]{0,1}://[a-z].[a-z][a-z.0-9]*:[0-9]+')
	endpoint = re.findall(pat,machine["location"])
	#check that endpoint/compute has at least one "X-OCCI-Location:" running, else don't do nothing
	#usefull also to check that user running script has appropiate cerficate
	found=0
	if len(insecures) > 0:
	    for site in insecures:
		if endpoint[0].find(site) != -1:
		    checkRunning = "curl -s -sslv3 --insecure --cert "+certpath+"/usercert.pem:"+passwd+" --key "+certpath+"/userkey.pem "+endpoint[0]+"/compute/ | awk \'{ print $1 }\'"
		    found = 1
		    break
	if found == 0:
	    checkRunning = "curl -s --cert "+certpath+"/usercert.pem:"+passwd+" --key "+certpath+"/userkey.pem "+endpoint[0]+"/compute/ --capath "+capath+" | awk \'{ print $1 }\'"
	if debug == 1: print "Launched:",checkRunning.replace(passwd,"xxxxxx")
	status, checkResult = commands.getstatusoutput(checkRunning)
	if checkResult.find("X-OCCI-Location:") != -1:
	    
	    found=0
	    if len(insecures) > 0:
		for site in insecures:
		    if endpoint[0].find(site) != -1:
			runningMachines = "curl -s --insecure --cert "+certpath+"/usercert.pem:"+passwd+" --key "+certpath+"/userkey.pem "+endpoint[0]+"/compute/ | awk \'{ print $2 }\'"
			found = 1
			break
	    if found == 0:
		runningMachines = "curl -s --cert "+certpath+"/usercert.pem:"+passwd+" --key "+certpath+"/userkey.pem "+endpoint[0]+"/compute/ --capath "+capath+" | awk \'{ print $2 }\'"
	    if debug == 1: print "Launched:",runningMachines.replace(passwd,"xxxxxx")
	    status, machines = commands.getstatusoutput(runningMachines)
	    listMachines = machines.splitlines()
	    
	    for m in listMachines:
		found=0
		if len(insecures) > 0:
		    for site in insecures:
			if endpoint[0].find(site) != -1:
			    comm = "curl -s --insecure --cert "+certpath+"/usercert.pem:"+passwd+" --key "+certpath+"/userkey.pem "+m
			    found = 1
			    break
		if found == 0:
		    comm = "curl -s --cert "+certpath+"/usercert.pem:"+passwd+" --key "+certpath+"/userkey.pem --capath "+capath+" "+m
		if debug == 1: print "Launched:",comm.replace(passwd,"xxxxxx")
		status, occiValues = commands.getstatusoutput(comm)
		##only must be saved/showed valid machines for fedcloud or by user, attending occi values
		machineValues = occiValues.splitlines()
		info={}
		for m in machineValues:
		    if m.find("occi.core.title=") != -1:
			info['title']=m.replace("X-OCCI-Attribute: occi.core.title=","").replace("\"","")
		    if m.find("occi.core.summary=") != -1:
			info['summary']=m.replace("X-OCCI-Attribute: occi.core.summary=","").replace("\"","")
		    if m.find("opennebula.vm.ip=") != -1:
			info['ip']=m.replace("X-OCCI-Attribute: opennebula.vm.ip=","").replace("\"","")
		    if m.find("opennebula.vm.vnc=") != -1:
			info['vnc']=m.replace("X-OCCI-Attribute: opennebula.vm.vnc=","").replace("\"","")
		    if m.find("opennebula.vm.web_vnc=") != -1:
			info['vncweb']=m.replace("X-OCCI-Attribute: opennebula.vm.web_vnc=","").replace("\"","")
		    if m.find("occi.compute.cores=") != -1:
			info['cores']=m.replace("X-OCCI-Attribute: occi.compute.cores=","").replace("\"","")
		    if m.find("occi.compute.memory=") != -1:
			info['memory']=m.replace("X-OCCI-Attribute: occi.compute.memory=","").replace("\"","")
		    if m.find("occi.compute.architecture=") != -1:
			info['architecture']=m.replace("X-OCCI-Attribute: occi.compute.architecture=","").replace("\"","")
		    if m.find("occi.core.id=") != -1:
			info['occi_id']=m.replace("X-OCCI-Attribute: occi.core.id=","").replace("\"","")
		    if m.find("occi.compute.state=") != -1:
			info['status']=m.replace("X-OCCI-Attribute: occi.compute.state=","").replace("\"","")
		if info['title'].find(machine["identifier"]) != -1:
		    info['endpoint']=endpoint[0]
		    validMachines.append(info)
    return validMachines


def machineDelete(machines):
    #TODO: check user dn and try to show only machines matching dn
    numberMachines=menuMachines(machines)
    print "\n\t[",numberMachines,"] Back."
    key=-1
    numList=[]
    numbs=raw_input("\n\t - Enter a list of number machine separated by commas (,) : ").split(",")
    for i in numbs:
	try:
	    numbs2=int(i)
	    numList.append(numbs2)
	except ValueError:
	    print "\n\t - Value ",i," is incorrect. Ignoring ..."  
	    raw_input('\n\n\n\tPress enter to continue...')  

    for key in numList:
	if key>=0 and key<numberMachines:
	    os.system('clear')
	    print "\n\nDeleting machine: ", machines[key]['endpoint']+machines[key]['occi_id']
	    found=0
	    if len(insecures) > 0:
		for site in insecures:
		    if machines[key]['endpoint'].find(site) != -1:
			instantiate="curl -s --sslv3 --insecure --cert "+certpath+"/usercert.pem:"+passwd+" --key "+certpath+"/userkey.pem -X DELETE -v "+machines[key]['endpoint']+"/compute/"+machines[key]['occi_id']
			found = 1
			break
	    if found == 0:
		instantiate="curl -s --sslv3 --cert "+certpath+"/usercert.pem:"+passwd+" --key "+certpath+"/userkey.pem -X DELETE -v "+machines[key]['endpoint']+"/compute/"+machines[key]['occi_id']+" --capath "+capath
	    if debug == 1: print "Launched:",instantiate.replace(passwd,"xxxxxx")
	    status, result = commands.getstatusoutput(instantiate)
	    
	    if result.find('Status: 200') != -1:
		if debug == 1: print result
		print "\n\n ****** Machine ",machines[key]['endpoint']+"/compute/"+machines[key]['occi_id']," deleted correctly."
	    else: 
		if debug == 1: print result
		print "\n\t\tError deleting selected machine."
	    raw_input('\n\tPress enter to continue')
	if key==numberMachines: 
	    break
	    

def loadCertPasswd():
    os.system('clear')
    print ("\n\n\n Your passwd will be stored only in memory for this script running, to avoid ask many times. It will not be stored in any file.\n\n\n")
    valid = 0
    i = 0
    while valid == 0 and i < 5:
	p = getpass.getpass("\t - Insert userkey.pem password:")
	#status, result = commands.getstatusoutput("curl -s -S --insecure --cert usercert.pem:"+p+" --key userkey.pem https://meghacloud.cesga.es:3202")
	status, result = commands.getstatusoutput("openssl rsa -in "+certpath+"/userkey.pem -passin pass:"+p+" -check")
	if status == 0:
	    valid = 1
	    break
	i +=1
	print "\t\t\tWrong password, try number ",i,"\n"
    if i == 5:
	print "\n\n\n - Too many tries with wrong password.\n\n\tExiting ... \n\n"
	sys.exit()
    return p    

    
    
def usage():
    print "\n\tUsage: fedcloud.py <marketplace-endpoint> [--insecure=<site1,site2,site3> [--debug]"
    print "\t\tExample: python fedcloud.py http://marketplace.egi.eu --insecure=site1.com,site2.com --debug"
    exit(1)    


#main program
if (len(sys.argv) < 2):
    usage()
else:
    #checking args passed
    debug=0
    insecures=[]
    if len(sys.argv) > 2:
	if sys.argv[2].find("--insecure=") != -1:
	    insecures=sys.argv[2].replace("--insecure=","").split(",")
	    if len(sys.argv) > 3:
		if sys.argv[3] == "--debug":
		    debug=1
		else:
		    usage()
	else:
	    if sys.argv[2] == "--debug":
		debug=1
	    else:
		usage()
    ## 
    metadataList = _getMetadataInfo(sys.argv[1])
    passwd=loadCertPasswd()
    op = 1
    key=-1    
    while op>0 and op<5:
	menuMain()
	try:
	    key=int(raw_input('\n\t - Input one option above: '))
	except ValueError:
	    print "*-*-* You must enter a number *-*-*"
	    continue
	if key == 1:
	    menuMachines(machineList(metadataList))
	    raw_input('\n\tPress enter to continue')
	if key == 2:
	    machineLaunch(metadataList)
	if key == 3:
	    machineDelete(machineList(metadataList))
	if key == 4:
	    break
