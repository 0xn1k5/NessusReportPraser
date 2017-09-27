#!/usr/bin/python

########################################################################################################
# Name: Nessus 6 Report visualizer and converter
# Author: Nikhil Raj ( nikhilraj149@gmail.com )
#
# Version: 1.0
# Last Updated: 7 Aug 2017
#
# Description:  The script parses multiple *.nessus report file(s) and generates neat summary per
#		host basis on the terminal. It allows to filter the output based on host, port, severity
#		or vulnerability description. This filtered output can be saved in csv format as well.
#
# Usage: 	python ./nessusReportParser.py -f <my_nessus_scan_xyz.nessus> <my_nessus_scan2_xyz.nessus>
#
# Requirements: This script requires below two libraries which may not be present by default in your
#		python installation:
#
#		1) LXML - Required for parsing nessus data
#		2) PrettyTable (Optional) - for formatting data in tabular fashion on terminal
#
#########################################################################################################

from os.path import isfile

# Importing pretty table library for printing data in tabular fashion [Optional]
# Use "sudo apt-get install python-prettytable" in ubuntu for package installation
try:
    from prettytable import PrettyTable
except ImportError:
    print "[-] Unable to load PrettyTable library, will print data in generic format"
    HAS_PRETTYTABLE=False
else:
    HAS_PRETTYTABLE=True

# Importing lxml library for parsing nessus data [Required
# Use "sudo apt-get install python-lxml" in ubuntu for package installation
try:
    from lxml import etree
except ImportError:
    print "[-] Failed to load lxml library"
    exit(-1)

# Options definition
import argparse
parser=argparse.ArgumentParser()
parser.add_argument("-f","--file",help="input nessus report file(s)", required=True, nargs="*")
parser.add_argument("-v","--vulnerability",help="filter by vulnerability e.g ms17-010")
parser.add_argument("-p","--port",help="filter output by port range e.g. 0-1024 or 21,23,25 or 80")
parser.add_argument("-c","--severity-level",help="filter by severity level 4-Critical, 3-High, 2,-Medium, 1-Low, 0-Info")
parser.add_argument("-e","--exclude-ip",help="comma separated list of ip address to exclude from output ")
parser.add_argument("-o","--output-file",help="write output in csv format")
args=parser.parse_args()

def expandUserInput(inputRange):
    outputList=list()
    if inputRange is None:
        return '[]'
    if "-" in inputRange:
        for item in range(int(inputRange.split("-")[0]),int(inputRange.split("-")[1])+1):
            outputList.append(item)
    elif "," in inputRange:
        for item in inputRange.split(","):
            outputList.append(int(item))
    else:
        outputList.append(int(inputRange))
    return outputList

def expandIPRange():
    ipList=list()
    if args.exclude_ip:
        for ip in args.exclude_ip.split(","):
            ipList.append(ip)
        return ipList
    else:
        return []

# Global variable
blackListedHostList = expandIPRange()
portList = expandUserInput(args.port)
severityList = expandUserInput(args.severity_level)

# Function for formatting message before printing
def printMessage(message,flag=1):
    if flag==1:
        print "[+] " + message
    elif flag==0:
        print "[-] " + message
    elif flag==2:
        print "\n[*] " + message
    else:
        print message

def verifyInputFile(file):
    if file.split(".")[-1]=="nessus":
        if isfile(file):
            return True
    else:
        return False

def checkInputFile():
    fileList=list()
    if args.file:
        for file in args.file:
            if verifyInputFile(file):
                fileList.append(file)
                printMessage("Input nessus report file: " + file,1)
            else:
                printMessage("Invalid input file detected: " + file,0)
    else:
        printMessage("No input file(s) specified, use -h flag to see help",0)
        exit(-1)
    return fileList

def readNessusData(file):
    nessusFile=open(file,'r')
    nessusData=nessusFile.read()
    nessusFile.close()
    return nessusData

def checkNessusReportFormat(nessusData):
    nessusRoot = etree.fromstring(nessusData)
    if nessusRoot.tag == "NessusClientData_v2":
        return True
    else:
        return False

def parseHostData(HostProperties):
    host = dict()
    host["netbios"] = "NA"
    host["mac"] = "NA"
    host["os"] = "NA"
    for tag in HostProperties:
        if tag.attrib['name'] == "HOST_START":
            host["start"] = tag.text
        if tag.attrib['name'] == "HOST_END":
            host["end"] = tag.text
        if tag.attrib['name'] == "netbios-name":
            host["netbios"] = tag.text.replace('\n', ' ').replace('\r', '')
        if tag.attrib['name'] == "operating-system":
            host["os"] = tag.text.replace('\n', ' ').replace('\r', '')
        if tag.attrib['name'] == "mac-address":
            host["mac"] = tag.text.replace('\n', ' ').replace('\r', '')
        if tag.attrib['name'] == "host-ip":
            host["ip"] = tag.text
    return host

def parseReportItem(reportItemTag):
    global portList
    global severityList
    vuln = dict()

    vuln['protocol'] = reportItemTag.attrib['protocol']
    vuln['port'] = reportItemTag.attrib['port']
    vuln['svc_name'] = reportItemTag.attrib['svc_name']
    vuln['severity'] = reportItemTag.attrib['severity']
    vuln['pluginName'] = reportItemTag.attrib['pluginName']
    vuln['plugin_output'] = "NA"


    #print type(reportItemTag)
    for childTag in reportItemTag:
        if childTag.tag == "description":
            vuln['description'] = childTag.text.replace('\n', ' ').replace('\r', '')
        elif childTag.tag == "solution":
            vuln['solution'] = childTag.text.replace('\n', ' ').replace('\r', '')
        elif childTag.tag == "plugin_output":
            vuln['plugin_output'] = childTag.text.replace('\n', ' ').replace('\r', '')

    #print reportItemTag.xpath("./@port")
    #vuln['plugin_output'] = ""

    if args.port and not args.severity_level:
        if int(vuln['port']) in portList:
            return vuln

    elif args.severity_level and not args.port:
        if int(vuln['severity']) in severityList:
            return vuln

    elif args.severity_level and args.port:
        if (int(vuln['severity']) in severityList) and (int(vuln['port']) in portList):
            return vuln

    elif args.vulnerability:
        for pluginName in args.vulnerability.split(","):
            if pluginName.lower() in vuln['pluginName'].lower():
                return vuln
    else:
        return vuln

    return ''

# It returns a list of dictionary ( host vs list_of_vulnerabilities_per_host for given nessus data
def parseNessusData(nessusData):
    global blackListedHostList
    reportSummary=list()
    hostInfo=dict()
    listVulnInfo=list()
    nessusRoot = etree.fromstring(nessusData)
    for block in nessusRoot:
        if block.tag == "Report":
            printMessage("Parsing report: " + block.attrib['name'],1)
            for ReportHost in block:
                hostInfo = dict()
                listVulnInfo = list()
                if ReportHost.attrib['name'] not in blackListedHostList:
                    for HostProperties_ReportItem in ReportHost:
                        if HostProperties_ReportItem.tag == "HostProperties":
                            hostInfo=parseHostData(HostProperties_ReportItem)
                        elif HostProperties_ReportItem.tag == "ReportItem":
                            vuln=parseReportItem(HostProperties_ReportItem)
                            if len(vuln) != 0:
                                listVulnInfo.append(vuln)
                    reportSummary.append({"host":hostInfo,"vuln":listVulnInfo})
    return reportSummary

def dumpCsvOutput(reports):
    delimeter="||"
    outFile=""
    severityIndex=['Info','Low','Medium','High','Critical']
    try:
        outFile=open(args.output_file,"w")
    except:
        printMessage("Error occured while writing output to csv file: "+args.output_file,0)

    outFile.write('HOST_IP' + delimeter + 'NETBIOS_HOSTNAME' + delimeter + 'OPERATING SYSTEM' + delimeter + 'MAC ADDRESS' + delimeter + 'PROTOCOL' + delimeter + 'PORT' + delimeter + 'SERVICE_NAME' + delimeter +
                      'SEVERITY' + delimeter + 'ISSUE' + delimeter + 'DESCRIPTION' + delimeter +
                      'SOLUTION' + delimeter + 'RESPONSE_RECEIVED' + "\n")
    for report in reports:
        for hostInfo in report:
            for vuln in hostInfo['vuln']:
                outFile.write(hostInfo['host']['ip'] + delimeter + hostInfo['host']['netbios'] + delimeter + hostInfo['host']['os'] + delimeter + hostInfo['host']['mac']+ delimeter +vuln['protocol']+ delimeter + vuln['port']+ delimeter + vuln['svc_name']+delimeter+ severityIndex[int(vuln['severity'])] + delimeter +vuln['pluginName']+ delimeter +vuln['description']+ delimeter +vuln['solution']+ delimeter +vuln['plugin_output'] + "\n")
    outFile.close()

def printData(reports):
    if HAS_PRETTYTABLE:
        t = PrettyTable(['protocol', 'Port', 'svc_name','severity','pluginName'])
    for report in reports:
        for hostInfo in report:
            printMessage("Host Info: " + hostInfo['host']['ip'] + "|" + hostInfo['host']['netbios'] + "|" + hostInfo['host']['os'].split('\n')[0] + "|" + hostInfo['host']['mac'],2)
            for vuln in hostInfo['vuln']:
                if HAS_PRETTYTABLE:
                    t.add_row([vuln['protocol'], vuln['port'], vuln['svc_name'],vuln['severity'],vuln['pluginName']])
                else:
                    printMessage("\t\t"+vuln['protocol']+"/"+vuln['port']+"-"+vuln['svc_name']+"\t"+vuln['severity']+"\t"+vuln['pluginName'],99)
            if HAS_PRETTYTABLE:
                print t
                t.clear_rows()

def main():
    printMessage("Starting nessus parser - ver 0.1")
    fileList=checkInputFile()
    report=list()
    for file in fileList:
        nessusData=readNessusData(file)
        if checkNessusReportFormat(nessusData):
            report.append(parseNessusData(nessusData))
        else:
            printMessage("Invalid nessus report format, Only NessusClientData_v2 format supported: " + file,0)

    if args.output_file:
        dumpCsvOutput(report)
    else:
        printData(report)
    printMessage("Thanks! See you again ;)")

if __name__ == '__main__':
    main()