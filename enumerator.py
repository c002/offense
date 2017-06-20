#!/usr/bin/python
import nmap
import os
import sys
import subprocess
import psutil
from datetime import datetime 
import time
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
import argparse

###########################################
# Get the current time to mark the scan 
# output files: 
###########################################

day = time.strftime("%Y%m%d_")
clock = time.strftime("%I%M%S")
timestamp = day+clock



    
###########################################
# Different nmap scans:
###########################################
 
def scannerDiscovery(ip, home_folder, timestamp):
    print 'Starting nmap discovery scan....'
    scanner_file = ip + '-'+ timestamp + '-discovery_scan.txt'
    nm = nmap.PortScanner()
    os.popen('mkdir -p ' + home_folder + '/' + ip)
    dest_folder = home_folder + '/' + ip
    scan_results = nm.scan(str(ip), arguments = '-sSVC -p- --script=discovery -oN  ' + dest_folder + '/' + scanner_file )
    return scan_results


def scannerVulnerability(ip, home_folder, timestamp):
    print 'Starting nmap vulnerability scan....'
    scanner_file = ip + '-'+ timestamp + '-vulnerability_scan.txt'
    nm = nmap.PortScanner()
    os.popen('mkdir -p ' + home_folder + '/' + ip)
    dest_folder = home_folder + '/' + ip
    scan_results = nm.scan(str(ip), arguments = '-sSVC -p- --script=vuln -oN ' + dest_folder + '/' + scanner_file )
    return scan_results


def scannerVulnerabilityPort(ip,port):
    print 'Starting nmap vulnerability scan on port ' + str(port) + '....'
    nm = nmap.PortScanner()
    os.popen('mkdir -p ' + home_folder + '/' + ip)
    dest_folder = home_folder + '/' + ip
    scan_results = nm.scan(str(ip), arguments = '-sSVC -p ' + str(port) + ' --script=discovery -oN ' + dest_folder + '/' + ip + '-vulnerability_scan.txt' )
    return scan_results

###########################################
# Function to get a list of open ports:
###########################################

def getports(scan_results, ip):
    open_ports = scan_results['scan'][ip]['tcp'].keys()
    open_ports.sort()
    return open_ports

###########################################
# Enumeration scans: 
###########################################

def web_enumeration(ip, port, timestamp):
    str_port = str(port)
    str_ip = str(ip)
    nikto_file = str_ip + '-' + str_port + '-' + timestamp + '-nikto.csv'
    dirb_file = str_ip + '-' + str_port + '-' + timestamp + '-dirb.txt'
    print 'Starting nikto scan on port ' + str_port + '...'
    os.popen('/usr/bin/nikto -nointeractive -ask no -Display P -h http://' + str_ip + ':' + str_port + ' -Format csv -o ' +  dest_folder + '/' + nikto_file + ' &>/dev/null &' )
    process_name= "nikto" 
    tmp = os.popen("ps -Af").read()
    while process_name in tmp[:]:
        print 'nikto still going...'
        time.sleep(180)
        tmp = os.popen("ps -Af").read()
        if process_name not in tmp[:]:
            break    
    print 'Nikto results written to ' +  dest_folder + '/' + nikto_file
    print 'Starting dirb scan on port ' + str_port + '...'
    os.popen('/usr/bin/dirb http://' + str_ip + ':' + str(port) + ' -o ' +  dest_folder + '/' + dirb_file + ' &>/dev/null &' )
    process_name= "dirb" 
    tmp = os.popen("ps -Af").read()
    while process_name in tmp[:]:
        print 'dirb still going...'
        time.sleep(180)
        tmp = os.popen("ps -Af").read()
        if process_name not in tmp[:]:
            break    
    print 'dirb results written to ' +  dest_folder + '/' + dirb_file 
    
def sslweb_enumeration(ip, port, timestamp):
    str_port = str(port)
    str_ip = str(ip)
    nikto_file = str_ip + '-' + str_port + '-' + timestamp + '-nikto.csv'
    dirb_file = str_ip + '-' + str_port + '-' + timestamp + '-dirb.txt'  
    print 'Starting nikto scan on port ' + str_port + '...'
    os.popen('/usr/bin/nikto -nointeractive -ask no -Display P -h https://' + str_ip + ':' + str(port) +  ' -Format csv -o ' +  dest_folder + '/' + nikto_file + ' &>/dev/null &' )
    process_name= "nikto" 
    tmp = os.popen("ps -Af").read()
    while process_name in tmp[:]:
        print 'nikto still going...'
        time.sleep(180)
        tmp = os.popen("ps -Af").read()
        if process_name not in tmp[:]:
            break    
    print 'Nikto results written to ' +  dest_folder + '/' + nikto_file
    print 'Starting dirb scan on port ' + str_port + '...'
    os.popen('/usr/bin/dirb https://' + str_ip + ':' + str(port) + ' -o ' +  dest_folder + '/' + dirb_file + ' &>/dev/null &' )
    process_name= "dirb" 
    tmp = os.popen("ps -Af").read()
    while process_name in tmp[:]:
        print 'dirb still going...'
        time.sleep(180)
        tmp = os.popen("ps -Af").read()
        if process_name not in tmp[:]:
            break    
    print 'dirb results written to ' +  dest_folder + '/' + dirb_file   
    
    
def smb_enumeration(ip, port):
    str_port = str(port)
    str_ip = str(ip)
    enum4linux_file = str_ip + '-' + str_port + '-' + timestamp + '-enum4linux.txt'
    print 'Starting enum4linux scan...'
    os.popen('/usr/bin/enum4linux ' + str_ip + ' > ' +  dest_folder + '/' + enum4linux_file + ' &>/dev/null &' )
    process_name= 'enum4linux'
    tmp = os.popen("ps -Af").read()
    while process_name in tmp[:]:
        print 'enum4linux still going...'
        time.sleep(180)
        tmp = os.popen("ps -Af").read()
        if process_name not in tmp[:]:
            break
    print 'enum4linux complete. Results written to ' + dest_folder + '/' + enum4linux_file

###########################################
# Function for getting timestamp: 
###########################################

def getTime():
    day = time.strftime("%Y%m%d_")
    clock = time.strftime("%I%M%S")
    execute_time = day+clock
    return execute_time

###########################################
###########################################
###########################################
# Functions below are for taking scan 
# results from an nmap **disocvery** scan 
# and determining what services are unning 
# on each port. 
###########################################
###########################################
###########################################


###########################################
# Function for determining all open HTTP 
# ports on nmap discovery scans and enumerating: 
###########################################

def DiscoveryHTTPenum(scan_results, open_ports):
    print "Beginning HTTP enumeration with Nikto and Dirb..."
    for port in open_ports:
        try:
            if 'http-headers' in scan_results['scan'][ip]['tcp'][port]['script']:
                if 'ssl-cert' not in scan_results['scan'][ip]['tcp'][port]['script']:
                    print str(port) + ' is an HTTP server!'
                    print 'Beginning HTTP enumeration on port ' + str(port)
                    web_enumeration(ip, port, timestamp)
                else: 
                    print 'Skipping HTTP enumeration on port ' + str(port)
            else: 
                print 'Skipping HTTP enumeration port ' + str(port)
        except:
            print 'Skipping HTTP enumeration on port ' + str(port)


###########################################
# Function for determining all open HTTPs 
# ports on nmap discovery scans and enumerating: 
###########################################

def DiscoveryHTTPsenum(scan_results, open_ports):
    print "Beginning HTTPs enumeration with Nikto and Dirb..."
    for port in open_ports:
        try:
            if 'ssl-cert' in scan_results['scan'][ip]['tcp'][port]['script']:
                if 'http-headers' in scan_results['scan'][ip]['tcp'][port]['script']:
                    print str(port) + ' is an HTTPs server!'
                    print 'Beginning HTTPs enumeration on port ' + str(port)
                    sslweb_enumeration(ip, port, timestamp)
                else: 
                    print 'Skipping HTTPs enumeration on port ' + str(port)
            else: 
                print 'Skipping HTTPs enumeration port ' + str(port)
        except:
            print 'Skipping HTTPs enumeration on port ' + str(port)

###########################################
###########################################
###########################################
# Functions below are for taking scan 
# results from an nmap **vuln** scan and 
# determining what services are unning on 
# each port. 
###########################################
###########################################
###########################################

###########################################
# Function for determining all open HTTP 
# ports on nmap vuln scans and enumerating: 
###########################################

def VulnerabilityHTTPenum(scan_results, open_ports):
    print "Beginning HTTP enumeration with Nikto and Dirb..."
    for port in open_ports:
        try:
            if 'http-server-header' in scan_results['scan'][ip]['tcp'][port]['script']:
                if 'sslv2-drown' not in scan_results['scan'][ip]['tcp'][port]['script']:
                    print str(port) + ' is an HTTP server!'
                    print 'Beginning HTTP enumeration on port ' + str(port)
                    web_enumeration(ip, port)
                else: 
                    print 'Skipping HTTP enumeration on port ' + str(port)
            else: 
                print 'Skipping HTTP enumeration on port ' + str(port)
        except:
            print 'Skipping HTTP enumeration on port ' + str(port)


###########################################
# Function for determining all open HTTPs 
# ports on nmap vuln scans and enumerating: 
###########################################

def VulnerabilityHTTPsenum(scan_results, open_ports):
    print "Beginning HTTPs enumeration with Nikto and Dirb..."
    for port in open_ports:
        try:
            if 'sslv2-drown' in scan_results['scan'][ip]['tcp'][port]['script']:
                if 'http-server-header' in scan_results['scan'][ip]['tcp'][port]['script']:
                    print str(port) + ' is an HTTPs server!'
                    print 'Beginning HTTPs enumeration on port ' + str(port)
                    sslweb_enumeration(ip, port, timestamp)
                else: 
                    print 'Skipping HTTPs enumeration on port ' + str(port)
            else: 
                print 'Skipping HTTPs enumeration on port ' + str(port)
        except:
            print 'Skipping HTTPs enumeration on port ' + str(port)
                  
###########################################
# Function for determining all open 
# CIFS/Samba ports on nmap discovery AND 
# vuln scans and enumerating:  
###########################################

def DiscoverySambaenum(scan_results, open_ports):
    print "Beginning samba enumeration with enum4linux..."
    for port in open_ports:
        if 'samba' in scan_results['scan'][ip]['tcp'][port]['cpe']:
            print str(port) + ' is an samba/cifs server!'
            print 'Beginning enum4linux against Samba service on port ' + str(port)
            smb_enumeration(ip, port, timestamp)
        else: 
            if 'microsoft-ds' in scan_results['scan'][ip]['tcp'][port]['name']:
                print str(port) + ' is an samba/cifs server!'
                print 'Beginning enum4linux against Windows SMB service on port ' + str(port)
                smb_enumeration(ip, port) 
            else: 
                print 'Skipping enum4linux port ' + str(port)

###########################################
# Function for command line arguments:
###########################################

def buildArgParser():
    parser = argparse.ArgumentParser(
        
        
        prog='Enumerator.py', description='Python script for use with Kali Linux. Scan all tcp ports then enumerate web and smb services based on nmap results')
    parser.add_argument(
        '--ip', help='The IP address to scan',
        required=True)
    parser.add_argument(
        '--scantype', help='NMAP scan type. Options are \'vuln\' , \'discovery\' or \'all\'',
        required=True)
    parser.add_argument(
        '--folder', help='Destination for scan results. If not defined, results will go to /scan/$ip',
        required=False)    
    return parser.parse_args()

# Results placed in /scans unless cli arg is used: 
home_folder = '/scans'

###########################################
# Argument handling logic: 
###########################################

args = buildArgParser()


if args.ip:
    ip = args.ip
    if args.folder:
        home_folder = args.folder
        dest_folder = home_folder + '/' + ip
        print "The target is " + str(ip)  
    else:
        dest_folder = home_folder + '/' + ip
        print "The target is " + str(ip)
else:
    print "Cant do anything wihtout an IP to scan"
    sys.exit()
    
if args.scantype == 'vuln':
    scan_results = scannerVulnerability(ip, home_folder, timestamp)
    if scan_results['nmap']['scanstats']['uphosts'] == '1':
        open_ports = getports(scan_results, ip) 
        VulnerabilityHTTPenum(scan_results, open_ports)
        VulnerabilityHTTPsenum(scan_results, open_ports)
        DiscoverySambaenum(scan_results, open_ports)    
        sys.exit()
    else:
        print "Host did not reply to scan attempts. Please pick a new IP to scan"
        sys.exit()        
if args.scantype == 'discovery': 
    scan_results = scannerDiscovery(ip, home_folder, timestamp)
    if scan_results['nmap']['scanstats']['uphosts'] == '1':
        open_ports = getports(scan_results, ip) 
        DiscoveryHTTPenum(scan_results, open_ports)
        DiscoveryHTTPsenum(scan_results, open_ports)
        DiscoverySambaenum(scan_results, open_ports)
        sys.exit()
    else:
        print "Host did not reply to scan attempts. Please pick a new IP to scan"
        sys.exit()      
if args.scantype == 'all': 
    scan_results = scannerDiscovery(ip, home_folder, timestamp)
    if scan_results['nmap']['scanstats']['uphosts'] == '1':
        open_ports = getports(scan_results, ip) 
        DiscoveryHTTPenum(scan_results, open_ports)
        DiscoveryHTTPsenum(scan_results, open_ports)
        DiscoverySambaenum(scan_results, open_ports)
    else:
        print "Host did not reply to scan attempts. Please pick a new IP to scan"
        sys.exit()
    scan_results = scannerVulnerability(ip, home_folder, timestamp)
    if scan_results['nmap']['scanstats']['uphosts'] == '1':
        print 'Vulnerability scan complete. All enumeration is done!'
        sys.exit()
else:
    print 'The scan options are vuln, discovery or all (run both discovery and vuln scans). Your selecion didnt match any of those'
    sys.exit()


###########################################
# Zip the resulting scan files:
###########################################

date_time = getTime()
file_name = home_folder + '/' + str(ip) + '-scan-' + timestamp + '.zip'
os.popen('zip -r ' + file_name + ' ' + dest_folder)

 
   
    
