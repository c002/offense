#!/usr/bin/python

# Work in progress. Another script to run at boot on a Pi device or similar. 
# Grabs network interface info, scans the directly connected subnet, and emails results.
# Email un/pw will need to be populated. 


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
import netifaces
import socket
import netaddr

def main():
    timestamp = getTimeStamp()
    default_route_int = getEthernet()
    target_subnet = getTargetSubnet(default_route_int)
    subnet = target_subnet[0]
    network = target_subnet[1]
    sendscanstartmail(timestamp,subnet)
    output_file = '/scans/' + str(network) + '-'+ timestamp + '-discovery_scan.txt'
    scannerDiscovery(subnet,output_file)
    sendnotificationmail(output_file)
    

def getTimeStamp():
    day = time.strftime("%Y%m%d_")
    clock = time.strftime("%I%M%S")
    timestamp = day+clock
    return timestamp

def getEthernet():
    def_gw_device = netifaces.gateways()['default'][netifaces.AF_INET][1]
    return def_gw_device

def getTargetSubnet(default_route_int):
    addrs = netifaces.ifaddresses(default_route_int)
    ipinfo = addrs[socket.AF_INET][0]
    address = ipinfo['addr']
    netmask = ipinfo['netmask'] 
    cidr = netaddr.IPNetwork('%s/%s' % (address, netmask))
    target = cidr.network
    subnet = str(cidr) 
    return subnet,target

def sendscanstartmail(timestamp,subnet):
    msg = MIMEMultipart()
    # fill in all the normal email parts
    msg['Subject'] = "Kali PI has started on network:" + subnet + " - " + timestamp
    msg['From'] = ""
    msg['To'] = ""
    SERVER = "smtp.gmail.com:465"
    gmail_user = ''
    gmail_password = ''
    body = ""
    body += "Scan has started on network: " + subnet
    msg.attach(MIMEText(body))
    server = smtplib.SMTP_SSL(SERVER)
    server.ehlo()
    server.login(gmail_user , gmail_password)
    server.sendmail(msg['From'], msg['To'], msg.as_string())
    server.quit()
    
def sendnotificationmail(scanResults):
    day = time.strftime("%Y%m%d_")
    clock = time.strftime("%I%M%S")
    timestamp = day+clock
    # create message object
    msg = MIMEMultipart()
    # fill in all the normal email parts
    msg['Subject'] = "Kali PI nmap Scan Complete"
    msg['From'] = ""
    msg['To'] = ""
    SERVER = "smtp.gmail.com:465"
    gmail_user = ''
    gmail_password = ''
    resultsFile = file(scanResults)
    attachment = MIMEText(resultsFile.read())
    attachment.add_header('Content-Disposition', 'attachment', filename=scanResults)
    body = ""
    body += "See attached scan results"
    msg.attach(MIMEText(body))
    # attach human-readable scan results
    msg.attach(attachment)
    server = smtplib.SMTP_SSL(SERVER)
    server.ehlo()
    server.login(gmail_user , gmail_password)
    server.sendmail(msg['From'], msg['To'], msg.as_string())
    server.quit()

def scannerDiscovery(subnet,output_file):
    nm = nmap.PortScanner()
    print "Starting Discovery Scan!"
    scan_results = nm.scan(str(subnet), arguments = '-sSVC -p- --script=discovery -oN  ' + output_file )
    return scan_results
 

main()
