#!/usr/bin/python


# Small script useful for DHCP devices to keep track of when they come online and
# from where. Originally written for a Kali Rasperry Pi. 
# 
# Add "/usr/bin/python /scripts/boot-info.py &" 
# to /etc/rc.local on your raspberry pi to get network info once the Pi boots
# 
# Be sure to update the gmail settings with un/pw

import os
import sys
import subprocess
import netaddr
from netaddr import IPNetwork,IPAddress
import netifaces
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
import requests



def main():
    network_data = getNetworkData()
    sendnotificationmail(network_data)

# Write to stdout, not currently used but here for reference
def bash_command1(cmd):
    subprocess.Popen(['/bin/bash', '-c', cmd])
    
# Write to variable
def bash_command2(cmd):
    results = subprocess.check_output(['/bin/bash', '-c', cmd])
    return results

# Not currently used but may be useful in the future: 
def getEthernet():
    def_gw_device = netifaces.gateways()['default'][netifaces.AF_INET][1]
    return def_gw_device

# Email the results: 
def sendnotificationmail(body_contents):
    gmail_user = ''
    gmail_password = ''
    to_email = ''
    # create message object
    msg = MIMEMultipart()
    # fill in all the normal email parts
    msg['Subject'] = "The Kali PI Has Connected to a New Network"
    msg['From'] = gmail_user
    msg['To'] = to_email
    SERVER = "smtp.gmail.com:465"
    # resultsFile = file(scanResults)
    # attachment = MIMEText(resultsFile.read())
    # attachment.add_header('Content-Disposition', 'attachment', filename=scanResults)
    body = body_contents
    msg.attach(MIMEText(body))
    # attach human-readable scan results
    # msg.attach(attachment)
    server = smtplib.SMTP_SSL(SERVER)
    server.ehlo()
    server.login(gmail_user , gmail_password)
    server.sendmail(msg['From'], msg['To'], msg.as_string())
    server.quit()

# Gather the info you're looking for. Customize with different bash commands as needed and 
# append to 'results'
def getNetworkData():
    get_int = '/sbin/ifconfig'
    get_route = 'netstat -rn'
    get_open_ports = 'netstat -anop | grep LISTEN | grep -v unix'
    public_ip = requests.get('http://ip.42.pl/raw').text
    results = "The public IP of the internet connection is: " + str(public_ip)
    results += '\n'
    results += '\n'
    results += bash_command2(get_int)
    results += bash_command2(get_route)
    results += '\n'
    results += bash_command2(get_open_ports)
    return results


    
main()

