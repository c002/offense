import paramiko
import sys
import os
import socket
import argparse

def sshConnection(ip, user, pw):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
                ssh.connect( ip , username = user, password = pw, timeout = 3)
                print "Connection a success for IP: " + ip
                ssh.close
        except socket.timeout:
                print "Connection failed due to timeout waiting for port 22 to reply for IP: " + ip
        except paramiko.AuthenticationException:
                print "Connection failed due to authentication error for IP: " + ip
        except paramiko.SSHException:
                print "Connection failed due SSH error for IP: " + ip
        except paramiko.ssh_exception.NoValidConnectionsError:
                print "Connection failed because host is not listening on port 22 (reset) : " + ip

def buildArgParser():
        parser = argparse.ArgumentParser(
                prog='sshchecker.py', description='Check a host for ssh authentication')
        parser.add_argument(
                '--file', help='Text file containing a list of IPs to check',
        required=True)
        parser.add_argument(
                '--user', help='Username to attempt authentication with',
        required=True)
        parser.add_argument(
                '--password', help='Password',
        required=True)        
        return parser.parse_args()


args = buildArgParser()

 
if args.file:
        filename = args.file
        file = open(filename, 'r')
        print 'Checking the list of host in ' + filename
else:
        print "Please use --file to point the script to a list of IP addresses"
if args.user: 
        user = args.user
        print 'Trying to ssh to the hosts with username: ' + user
else: 
        print "Please provide a username with --user"
if args.password:
        pw = args.password
        print "Using the password provided"
else:
        print "A password should be included with --password"


for ip in file.readlines():
        sshConnection(ip, user, pw)

#stdin,stdout,stderr = ssh.exec_command("ls /etc/")

#for line in stdout.readlines():
#        print line.strip()
sys.exit()

