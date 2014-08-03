#!/usr/bin/env python

import threading
import sys
import os
import time
import base64
from optparse import OptionParser
import paramiko

beg_time = 0

#===============================================================================
# execute command at remote computer
#===============================================================================
def ExeCmd(ip, port, user, pwd, sh, timeout):
	if ip == '' or port == '' or user == '' or sh == '':
#		print 'shell: wrong args'
		exit(255)

	sh = sh.strip(';')
	cmds = sh.split(';')
	
	index = 0
	try:
		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		ssh.connect(ip, port, user, pwd, timeout=30)
		for cmd in cmds:
			global beg_time
			exe_time = time.time() - beg_time
			if timeout < exe_time:
				raise SystemError
				
			index += 1
			ret = 0

			cmd = cmd.strip(' ')
			if cmd.find('scp') == 0:
				ret = SendFile(cmd, ssh)
			else:
				cmd_ch = cmd + " > /dev/null 2>&1;echo $?"
				stdin, stdout, stderr = ssh.exec_command(cmd_ch)
				out = stdout.read()
				_err = stderr.read()
				ret = int(out)
				
			print(ret)
			sys.stdout.flush()
			if ret != 0:
				raise SystemExit


		ssh.close()
	except SystemError:
		sys.exit(255)
	except SystemExit:
		sys.exit(index)
	except Exception as e:
		#print e
		sys.exit(255)

#===============================================================================
# send file to remote computer
#===============================================================================
def SendFile(cmd, ssh):
	scp_cmd = cmd.split(' ')
	obj = scp_cmd[1]
	dir = scp_cmd[2]
	dir = dir[dir.find('/'):]
	
	if obj == '' or dir == '':
#		print 'install: wrong args'
		return 1

	if not os.path.exists(obj):
#		print 'install: wrong file'
		return 1

	try:
		dest = os.path.basename(obj)
		dest = os.path.join(dir, dest)
		sftp = ssh.open_sftp()
		sftp.put(obj, dest)
		sftp.close()
	except Exception as e:
#		print e
		return 1

	return 0


#===============================================================================
# check network and OS
#===============================================================================
def Check(ip, port, user, pwd, check):
	items = {}
	try:
		check = check.split(',')
		for i in check:
			try:
				i = i.split('=')
				items[i[0]] = i[1]
			except:
				pass
	except:
		pass
		
	if not items.get('libgcc'):
		items['libgcc'] = '4.4'
		
	if not items.get('os'):
		items['os'] = 'CentOS release 6'
	
	try:
		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		ssh.connect(ip, port, user, pwd, timeout=30)
	except:
		print("cann't connect by ssh")
		sys.exit(1)
	
	try:
		sftp = ssh.open_sftp()
	except:
		print('sftp is not running')
		sys.exit(1)

	# check libgcc -------------------------------------------------------------
	stdin, stdout, stderr = ssh.exec_command('rpm -q libgcc')
	ret = stdout.read()
	ret = ret.split('\n')
	x = False
	for i in ret:
		try:
			i = i.split('-')
			if (i[0] == 'libgcc' and i[1].startswith(items['libgcc']) and 
			i[2].find('x86_64') != -1):
				x = True
		except:
			continue
	if not x:
		print("libgcc's version is not {0}-x86-64".format(items['libgcc']))
		sys.exit(1)
		
	# check os -----------------------------------------------------------------
	stdin, stdout, stderr = ssh.exec_command('cat /etc/centos-release')
	ret = stdout.read()
	if ret.find(items['os']) == -1:
		print('os is not {0}'.format(items['os']))
		sys.exit(1)
	
	sftp.close()
	ssh.close()
	
#===============================================================================
# main
#===============================================================================
def main():
	global beg_time
	beg_time = time.time()
	
	parser = OptionParser()
	parser.add_option('-t', '--to', help='remote host', dest='to')
	parser.add_option('-u', '--user', help="remote host's ssh user", dest='user')
	parser.add_option('-p', '--password', help='remote host\'s ssh password', dest='password')
	parser.add_option('-b', '--base64', action='store_true', help='password is encoded with base64', dest='base64')
	parser.add_option('-c', '--command', help='command need to execute', dest='command')
	parser.add_option('-s', '--timeout', type='int', help='executing timeout', dest='timeout')
	parser.add_option('-x', '--check', help='check network and OS', dest='check')
	
	(options, args) = parser.parse_args()
	if not options.to or not options.user or not options.password:
		parser.print_help()
		sys.exit(255)
	
	if options.base64:
		options.password = base64.b64decode(options.password)
		
	addr = options.to.split(':')
	if len(addr) == 1:
		ip = addr[0]
		port = 22
	else:
		ip = addr[0]
		port = int(addr[1])
		
	if options.check != None:
		Check(ip, port, options.user, options.password, options.check)
		sys.exit(0)
	
	if not options.timeout:
		options.timeout = 30
	
	ExeCmd(ip, port, options.user, options.password, options.command, options.timeout)

#===============================================================================
# __main__
#===============================================================================
if __name__ == "__main__":
	main()
	exit(0)




