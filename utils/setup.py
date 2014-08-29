#!/usr/bin/env python
""" This is a script for collecting the credentials, 
choosing one of them, and creating a pickle file to hold them """

import pprint
import sys
import os
from glob import glob
import AWS_keypair_management
import pickle
from os.path import expanduser
import boto.ec2


# If the EC2_VAULT environ var is set then use it, otherwise default to ~/Vault/
try:
    os.environ['EC2_VAULT']
except KeyError:
    vault = expanduser("~") + '/Vault'
else:
    vault = os.environ['EC2_VAULT']

if os.path.isdir(vault):
    print 'files in' + vault + '/* :\n', '\n'.join(glob(vault+'/*'))
else:
    sys.exit("Vault directory not found.")

AWS_KM = AWS_keypair_management.AWS_keypair_management()
(Creds, bad_files) = AWS_KM.Get_Working_Credentials(vault)

print '\n Here are the credentials I found:'
pp = pprint.PrettyPrinter()
pp.pprint(Creds)

if len(Creds) > 1:
    print "You have creds for ",\
        ' '.join(['(%1d),%s' % (i, Creds.keys()[i])
                  for i in range(len(Creds.keys()))])
    ID_index = raw_input("Which one do you want to use? (index)? ")
    ID = Creds.keys()[int(ID_index)]
else:
    ID = Creds.keys()[0]

entry = Creds[ID]
print 'Using the 0 elements from \n', entry
key_id = entry['Creds'][0]['Access_Key_Id']
secret_key = entry['Creds'][0]['Secret_Access_Key']

# TODO: make us-east-1 variable
conn = boto.ec2.connect_to_region("us-east-1",
                                  aws_access_key_id=key_id,
                                  aws_secret_access_key=secret_key)

# Ask for an EC2 security group or allow LaunchNotebookServer.py to create a new security group based on the current
# ip address. If an EC2 security group is entered, then verify it exists in EC2 before proceeding.
security_group_loop = True
while security_group_loop:
    print "\nWhich EC2 security group would you like to use for instances? "
    print "\nSecurity groups defined in the EC2 management console:"
    server_security_groups = conn.get_all_security_groups()

    # display the security group menu
    i = 0
    for g in server_security_groups:
        print "\t[%s] %s" % (i, g.name)
        i += 1

    user_input = raw_input('\nSelect a security group OR enter nothing to create security groups based on your current '
                           'ip address: ')

    if user_input == "":
        security_group = None
        security_group_loop = False
    else:
        try:
            security_group = str(server_security_groups[int(user_input)].name)
        except (ValueError, IndexError):
            security_group = None
            print "Invalid input!"

        for g in conn.get_all_security_groups():
            if g.name == security_group:
                security_group_loop = False
        if security_group_loop:
            print "Security group not found..."

    security_groups = [security_group]

# List all of the EC2 key pair names defined on the server and allow the user to choose which one to use. Keep looping
# until a valid selection is made
ssh_key_name_loop = True
while ssh_key_name_loop:
    print "\nWhich EC2 SSH key pair would you like to use to login to your instances? "
    print "\nSSH key pairs defined in the EC2 management console:"
    server_ssh_key_pairs = conn.get_all_key_pairs()

    # display the ssh key pair menu
    i = 0
    for k in server_ssh_key_pairs:
        print "\t[%s] %s" % (i, k.name)
        i += 1

    user_input = raw_input('\nSelect an SSH key pair: ')

    try:
        ssh_key_name = server_ssh_key_pairs[int(user_input)].name
    except (ValueError, IndexError):
        ssh_key_name = None
        print "Invalid input!"

    for k in server_ssh_key_pairs:
        if k.name == ssh_key_name:
            ssh_key_name_loop = False
    if ssh_key_name_loop:
        print "EC2 key pair not found..."

ssh_key_pair_file = '///'
while not os.path.isfile(ssh_key_pair_file):
    ssh_key_pair_file = raw_input('Enter the full path to the key pair file (extension .pem)? ')

print 'ID: %s, key_id: %s, secret_key: %s' % (ID, key_id, secret_key)
print 'ssh_key_name: %s, ssh_key_pair_file: %s' % (ssh_key_name, ssh_key_pair_file)
print 'security groups: %s' % security_groups

with open(vault+'/Creds.pkl', 'wb') as pickle_file:
    if security_group is None:
        pickle.dump({'ID': ID,
                     'key_id': key_id,
                     'secret_key': secret_key,
                     'ssh_key_name': ssh_key_name,
                     'ssh_key_pair_file': ssh_key_pair_file}, pickle_file)
    else:
        pickle.dump({'ID': ID,
                     'key_id': key_id,
                     'secret_key': secret_key,
                     'ssh_key_name': ssh_key_name,
                     'ssh_key_pair_file': ssh_key_pair_file,
                     'security_groups': security_groups}, pickle_file)
conn.close()