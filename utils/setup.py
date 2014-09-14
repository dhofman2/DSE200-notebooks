#!/usr/bin/env python
""" This is a script for collecting the credentials, 
choosing one of them, and creating a pickle file to hold them """

import sys
import os
from glob import glob
import AWS_keypair_management
import pickle
from os.path import expanduser
import boto.ec2
import socket
import time
import curses_menu


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

# If there is more than one AWS keypair then display them using a menu, otherwise just select the one
if len(Creds) > 1:
    title = "Which AWS credentials do you want to use?"
    top_instructions = "Use the arrow keys make your selection and press return to continue"
    bottom_instructions = ""
    user_input = curses_menu.curses_menu(Creds, title=title, top_instructions=top_instructions,
                                         bottom_instructions=bottom_instructions)
    ID = Creds.keys()[int(user_input)]
elif len(Creds) == 1:
    ID = Creds.keys()[0]
else:
    sys.exit("No AWS keypair found.")

entry = Creds[ID]

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
    server_security_groups = conn.get_all_security_groups()

    # display the security group menu
    server_security_groups.insert(0, "Generate New Security Group")
    title = "Which EC2 security group would you like to use for instances? "
    top_instructions = "Use the arrow keys make your selection and press return to continue"
    bottom_instructions = "Enter nothing ..."
    user_input = curses_menu.curses_menu(server_security_groups, title=title, top_instructions=top_instructions,
                                         bottom_instructions=bottom_instructions)

    if str(user_input) is "0":
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
    server_ssh_key_pairs = conn.get_all_key_pairs()

    # display the EC2 SSH key pair menu
    server_ssh_key_pairs.insert(0, "Generate New SSH Key Pair")
    title = "Which EC2 SSH key pair would you like to use to login to your instances? "
    top_instructions = "Use the arrow keys make your selection and press return to continue"
    bottom_instructions = ""
    user_input = curses_menu.curses_menu(server_ssh_key_pairs, title=title, top_instructions=top_instructions,
                                         bottom_instructions=bottom_instructions)

    # if the user enters add then try to create and save a new SSH key pair
    if str(user_input) == "0":
        ssh_key_name = str(ID) + "_" + str(socket.gethostname()) + "_" + str(int(time.time()))
        key = conn.create_key_pair(key_name=ssh_key_name)
        key.save(vault)
        ssh_key_pair_file = vault + "/" + ssh_key_name + ".pem"

        if os.path.isfile(ssh_key_pair_file):
            ssh_key_pair_file_loop = False
            print "SSH key pair created..."
    else:
        try:
            ssh_key_name = str(server_ssh_key_pairs[int(user_input)].name)
        except (ValueError, IndexError):
            ssh_key_name = None
            print "Invalid input!"

    for k in conn.get_all_key_pairs():
        if k.name == ssh_key_name:
            ssh_key_name_loop = False
    if ssh_key_name_loop:
        print "EC2 key pair not found..."


# List all of the .pem files in the vault directory and allow the user to choose which one to use or allow the user to
# enter the path to a .pem file outside of the vault directory
try:
    ssh_key_pair_file_loop
except NameError:
    ssh_key_pair_file_loop = True

while ssh_key_pair_file_loop:
    pem_files = glob(vault+'/*.pem')

    if len(pem_files) is 0:
        print "\tNo .pem files found in %s" % vault

    # display the ssh key pair file menu
    title = "Which EC2 SSH key pair file (extension .pem) is associated with %s?" % ssh_key_name
    top_instructions = "Use the arrow keys make your selection and press return to continue"
    bottom_instructions = ""
    user_input = curses_menu.curses_menu(pem_files, title=title, top_instructions=top_instructions,
                                         bottom_instructions=bottom_instructions)

    try:
        int(user_input)
        try:
            ssh_key_pair_file = str(pem_files[int(user_input)])
        except (ValueError, IndexError):
            ssh_key_pair_file = None
            print "Invalid input!"
    except ValueError:
        ssh_key_pair_file = user_input

    if os.path.isfile(ssh_key_pair_file):
        ssh_key_pair_file_loop = False
    else:
        print "\n%s is not a valid file!" % ssh_key_pair_file

print 'ID: %s, key_id: %s, secret_key: %s' % (ID, key_id, secret_key)
print 'ssh_key_name: %s, ssh_key_pair_file: %s' % (ssh_key_name, ssh_key_pair_file)
print 'security groups: %s' % security_groups

# Read the contents of vault/Creds.pkl if it exists
try:
    pickle_file = open(vault + '/Creds.pkl', 'rb')
    credentials = pickle.load(pickle_file)
    pickle_file.close()
    print "Updating %s/Creds.pkl" % vault
except (IOError, EOFError):
    credentials = []
    print "Creating a new %s/Creds.pkl" % vault

# Write the new vault/Creds.pkl
with open(vault + '/Creds.pkl', 'wb') as pickle_file:
    # Add all the top level keys that are not launcher
    for c in credentials:
        if not c == "launcher":
            pickle.dump({c: credentials[c]}, pickle_file)

    # Add the new launcher credentials
    if security_group is None:
        pickle.dump({'launcher': {'ID': ID,
                                  'key_id': key_id,
                                  'secret_key': secret_key,
                                  'ssh_key_name': ssh_key_name,
                                  'ssh_key_pair_file': ssh_key_pair_file}}, pickle_file)
    else:
        pickle.dump({'launcher': {'ID': ID,
                                  'key_id': key_id,
                                  'secret_key': secret_key,
                                  'ssh_key_name': ssh_key_name,
                                  'ssh_key_pair_file': ssh_key_pair_file,
                                  'security_groups': security_groups}}, pickle_file)

    pickle_file.close()
conn.close()