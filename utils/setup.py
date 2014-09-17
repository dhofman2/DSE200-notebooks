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
import logging


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

# Create a logs directory in the vault directory if one does not exist
if not os.path.exists(vault + "/logs"):
    os.makedirs(vault + "/logs")

# Save a log to vault/logs/setup.log
logging.basicConfig(filename=vault + "/logs/setup.log", format='%(asctime)s %(message)s', level=logging.INFO)

logging.info("setup.py started")
logging.info("Vault: %s" % vault)

# Log the csv files found in the vault directory
for csv in glob(vault+'/*.csv'):
    logging.info("Found csv file: %s" % csv)

AWS_KM = AWS_keypair_management.AWS_keypair_management()
(credentials, bad_files) = AWS_KM.Get_Working_Credentials(vault)

# If there is more than one AWS key pair then display them using a menu, otherwise just select the one
if len(credentials) > 1:
    # Log the valid AWS credentials that are found
    logging.info("Multiple AWS credentials found:")
    for credential in credentials:
        logging.info("AWS credential found: %s : %s" %
                     (credential, credentials[credential]['Creds'][0]['Access_Key_Id']))

    title = "Which AWS credentials do you want to use? Below is the list of user names."
    top_instructions = "Use the arrow keys make your selection and press return to continue"
    bottom_instructions = ""
    user_input = curses_menu.curses_menu(credentials, title=title, top_instructions=top_instructions,
                                         bottom_instructions=bottom_instructions)
    ID = credentials.keys()[int(user_input)]
    logging.info("AWS credential selected: %s : %s" % (ID, credentials[ID]['Creds'][0]['Access_Key_Id']))
elif len(credentials) == 1:
    ID = credentials.keys()[0]
    logging.info("One AWS credential found and selected: %s : %s" % (ID, credentials.keys()[0]))
else:
    logging.info("No AWS credentials found")
    sys.exit("No AWS credentials found.")

entry = credentials[ID]

key_id = entry['Creds'][0]['Access_Key_Id']
secret_key = entry['Creds'][0]['Secret_Access_Key']

try:
    # TODO: make us-east-1 variable
    conn = boto.ec2.connect_to_region("us-east-1",
                                      aws_access_key_id=key_id,
                                      aws_secret_access_key=secret_key)
except Exception, e:
    logging.info("There was an error connecting to AWS: %s" % e)
    sys.exit("There was an error connecting to AWS: %s" % e)

# Generate or specify the SSH key pair
need_ssh_key_pair = True
pem_files = glob(vault+'/*.pem')

# Log the pem files found in the vault directory
for pem_file in pem_files:
    logging.info("Found pem file: %s" % pem_file)

while need_ssh_key_pair:
    # If no pem_files exist in the vault then create one
    if len(pem_files) is 0:
            logging.info("No pem files found, generating a new SSH key pair")
            ssh_key_name = str(ID) + "_" + str(socket.gethostname()) + "_" + str(int(time.time()))
            try:
                key = conn.create_key_pair(key_name=ssh_key_name)
                key.save(vault)
            except Exception, e:
                logging.info("There was an error generating and saving a new SSH key pair: %s" % e)
                sys.exit("There was an error generating and saving a new SSH key pair: %s" % e)
            ssh_key_pair_file = vault + "/" + ssh_key_name + ".pem"

            if os.path.isfile(ssh_key_pair_file):
                print "SSH key pair created..."
                logging.info("SSH key pair created: %s : %s" % (ssh_key_name, ssh_key_pair_file))
                need_ssh_key_pair = False
            else:
                logging.info("Error creating SSH key pair")
                sys.exit("Error creating SSH key pair")
    # If pem_files exist in the vault the select the first one that matches the name of a ssh key pair on AWS
    else:
        try:
            aws_key_pairs = conn.get_all_key_pairs()
        except Exception, e:
            logging.info("There was an error getting the key pairs from AWS: %s" % e)
            sys.exit("There was an error getting the key pairs from AWS: %s" % e)

        for pem_file in pem_files:
            logging.info("Checking %s for a match on AWS" % pem_file)
            ssh_key_name = os.path.splitext(os.path.basename(str(pem_file)))[0]
            ssh_key_pair_file = pem_file

            # Verify the ssh_key_name matches a ssh_key on AWS
            if any(ssh_key_name in k.name for k in aws_key_pairs):
                logging.info("Found matching SSH key pair: %s :  %s" % (ssh_key_name, ssh_key_pair_file))
                print "Found matching SSH key pair..."
                need_ssh_key_pair = False
                break


print 'ID: %s, key_id: %s' % (ID, key_id)
print 'ssh_key_name: %s, ssh_key_pair_file: %s' % (ssh_key_name, ssh_key_pair_file)


# Read the contents of vault/Creds.pkl if it exists
try:
    pickle_file = open(vault + '/Creds.pkl', 'rb')
    saved_credentials = pickle.load(pickle_file)
    pickle_file.close()
    logging.info("Updating %s/Creds.pkl" % vault)
    print "Updating %s/Creds.pkl" % vault
except (IOError, EOFError):
    saved_credentials = []
    logging.info("Creating a new %s/Creds.pkl" % vault)
    print "Creating a new %s/Creds.pkl" % vault

# Write the new vault/Creds.pkl
with open(vault + '/Creds.pkl', 'wb') as pickle_file:
    # Add all the top level keys that are not launcher
    for c in saved_credentials:
        logging.info("Found top level key in Creds.pkl: %s" % c)
        if not c == "launcher":
            logging.info("Saving %s to Creds.pkl unchanged" % c)
            pickle.dump({c: saved_credentials[c]}, pickle_file)

    logging.info("Adding ID: %s, key_id: %s, ssh_key_name: %s, ssh_key_pair_file: %s to Creds.pkl" %
                 (ID, key_id, ssh_key_name, ssh_key_pair_file))
    # Add the new launcher credentials
    pickle.dump({'launcher': {'ID': ID,
                              'key_id': key_id,
                              'secret_key': secret_key,
                              'ssh_key_name': ssh_key_name,
                              'ssh_key_pair_file': ssh_key_pair_file}}, pickle_file)

    pickle_file.close()
    logging.info("Saved %s/Creds.pkl" % vault)
conn.close()
logging.info("setup.py finished")