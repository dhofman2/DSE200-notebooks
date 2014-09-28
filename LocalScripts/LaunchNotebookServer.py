#!/usr/bin/env python
### A Script for Launching and managing an iPython notebook server on AWS ###

# ### Definitions of procedures ###
import boto.ec2
import time
import pickle
import subprocess
import sys
import os
import re
import webbrowser
import select
import argparse
from os.path import expanduser
import json
from urllib2 import urlopen
import dateutil.parser
import datetime
import logging


# AMI name: ERM_Utils These two lines last updated 8/27/2014
ami_owner_id = '846273844940'
ami_name = 'MASDSE'
login_id = 'ubuntu'


def read_credentials(c_vault):
    # Read credentials from vault/Creds.pkl
    try:
        logging.info("(RC) Reading credentials from %s/Creds.pkl" % c_vault)
        p_credentials_path = c_vault + '/Creds.pkl'
        p_credentials_file = open(p_credentials_path)
        p = pickle.load(p_credentials_file)
        credentials = p['launcher']
    except Exception, e:
        print e
        logging.info("(RC) Could not read %s/Creds.pkl" % c_vault)
        sys.exit("Could not read %s/Creds.pkl" % c_vault)

    for c in credentials:
        if c == "key_id":
            p_aws_access_key_id = credentials['key_id']
            logging.info("(RC) Found aws_access_key_id: %s" % p_aws_access_key_id)
        elif c == "secret_key":
            p_aws_secret_access_key = credentials['secret_key']
            logging.info("(RC) Found aws_secret_access_key: ...")
        elif c == "ID":
            p_user_name = credentials['ID']
            logging.info("(RC) Found user_name: %s" % p_user_name)
        elif c == "ssh_key_pair_file":
            p_key_pair_file = credentials['ssh_key_pair_file']    # name of local file storing keypair
            logging.info("(RC) Found key_pair_file: %s" % p_key_pair_file)
        elif c == "ssh_key_name":
            p_key_name = credentials['ssh_key_name']              # name of keypair on AWS
            logging.info("(RC) Found key_name: %s" % p_key_name)

    # These credentials are required to be set before proceeding
    try:
        p_credentials_path
        p_aws_access_key_id
        p_aws_secret_access_key
        p_user_name
        p_key_pair_file
        p_key_name
    except NameError, e:
        logging.info("(RC) Not all of the credentials were defined: %s" % e)
        sys.exit("Not all of the credentials were defined: %s" % e)

    return p_credentials_path, p_aws_access_key_id, p_aws_secret_access_key, p_user_name, p_key_pair_file, p_key_name


# Find all instances that are tagged as owned by user_name and the source is LaunchNotebookServer.py
def report_all_instances():
    logging.info("(RI) Getting instances using filters: tag:owner:%s, tag:source:LaunchNotebookServer.py" % user_name)
    reservations = conn.get_all_instances(filters={"tag:owner": user_name, "tag:source": "LaunchNotebookServer.py"})
    return_instance = None

    # Print out the number of instances found
    if len(reservations) > 0:
        logging.info("(RI) %s private instances launched by this script:" % len(reservations))
        print "\n\n%s private instances launched by this script:" % len(reservations)
    else:
        logging.info("(RI) No private instances launched by this script found!")
        print "\n\nNo private instances launched by this script found!"

    for r in reservations:
        for n in r.instances:
            logging.info("(RI) Instance name = %s | Instance state = %s | Launched = %s | DNS name = %s" %
                         (n.id, n.state, n.launch_time, n.public_dns_name))
            print "\tInstance name = %s | Instance state = %s | Launched = %s | DNS name = %s" % \
                  (n.id, n.state, n.launch_time, n.public_dns_name)

            # Only consider instances that are running or pending or stopped
            if n.state == "running" or n.state == "pending" or n.state == "stopped":
                # Return the instance that was launched last
                if return_instance is None:
                    return_instance = n
                else:
                    if dateutil.parser.parse(n.launch_time) > dateutil.parser.parse(return_instance.launch_time):
                        return_instance = n

    if return_instance is None:
        logging.info("(RI) No running instances found")
    else:
        # Start the instance if the returned instance has been stopped
        if return_instance.state == "stopped":
            logging.info("(RI) Starting stopped instance: %s" % return_instance.id)
            print "(Starting stopped instance: %s" % return_instance.id
            return_instance.start()
        logging.info("(RI) Selected: Instance name = %s | Instance state = %s | Launched = %s | DNS name = %s" %
                     (return_instance.id, return_instance.state, return_instance.launch_time,
                      return_instance.public_dns_name))

    return return_instance


# Find and stop all instances that are tagged as owned by user_name and the source is LaunchNotebookServer.py
def stop_all_instances():
    logging.info("(SI) Getting instances using filters: tag:owner:%s, tag:source:LaunchNotebookServer.py" % user_name)
    reservations = conn.get_all_instances(filters={"tag:owner": user_name, "tag:source": "LaunchNotebookServer.py"})

    logging.info("(SI) Stopping all running instances!")
    print "\n\nStopping all running instances!"

    for r in reservations:
        for n in r.instances:
            # Only consider instances that are running or pending
            if n.state == "running" or n.state == "pending":
                logging.info("(SI) Stopping instance name = %s | Instance state = %s | Launched = %s | DNS name = %s" %
                             (n.id, n.state, n.launch_time, n.public_dns_name))
                print "Stopping instance name = %s | Instance state = %s | Launched = %s | DNS name = %s" % \
                      (n.id, n.state, n.launch_time, n.public_dns_name)
                n.stop()


# Find and terminate all instances that are tagged as owned by user_name and the source is LaunchNotebookServer.py
def terminate_all_instances():
    logging.info("(TI) Getting instances using filters: tag:owner:%s, tag:source:LaunchNotebookServer.py" % user_name)
    reservations = conn.get_all_instances(filters={"tag:owner": user_name, "tag:source": "LaunchNotebookServer.py"})

    logging.info("(TI) Terminating all running instances!")
    print "\n\nTerminating all running instances!"

    for r in reservations:
        for n in r.instances:
            # Consider instances that have not been terminated
            if not n.state == "terminated":
                logging.info("(TI) Terminating instance name = %s | Instance state = %s | Launched = %s | "
                             "DNS name = %s" % (n.id, n.state, n.launch_time, n.public_dns_name))
                print "Terminating instance name = %s | Instance state = %s | Launched = %s | DNS name = %s" % \
                      (n.id, n.state, n.launch_time, n.public_dns_name)

                # Get all of the volumes attached to the instance
                logging.info("(TI) Getting attached volumes using filters: attachment.instance-id:%s" % n.id)
                t_volumes = conn.get_all_volumes(filters={"attachment.instance-id": n.id})

                n.terminate()

                # Keep checking the instance state and loop until it has been terminated
                while not n.state == 'terminated':
                    logging.info("(TI) Waiting for instance to terminate: %s Instance status: %s " %
                                 (n.id, n.state))
                    print "%s Waiting for instance to terminate. Instance status: %s" % (time.strftime('%H:%M:%S'),
                                                                                         n.state)
                    time.sleep(10)
                    n.update()

                logging.info("(TI) Deleting %s attached volumes attached to instance: %s" % (len(t_volumes), n.id))
                print "Deleting %s attached volumes attached to instance: %s" % (len(t_volumes), n.id)

                for w in t_volumes:
                    logging.info("(TI) Volume id: %s Attach State: %s" % (w.id, w.attachment_state()))

                    while w.attachment_state() == 'attached':
                        logging.info("(TI) Waiting for volume to detach. Volume %s is still attached to instance %s" %
                                     (w.id, n.id))
                        print "%s Waiting for volume to detach. Volume %s is still attached to instance %s" % \
                              (time.strftime('%H:%M:%S'), w.id, n.id)
                        time.sleep(10)
                        w.update()

                    logging.info("(TI) Deleting volume %s from instance %s" % (w.id, n.id))
                    print "Deleting volume %s from instance %s" % (w.id, n.id)
                    w.delete()


def empty_call_back(line):
    return False


def kill_all_notebooks():
    command = ['scripts/CloseAllNotebooks.py']
    send_command(command, empty_call_back)


def set_credentials():
    """ set ID and secret key as environment variables on the remote machine"""


def copy_credentials(local_dir):
    from glob import glob
    print 'Entered copy_credentials:', local_dir
    mkdir = ['mkdir', 'Vault']
    send_command(mkdir, empty_call_back, dont_wait=True)
    local_dir_list = glob(local_dir)
    scp = ['scp', '-i', key_pair_file]+local_dir_list+[('%s@%s:Vault/' % (login_id, instance.public_dns_name))]
    print ' '.join(scp)
    subprocess.call(scp)


def set_password(password):
    if len(password) < 6:
        sys.exit('Password must be at least 6 characters long')
    command = ["scripts/SetNotebookPassword.py", password]
    send_command(command, empty_call_back)


def create_image(image_name):
    #delete the Vault directory, where all of the secret keys and passwords reside.
    delete_vault = ['rm', '-r', '~/Vault']
    send_command(delete_vault, empty_call_back)
    instance.create_image(image_name)


def send_command(command, callback, dont_wait=False):
    print 'SendCommand:', ' '.join(ssh+command)
    ssh_process = subprocess.Popen(ssh+command,
                                   shell=False,
                                   stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)

    def data_waiting(source):
        return select.select([source], [], [], 0) == ([source], [], [])

    end_reached = False
    while not end_reached:
        # Check for errors before checking the output
        if data_waiting(ssh_process.stderr):
            line = ssh_process.stderr.readline()
            if len(line) > 0:
                print line

        if data_waiting(ssh_process.stdout):
            line = ssh_process.stdout.readline()
            if not line:
                end_reached = True
            if len(line) > 0:
                print line,

                end_reached = end_reached | callback(line)

                match_end = re.match('=== END ===', line)
                if match_end:
                    end_reached = True
        if dont_wait:
            end_reached = True
        time.sleep(0.1)


def launch_notebook(name=''):
    command = ["scripts/launch_notebook.py", name, "2>&1"]

    def detect_launch_port(line):
        match = re.search('IPython\ Notebook\ is\ running\ at\:.*system\]\:(\d+)/', line)
        if match:
            port_no = match.group(1)
            print 'opening https://'+instance.public_dns_name+':'+port_no+'/'
            webbrowser.open('https://'+instance.public_dns_name+':'+port_no+'/')
            return True
        return False

    send_command(command, detect_launch_port)


def check_security_groups():
    #
    # Use a security named the same as user_name. Create the security group if it does not exist.
    # Make sure the current IP address is added to the security group if it is missing.
    #

    # Open http://httpbin.org/ip to get the public ip address
    ip_address = json.load(urlopen('http://httpbin.org/ip'))['origin']
    logging.info("(SG) Found IP address: %s" % ip_address)

    security_group_name = user_name

    # Check for the security group and create it if missing
    c_security_groups = [security_group_name]
    security_group_found = False

    for sg in conn.get_all_security_groups():
        if sg.name == security_group_name:
            logging.info("(SG) Found security group: %s" % security_group_name)
            security_group_found = True

            tcp_rule = False
            udp_rule = False
            icmp_rule = False

            # Verify the security group has the current ip address in it
            for rule in sg.rules:
                if (str(rule.ip_protocol) == "tcp" and str(rule.from_port) == "0" and
                        str(rule.to_port) == "65535" and str(ip_address) + "/32" in str(rule.grants)):
                    logging.info("(SG) Found TCP rule: %s : %s" % (security_group_name, ip_address))
                    tcp_rule = True

                if (str(rule.ip_protocol) == "udp" and str(rule.from_port) == "0" and
                        str(rule.to_port) == "65535" and str(ip_address) + "/32" in str(rule.grants)):
                    logging.info("(SG) Found UDP rule: %s : %s" % (security_group_name, ip_address))
                    udp_rule = True

                if (str(rule.ip_protocol) == "icmp" and str(rule.from_port) == "-1" and
                        str(rule.to_port) == "-1" and str(ip_address) + "/32" in str(rule.grants)):
                    logging.info("(SG) Found ICMP rule: %s : %s" % (security_group_name, ip_address))
                    icmp_rule = True

            # If the current ip address is missing from the security group then add it
            if tcp_rule is False:
                logging.info("(SG) Adding " + str(ip_address) + " (TCP) to " + security_group_name + " security group")
                print "Adding " + str(ip_address) + " (TCP) to " + security_group_name + " security group"
                sg.authorize('tcp', 0, 65535, str(ip_address) + "/32")  # Allow all TCP
            if udp_rule is False:
                logging.info("(SG) Adding " + str(ip_address) + " (UDP) to " + security_group_name + " security group")
                print "Adding " + str(ip_address) + " (UDP) to " + security_group_name + " security group"
                sg.authorize('udp', 0, 65535, str(ip_address) + "/32")  # Allow all UDP
            if icmp_rule is False:
                logging.info("(SG) Adding " + str(ip_address) + " (ICMP) to " + security_group_name + " security group")
                print "Adding " + str(ip_address) + " (ICMP) to " + security_group_name + " security group"
                sg.authorize('icmp', -1, -1, str(ip_address) + "/32")   # Allow all ICMP

    # If a security group does not exist for the user then create it
    if security_group_found is False:
        logging.info("(SG) Creating security group: %s : %s" % (security_group_name, ip_address))
        print "Creating security group: %s" % security_group_name
        security_group_description = "MAS DSE created on " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sg = conn.create_security_group(security_group_name, security_group_description)
        sg.authorize('tcp', 0, 65535, str(ip_address) + "/32")  # Allow all TCP
        sg.authorize('udp', 0, 65535, str(ip_address) + "/32")  # Allow all UDP
        sg.authorize('icmp', -1, -1, str(ip_address) + "/32")   # Allow all ICMP

    return c_security_groups


if __name__ == "__main__":
    # parse parameters
    parser = argparse.ArgumentParser(description='launch an ec2 instance and then start an ipython notebook server')
    parser.add_argument('-c', '--collection',
                        help="""Choice of notebook collection, there are two options:
                        1) '@path' an explicit path to the wanted directory, relative to /home/ubuntu\n\n
                        2) 'name' the name of a collection listed in the markdown file:\n\n
                              https://github.com/yoavfreund/UCSD_BigData/blob/master/AWS_scripts/NotebookCollections.md
                           \n\nthe name of the collection is given in a pattern of the form __[name]__
                        """)
    parser.add_argument('-i', '--create_image',
                        help='Create an AMI from the current state of the (first) instance')
    parser.add_argument('-p', '--password',
                        help='Specify password for notebook (if missing=use existing password)')
    parser.add_argument('-t', '--instance_type', default='t1.micro',
                        help='Type of instance to launch, Common choices are t1.micro, c1.medium, m3.xlarge for more' +
                             'info see: https://aws.amazon.com//ec2/instance-types/')
    parser.add_argument('-k', '--kill_all', dest='kill', action='store_true', default=False,
                        help='close all running notebook servers')
    parser.add_argument('-d', '--disk_size', default=0, type=int,
                        help='Amount of additional disk space in GB (default 0)')
    parser.add_argument('-A', '--Copy_Credentials',
                        help='Copy the credentials files to the Vault directory on the AWS instance. ' +
                             'Parameter is a the full path of the files you want to transfer to the vault. ' +
                             'Wildcards are allowed but have to be preceded by a "\")')
    parser.add_argument('-s', '--stop_instances', dest='stop', action='store_true', default=False,
                        help='Stop all running ec2 instances')
    parser.add_argument('--term_instances', dest='terminate', action='store_true', default=False,
                        help='Terminate all running and stopped ec2 instances. THIS WILL DELETE ALL DATA STORED ' +
                              'ON THE INSTANCES! Backup your data first!')

    args = vars(parser.parse_args())

    # If the EC2_VAULT environ var is set then use it, otherwise default to ~/Vault/
    try:
        os.environ['EC2_VAULT']
    except KeyError:
        vault = expanduser("~") + '/Vault'
    else:
        vault = os.environ['EC2_VAULT']

    # Exit if no vault directory is found
    if not os.path.isdir(vault):
        sys.exit("Vault directory not found.")

    # Create a logs directory in the vault directory if one does not exist
    if not os.path.exists(vault + "/logs"):
        os.makedirs(vault + "/logs")

    # Save a log to vault/logs/LaunchNotebookServer.log
    logging.basicConfig(filename=vault + "/logs/LaunchNotebookServer.log", format='%(asctime)s %(message)s',
                        level=logging.INFO)

    logging.info("LaunchNotebookServer.py started")
    logging.info("Vault: %s" % vault)

    credentials_path, aws_access_key_id, aws_secret_access_key, user_name, key_pair_file, key_name = \
        read_credentials(vault)

    # Open connection to aws
    try:
        conn = boto.ec2.connect_to_region("us-east-1",
                                          aws_access_key_id=aws_access_key_id,
                                          aws_secret_access_key=aws_secret_access_key)
        logging.info("Created Connection = %s" % conn)
        print "Created Connection = %s" % conn
    except Exception, e:
        logging.info("There was an error connecting to AWS: %s" % e)
        sys.exit("There was an error connecting to AWS: %s" % e)

    # All instances have been requested to be stopped
    if args['stop']:
        stop_all_instances()
        logging.info("LaunchNotebookServer.py finished")
        sys.exit("All instances stopped!")

    # All instances have been requested to be terminated
    if args['terminate']:
        terminate_all_instances()
        logging.info("LaunchNotebookServer.py finished")
        sys.exit("All instances terminated!")

    # Make sure a security group exists for the user and their current ip address has been added
    security_groups = check_security_groups()

    #Get and print information about all current instances
    instance = report_all_instances()

    # If there is no instance that is pending or running, create one
    if instance is None:
        instance_type = args['instance_type']
        disk_size = args['disk_size']

        logging.info("Launching an EC2 instance: type=%s, ami=%s, disk_size=%s" % (instance_type, ami_name, disk_size))
        print "Launching an EC2 instance: type=%s, ami=%s, disk_size=%s" % (instance_type, ami_name, disk_size)

        bdm = boto.ec2.blockdevicemapping.BlockDeviceMapping()
        if disk_size > 0:
            dev_sda1 = boto.ec2.blockdevicemapping.EBSBlockDeviceType()
            dev_sda1.size = disk_size   # size in Gigabytes
            bdm['/dev/sda1'] = dev_sda1

        logging.info("Getting AMI image using filters: owner-id:%s, name:%s" % (ami_owner_id, ami_name))
        images = conn.get_all_images(filters={'owner-id': ami_owner_id, 'name': ami_name})

        # Attempt to start an instance only if one AMI image is returned
        if len(images) == 1:
            logging.info("Found %s AMI image. Launching instance with key_name: %s, instance_type: %s, "
                         "security_group: %s" % (len(images), key_name, instance_type, security_groups))
            reservation = images[0].run(key_name=key_name,
                                        instance_type=instance_type,
                                        security_groups=security_groups,
                                        block_device_map=bdm)
        else:
            logging.info("Error finding AMI image: %s images found" % len(images))
            sys.exit("Error finding AMI image")

        logging.info("Launched Instance: %s" % reservation)
        print 'Launched Instance: %s' % reservation

        # Tag the instances with the user_name
        for i in reservation.instances:
            logging.info("Tagging instance %s with Name:%s, owner:%s, source:LaunchNotebookServer.py, created:%s" %
                         (i.id, user_name, user_name, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            i.add_tag("Name", user_name)
            i.add_tag("owner", user_name)
            i.add_tag("source", "LaunchNotebookServer.py")
            i.add_tag("created", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        # Give AWS some time to process the request before checking the status of the instance
        time.sleep(10)

        instance = report_all_instances()

    # Keep checking the instance state and loop until it is running
    while instance.state != 'running':
        logging.info("Check instance state: %s Instance status: %s " % (instance.id, instance.state))
        print '\r', time.strftime('%H:%M:%S'), 'Instance status: ', instance.state
        time.sleep(10)
        instance.update()

    logging.info("Instance started: %s" % instance.id)

    # Make sure the volumes are always tagged properly
    logging.info("Getting attached volumes using filters: attachment.instance-id:%s" % instance.id)
    volumes = conn.get_all_volumes(filters={"attachment.instance-id": instance.id})
    for v in volumes:
        logging.info("Tagging volume %s with Name:%s, owner:%s, source:LaunchNotebookServer.py, instance:%s" %
                     (v.id, user_name, user_name, instance.id))
        v.add_tag("Name", user_name)
        v.add_tag("owner", user_name)
        v.add_tag("source", "LaunchNotebookServer.py")
        v.add_tag("instance", instance.id)

    # Define the ssh command
    ssh = ['ssh', '-Xi', key_pair_file, ('%s@%s' % (login_id, instance.public_dns_name))]
    logging.info("The SSH Command: %s" % ' '.join(ssh))

    if len(sys.argv) == 1:
        logging.info("Instance Ready!")
        print "\nInstance Ready! %s %s" % (time.strftime('%H:%M:%S'), instance.state)

        logging.info("To connect to instance, use: %s" % ' '.join(ssh))
        print "\nTo connect to instance, use:\n%s" % ' '.join(ssh)

    if args['password']:
        set_password(args['password'])

    if args['kill']:
        print "Closing all notebook servers"
        kill_all_notebooks()
        sys.exit()

    if args['collection']:
        launch_notebook(args['collection'])

    if args['create_image']:
        print "creating a new AMI called %s" % args['create_image']
        create_image(args['create_image'])

    if args['Copy_Credentials']:
        copy_credentials(args['Copy_Credentials'])

    logging.info("LaunchNotebookServer.py finished")