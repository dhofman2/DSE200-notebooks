#!/usr/bin/env python
"""### A Script for Launching and managing an iPython notebook server on AWS ###
 # Written by Yoav Freund, March 2014

### Before you run this script ###
 Before running this script, you need to install boto on your local machine (not ec2).
 See https://pypi.python.org/pypi/boto.
 You can use either "sudo pip install boto" or "sudo easy_install boto"

### Security credentials ###
 In order to launch a notebook you need to first establish credentials on AWS. Set these credentials by editing the values in the file ../../Vault/AWSCredentials.py

Here are the steps you need to follow to achieve this

 1. Open an AWS account
 2. Create a key-pair so that  you can connect securely to your instances.
 3. Create a Security group to define which IPs can connect to your instances and through which ports.
 You need to complete these steps only one time. Later sessions can use the same credentials. If you are registered to the
 class you will get a credit of $100 towards your use of AWS. To get this credit goto the page "consolidated billing" (xxxx) and send a request to the class instructor.

 #### Security credentials ####
 In order to start your EC2 Session you need two things:

 1. A key-pair
 2. A security group

 Before you try to connect to an EC2 instance make sure that the
 security group that you are using contains the IP address that you
 are connecting from. The security group estricts which IP addresses
 are allowed to connect to which ports. Best set using the AWS web
 interface.

 Google "my ip" will give you your current address. Then go to the EC2
 web interface and make sure that you have rules for connecting from
 your current address to all of the ports.

"""

# ### Definitions of procedures ###
import boto.ec2
import time, pickle
import subprocess
import sys,os,re,webbrowser,select
from string import rstrip
import argparse
from os.path import expanduser
import json
from urllib2 import urlopen
import dateutil.parser

# AMI name: ERM_Utils These two lines last updated 8/27/2014
ami_owner_id = '846273844940'
ami_name = 'MASDSE'

# TODO: Set instance volumes to delete on terminate


def read_credentials():
    # If the EC2_VAULT environ var is set then use it, otherwise default to ~/Vault/
    try:
        os.environ['EC2_VAULT']
    except KeyError:
        vault = expanduser("~") + '/Vault'
    else:
        vault = os.environ['EC2_VAULT']

    # Read credentials from vault/Creds.pkl
    try:
        credentials_file = open(vault + '/Creds.pkl')
        p = pickle.load(credentials_file)
        credentials = p['launcher']
    except Exception, e:
        print e
        sys.exit('Could not read Creds.pkl')

    for c in credentials:
        if c == "key_id":
            plk_aws_access_key_id = credentials['key_id']
        elif c == "secret_key":
            plk_aws_secret_access_key = credentials['secret_key']
        elif c == "ID":
            plk_user_name = credentials['ID']
        elif c == "ssh_key_pair_file":
            plk_key_pair_file = credentials['ssh_key_pair_file']    # name of local file storing keypair
        elif c == "ssh_key_name":
            plk_key_name = credentials['ssh_key_name']              # name of keypair on AWS

    # These credentials are required to be set before proceeding
    try:
        plk_aws_access_key_id
        plk_aws_secret_access_key
        plk_user_name
        plk_key_pair_file
        plk_key_name
    except NameError, e:
        print e
        sys.exit("Not all of the credentials were defined")

    return plk_aws_access_key_id, plk_aws_secret_access_key, plk_user_name, plk_key_pair_file, plk_key_name


# Find all instances that are tagged as owned by user_name and the source is LaunchNotebookServer.py
def report_all_instances():
    reservations = conn.get_all_instances(filters={"tag:owner": user_name, "tag:source": "LaunchNotebookServer.py"})
    return_instance = None

    # Print out the number of instances found
    if len(reservations) > 0:
        print "\n\n%s private instances launched by this script:" % len(reservations)
    else:
        print "\n\nNo private instances launched by this script found!"

    for r in reservations:
        for n in r.instances:
            print "\tInstance name = %s | Instance state = %s | Launched = %s | DNS name = %s" % \
                  (n.id, n.state, n.launch_time, n.public_dns_name)

            # Only consider instances that are running or pending
            if n.state == "running" or n.state == "pending":
                # Return the instance that was launched last
                if return_instance is None:
                    return_instance = n
                else:
                    if dateutil.parser.parse(n.launch_time) > dateutil.parser.parse(return_instance.launch_time):
                        return_instance = n

    return return_instance

def emptyCallBack(line): return False

def kill_all_notebooks():
    command=['scripts/CloseAllNotebooks.py']
    Send_Command(command,emptyCallBack)

def set_credentials():
    """ set ID and secret key as environment variables on the remote machine"""

def copy_credentials(LocalDir):
    from glob import glob
    print 'Entered copy_credentials:',LocalDir
    mkdir=['mkdir','Vault']
    Send_Command(mkdir,emptyCallBack,dont_wait=True)
    list=glob(args['Copy_Credentials'])
    scp=['scp','-i',key_pair_file]+list+[('%s@%s:Vault/' % (login_id,instance.public_dns_name))]
    print ' '.join(scp)
    subprocess.call(scp)

def set_password(password):
    if len(password)<6:
        sys.exit('Password must be at least 6 characters long')
    command=["scripts/SetNotebookPassword.py",password]
    Send_Command(command,emptyCallBack)

def create_image(image_name):
    #delete the Vault directory, where all of the secret keys and passwords reside.
    delete_Vault=['rm','-r','~/Vault']
    Send_Command(delete_Vault,emptyCallBack)
    instance.create_image(args['create_image'])

def Send_Command(command,callback,dont_wait=False):
    init=time.time()

    print 'SendCommand:',' '.join(ssh+command)
    ssh_process = subprocess.Popen(ssh+command,
                                   shell=False,
                                   stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)

    def dataWaiting(source):
        return select.select([source], [], [], 0) == ([source], [], [])

    endReached=False
    while not endReached:
        # Check for errors before checking the output
        if dataWaiting(ssh_process.stderr):
            line=ssh_process.stderr.readline()
            if len(line)>0:
                print line
            else:
                endReached=True

        if dataWaiting(ssh_process.stdout):
            line=ssh_process.stdout.readline()
            if len(line)>0:
                print line,

                endReached = endReached | callback(line)

                matchEnd=re.match('=== END ===',line)
                if matchEnd:
                    endReached=True
        if dont_wait: endReached=True
        time.sleep(0.01)

def Launch_notebook(name=''):
    init=time.time()

    command=["scripts/launch_notebook.py",name,"2>&1"]

    def detect_launch_port(line):
        match=re.search('IPython\ Notebook\ is\ running\ at\:.*system\]\:(\d+)/',line)
        if match:
            port_no=match.group(1)
            print 'opening https://'+instance.public_dns_name+':'+port_no+'/'
            webbrowser.open('https://'+instance.public_dns_name+':'+port_no+'/')
            return True
        return False

    Send_Command(command,detect_launch_port)


if __name__ == "__main__":
    # Defaults
    login_id = 'ubuntu'

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

    args = vars(parser.parse_args())

    aws_access_key_id, aws_secret_access_key, user_name, key_pair_file, key_name = read_credentials()

    # Open connection to aws
    try:
        conn = boto.ec2.connect_to_region("us-east-1",
                                          aws_access_key_id=aws_access_key_id,
                                          aws_secret_access_key=aws_secret_access_key)
        print "Created Connection = %s" % conn
    except Exception, e:
        sys.exit("There was an error connecting to AWS: %s" % e)

    #Get and print information about all current instances
    instance = report_all_instances()

    # If there is no instance that is pending or running, create one
    if instance is None:
        instance_type = args['instance_type']
        disk_size = args['disk_size']

        print "Launching an EC2 instance: type=%s, ami=%s, disk_size=%s" % (instance_type, ami_name, disk_size)

        #
        # Use a security named the same as user_name. Create the security group if it does not exist.
        # Make sure the current IP address is added to the security group if it is missing.
        #

        # TODO: Make sure the current IP address is added to the security group every time the script is ran instead of
        # only when the instance is started.

        # Open http://httpbin.org/ip to get the public ip address
        ip_address = json.load(urlopen('http://httpbin.org/ip'))['origin']

        security_group_name = user_name

        # Check for the security group and create it if missing
        security_groups = [security_group_name]
        security_group_found = False

        for sg in conn.get_all_security_groups():
            if sg.name == security_group_name:
                print "Security group found..."
                security_group_found = True

                tcp_rule = False
                udp_rule = False
                icmp_rule = False

                # Verify the security group has the current ip address in it
                for rule in sg.rules:
                    if (str(rule.ip_protocol) == "tcp" and str(rule.from_port) == "0" and
                            str(rule.to_port) == "65535" and str(ip_address) + "/32" in str(rule.grants)):
                        print "Found TCP Rule"
                        tcp_rule = True

                    if (str(rule.ip_protocol) == "udp" and str(rule.from_port) == "0" and
                            str(rule.to_port) == "65535" and str(ip_address) + "/32" in str(rule.grants)):
                        print "Found UDP Rule"
                        udp_rule = True

                    if (str(rule.ip_protocol) == "icmp" and str(rule.from_port) == "-1" and
                            str(rule.to_port) == "-1" and str(ip_address) + "/32" in str(rule.grants)):
                        print "Found ICMP Rule"
                        icmp_rule = True

                # If the current ip address is missing from the security group then add it
                if tcp_rule is False:
                    print "Adding " + str(ip_address) + " (TCP) to " + security_group_name + " security group"
                    sg.authorize('tcp', 0, 65535, str(ip_address) + "/32")  # Allow all TCP
                if udp_rule is False:
                    print "Adding " + str(ip_address) + " (UDP) to " + security_group_name + " security group"
                    sg.authorize('udp', 0, 65535, str(ip_address) + "/32")  # Allow all UDP
                if icmp_rule is False:
                    print "Adding " + str(ip_address) + " (ICMP) to " + security_group_name + " security group"
                    sg.authorize('icmp', -1, -1, str(ip_address) + "/32")   # Allow all ICMP

        # If a security group does not exist for the user then create it
        if security_group_found is False:
            print "Creating security group..."
            security_group_description = "MAS DSE created on " + str(time.strftime("%m/%d/%Y"))
            sg = conn.create_security_group(security_group_name, security_group_description)
            sg.authorize('tcp', 0, 65535, str(ip_address) + "/32")  # Allow all TCP
            sg.authorize('udp', 0, 65535, str(ip_address) + "/32")  # Allow all UDP
            sg.authorize('icmp', -1, -1, str(ip_address) + "/32")   # Allow all ICMP

        bdm = boto.ec2.blockdevicemapping.BlockDeviceMapping()
        if disk_size > 0:
            dev_sda1 = boto.ec2.blockdevicemapping.EBSBlockDeviceType()
            dev_sda1.size = disk_size   # size in Gigabytes
            bdm['/dev/sda1'] = dev_sda1

        images = conn.get_all_images(filters={'owner-id': ami_owner_id, 'name': ami_name})

        # Attempt to start an instance only if one AMI image is returned
        if len(images) == 1:
            reservation = images[0].run(key_name=key_name,
                                        instance_type=instance_type,
                                        security_groups=security_groups,
                                        block_device_map=bdm)
        else:
            print "Error finding AMI Image"
            sys.exit("Error finding AMI Image")

        print 'Launched Instance: %s' % reservation

        # Tag the instances with the user_name
        for i in reservation.instances:
            i.add_tag("Name", user_name)
            i.add_tag("owner", user_name)
            i.add_tag("source", "LaunchNotebookServer.py")

        instance = report_all_instances()

    # Keep checking the instance state and loop until it is running
    while instance.state != 'running':
        print '\r', time.strftime('%H:%M:%S'), 'Instance status: ', instance.state
        time.sleep(10)
        instance.update()

    # Make sure the volumes are always tagged properly
    volumes = conn.get_all_volumes(filters={"attachment.instance-id": instance.id})
    for v in volumes:
        v.add_tag("Name", user_name)
        v.add_tag("owner", user_name)
        v.add_tag("source", "LaunchNotebookServer.py")

    print "\nInstance Ready! %s %s" % (time.strftime('%H:%M:%S'), instance.state)

    ssh = ['ssh', '-i', key_pair_file, ('%s@%s' % (login_id, instance.public_dns_name))]
    print "\nTo connect to instance, use:\n%s" % ' '.join(ssh)

    if args['password'] is None:
        set_password(args['password'])

    if args['kill']:
        print "Closing all notebook servers"
        kill_all_notebooks()
        sys.exit()

    if args['collection'] is None:
        Launch_notebook(args['collection'])

    if args['create_image'] is None:
        print "creating a new AMI called %s" % args['create_image']
        create_image(args['create_image'])

    if args['Copy_Credentials'] is None:
       copy_credentials(args['Copy_Credentials'])