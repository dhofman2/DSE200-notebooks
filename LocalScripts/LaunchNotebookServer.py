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

# AMI name: ERM_Utils These two lines last updated 8/27/2014
ami_owner_id = '846273844940'
ami_name = 'MASDSE'

# TODO: Set instance volumes to delete on terminate

# Read Credentials
#
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
        aws_access_key_id = credentials['key_id']
    elif c == "secret_key":
        aws_secret_access_key = credentials['secret_key']
    elif c == "ID":
        user_name = credentials['ID']
    elif c == "ssh_key_pair_file":
        key_pair_file = credentials['ssh_key_pair_file']    # name of local file storing keypair
    elif c == "ssh_key_name":
        key_name = credentials['ssh_key_name']              # name of keypair on AWS
    elif c == "security_groups":
        security_groups = credentials['security_groups']    # security groups for controlling access

# These credentials are required to be set before proceeding
try:
    aws_access_key_id
    aws_secret_access_key
    user_name
    key_pair_file
    key_name
except NameError, e:
    print e
    sys.exit("Not all of the credentials were defined")


# open connection
def open_connection(aws_access_key_id,
                    aws_secret_access_key):
    conn = boto.ec2.connect_to_region("us-east-1",
                                      aws_access_key_id=aws_access_key_id,
                                      aws_secret_access_key=aws_secret_access_key)
    print 'Created Connection=',conn
    return conn


#Get information about all current instances
def report_all_instances():
    # Find all instances that are tagged as owned by user and the source is LaunchNotebookServer.py
    reservations = conn.get_all_instances(filters={"tag:owner": user_name, "tag:source": "LaunchNotebookServer.py"})
    instances = []
    count = 0
    instance_alive = -1     # points to a pending or running instance, -1 indicates none
    pending = True          # indicates whether instance_alive refers to a pending instance.

    print 'time: %s' % time.strftime('%H:%M:%S')

    for reservation in reservations:
        print "\nReservation: %s" % reservation
        for instance in reservation.instances:
            print "Instance number = %s | Instance name = %s | DNS name = %s | Instance state = %s" % \
                  (count, instance.id, instance.public_dns_name, instance.state)
            print "This looks like a private instance launched by this script!"
            # This is the private instance, probably launched by this script.
            if instance_alive == -1 and instance.state != 'terminated':
                if instance.state == 'running' and pending:
                    instance_alive = count  # point to first running instance
                    pending = False
                elif instance.state == 'pending' and pending:
                    instance_alive = count  # point to first pending instance
                print "ssh -i %s %s@%s" % (key_pair_file, login_id, instance.public_dns_name)
                instances.append(instance)
            count += 1

    return instances, instance_alive

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

    # parse parameters
    parser = argparse.ArgumentParser(description='launch an ec2 instance and then start an ipython notebook server')
    parser.add_argument('-c','--collection',
                        help="""Choice of notebook collection, there are two options:
                        1) '@path' an explicit path to the wanted directory, relative to /home/ubuntu\n\n
                        2) 'name' the name of a collection listed in the markdown file:\n\n
                              https://github.com/yoavfreund/UCSD_BigData/blob/master/AWS_scripts/NotebookCollections.md\n\n
                           the name of the collection is given in a pattern of the form __[name]__
                        """)
    parser.add_argument('-i','--create_image',
                        help='Create an AMI from the current state of the (first) instance')
    parser.add_argument('-p','--password',
                        help='Specify password for notebook (if missing=use existing password)')
    parser.add_argument('-t','--instance_type',default='t1.micro',
                        help='Type of instance to launch, Common choices are t1.micro,c1.medium,m3.xlarge, for more info see: https://aws.amazon.com//ec2/instance-types/')
#Some common choices:
#              vCPU     ECU	Memory (GiB)	Instance Storage (GB)	Linux/UNIX Usage
#----------------------------------------------------------------------------------------
#t1.micro	1	Variable    0.615	 EBS Only	        $0.020 per Hour
#c1.medium	2	5	    1.7	         1 x 350	        $0.145 per Hour
#m3.xlarge	4	13	    15	         2 x 40 SSD	        $0.450 per Hour
#----------------------------------------------------------------------------------------
    parser.add_argument('-k','--kill_all',dest='kill',action='store_true',default=False,
                        help='close all running notebook servers')
    parser.add_argument('-d','--disk_size', default=0, type=int,
                        help='Amount of additional disk space in GB (default 0)')
    parser.add_argument('-A','--Copy_Credentials',
                        help='Copy the credentials files to the Vault directory on the AWS instance. Parameter is a the full path of the files you want to transfer to the vault. Wildcards are allowed but have to be preceded by a "\")')

    args = vars(parser.parse_args())

    # print 'args=',args

    # open connection to aws
    print 'The regions you are connected to are:',boto.ec2.regions()
    try:
        conn=open_connection(aws_access_key_id,aws_secret_access_key)
    except:
        e = sys.exc_info()[0]
        print "Error: %s" % e
        sys.exit("failed to connect to AWS")

    #Get and print information about all current instances
    login_id='ubuntu'
    (instances,instance_alive) = report_all_instances()

    if instance_alive==-1: # if there is no instance that is pending or running, create one
        instance_type=args['instance_type']
        disk_size=args['disk_size']

        print 'launching an ec2 instance, instance type=', instance_type, ', ami=', ami_name, ', disk size=', disk_size

        # Use the security group in Creds.pkl, otherwise use a security group based on the current ip address
        try:
            security_groups
            print "Using security group from Creds.pkl"
        except NameError:
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
                security_group_description = "MAS DSE created on " + str(time.strftime("%d/%m/%Y"))
                sg = conn.create_security_group(security_group_name, security_group_description)
                sg.authorize('tcp', 0, 65535, str(ip_address) + "/32")  # Allow all TCP
                sg.authorize('udp', 0, 65535, str(ip_address) + "/32")  # Allow all UDP
                sg.authorize('icmp', -1, -1, str(ip_address) + "/32")   # Allow all ICMP

        bdm = boto.ec2.blockdevicemapping.BlockDeviceMapping()
        if disk_size>0:
            dev_sda1 = boto.ec2.blockdevicemapping.EBSBlockDeviceType()
            dev_sda1.size = disk_size # size in Gigabytes
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

        print 'Launched Instance',reservation

        # Tag the instances with the user_name
        for i in reservation.instances:
            i.add_tag("Name", user_name)
            i.add_tag("owner", user_name)
            i.add_tag("source", "LaunchNotebookServer.py")

        (instances,instance_alive) = report_all_instances()

    # choose an instance and check that it is running
    instance = instances[instance_alive]
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

    if(args['password'] != None):
        set_password(args['password'])

    if(args['kill']):
        print "closing all notebook servers"
        kill_all_notebooks()
        sys.exit()

    if(args['collection'] != None):
        Launch_notebook(args['collection'])

    if(args['create_image'] != None):
        print "creating a new AMI called",args['create_image']
        create_image(args['create_image'])

    if(args['Copy_Credentials']!= None):
       copy_credentials(args['Copy_Credentials'])