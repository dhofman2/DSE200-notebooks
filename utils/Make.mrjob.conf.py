#!/usr/bin/env python
""" Insert credentials into mrjob configuration file """
import sys
import os
import pickle
from os.path import expanduser

# If the EC2_VAULT environ var is set then use it, otherwise default to ~/Vault/
try:
    os.environ['EC2_VAULT']
except KeyError:
    vault = expanduser("~") + '/Vault'
else:
    vault = os.environ['EC2_VAULT']
try:
    vaultname=vault+'/Creds.pkl'
    def check(key,Dict ):
        if not key in Dict.keys():
            sys.exit('The file: '+vaultname+' Does not contain the key "'+\
                     key+'" in the correct place"')

    with open(vaultname) as file:
        Creds=pickle.load(file)

    check('mrjob',Creds)
    keypair=Creds['mrjob']
    template=open('mrjob.conf.template').read()

    check('key_id',keypair)
    check('secret_key',keypair)
    filled= template % (keypair['key_id'],keypair['secret_key'])
    # print 'filled=\n',filled
    home=os.environ['HOME']
    outfile = home+'/.mrjob.conf'
    open(outfile,'wb').write(filled)
    print 'Created the configuration file:',outfile
except Exception, e:
    print e


