#!/usr/bin/env python
import sys
import os
import subprocess as sp
import shlex
import re

root = "/home/ubuntu/"
filename = "%s/scripts/NotebookCollections.md" % root


def print_file(print_filename):
    f = open(print_filename, 'r')
    print "############### Available Notebook collections: ##############\n"

    for line in f.readlines():
        print line,
    f.close()

    return


def parse_file(parse_filename):
    f = open(parse_filename, 'r')
    notebooks = {}
    for line in f.readlines():
        match = re.search(r'####\s*__\[(\S+)\]__\s+(\S+)', line)
        if match:
            notebook_name = match.group(1)
            notebook_path = root + match.group(2)

            #check that the path exists.
            if not os.path.isdir(notebook_path):
                print 'Error: name=%s, path %s does not exist as a directory' % (notebook_name, notebook_path)
            else:
                notebooks[notebook_name] = notebook_path
    f.close()
    return notebooks


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "not enough parameters: %s" % sys.argv
        print_file(filename)
    else:
        loc = 'none'
        name = sys.argv[1]
        direct_link = re.match('@(\S+)', name)
        if direct_link:
            loc = root + direct_link.group(1)
            print "Using direct link to location: %s" % loc
        else:
            d = parse_file(filename)
            if name in d.keys():
                loc = d[name]
                print "Using collection link from %s to %s" % (name, loc)
            else:
                print "Could not find notebook directory, printing Collection"
                print_file(filename)

        print "Checking if %s exists as a directory" % loc

        if not os.path.isdir(loc):
            print "Directory does not exist!"
        else:
            print "Launching: %s" % loc
            os.chdir(loc)
            command_line = "ipython notebook --profile=nbserver --port-retries=0"

            # If a hashed password was passed to the launch script then launch the notebook server with that password
            for argv in sys.argv:
                if not argv.find("sha1") == -1:
                    command_line += " --NotebookApp.password=%s" % argv

            command = shlex.split(command_line)
            print "Current directory: %s" % os.getcwd()
            print "Command: %s" % command
            sp.Popen(command)