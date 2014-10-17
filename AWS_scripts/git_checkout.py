#!/usr/bin/env python
import os
from os.path import expanduser
import sys
import logging
import subprocess
import select
import time
import shutil
import argparse


def empty_call_back(line):
    return False


def run_command(command, stderr_call_back=empty_call_back, stdout_call_back=empty_call_back, display=True):
    return_variable = False

    command_output = subprocess.Popen(command,
                                      shell=False,
                                      stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)

    def data_waiting(source):
        return select.select([source], [], [], 0) == ([source], [], [])

    while True:
        # Read from stderr and print any errors
        if data_waiting(command_output.stderr):
            command_stderr = command_output.stderr.readline()
            if len(command_stderr) > 0:
                if display:
                    print command_stderr,
                # Run custom stderr_call_back routine
                return_variable |= stderr_call_back(command_stderr)

        # Read from stdout
        if data_waiting(command_output.stdout):
            command_stdout = command_output.stdout.readline()
            # Stop if the end of stdout has been reached
            if not command_stdout:
                break
            else:
                if display:
                    print command_stdout,
                # Run custom stdout_call_back routine
                return_variable |= stdout_call_back(command_stdout)

        time.sleep(0.1)

    return return_variable


def get_git_remote(remote_repository, remote_name):
    # Function to parse the output of the get_git_remote command
    def parse_remote_response(response):
        logging.info("(PRR) %s" % response.strip())

        # Return true if the origin is the class repository
        if not response.find(remote_repository) == -1:
            logging.info("(PRR) remote repository %s" % response.strip())
            return True

        return False

    # Get the remote url of a remote repository in the local repository
    get_remote = ["git", "--git-dir=%s/.git" % local_repository, "--work-tree=%s" % local_repository,
                         "remote", "show", remote_name]
    # If the remote url matches the remote repository then return true, otherwise return false
    return run_command(get_remote, stdout_call_back=parse_remote_response, display=False)


if __name__ == "__main__":
    # Parse parameters
    parser = argparse.ArgumentParser(description='Checkout and merge a students private repository with the DSE200 '
                                                 'class repository.')
    parser.add_argument('-r', help='MAS-DSE GitHub Repository Name', dest='repository', metavar='repository',
                        required=True)

    args = vars(parser.parse_args())

    vault = expanduser("~") + '/Vault'
    local_repository = expanduser("~") + '/DSE200-notebooks'
    upstream_repository = "mas-dse/DSE200-notebooks.git"

    # Exit if no vault directory is found
    if not os.path.isdir(vault):
        sys.exit("Vault directory not found.")

    # Create a logs directory in the vault directory if one does not exist
    if not os.path.exists(vault + "/logs"):
        os.makedirs(vault + "/logs")

    # Save a log to vault/logs/git_checkout.log
    logging.basicConfig(filename=vault + "/logs/git_checkout.log", format='%(asctime)s %(message)s',
                        level=logging.INFO)

    logging.info("git_checkout.py started")
    logging.info("Vault: %s" % vault)

    # Vault/github_id_rsa is required to be uploaded to instance, stop if it is missing
    if os.path.isfile(vault + "/github_id_rsa"):
        logging.info("Found %s/github_id_rsa" % vault)
    else:
        logging.info("%s/github_id_rsa is missing!" % vault)
        logging.info("git_checkout.py finished")
        sys.exit("%s/github_id_rsa is missing!" % vault)

    # Check if a local repository exists
    if os.path.isdir(local_repository):
        logging.info("Found %s" % local_repository)

        # Check if the local repository is a clone of the class repository then remove it
        if get_git_remote(upstream_repository, "origin"):
            logging.info("%s is the class repository" % local_repository)
            print "%s is the class repository" % local_repository

            # Remove the local class repository
            shutil.rmtree(local_repository)

            # Verify the local repository has been removed
            if os.path.isdir(local_repository):
                logging.info("%s was not removed!" % local_repository)
                logging.info("git_checkout.py finished")
                sys.exit("%s was not removed!" % local_repository)
            else:
                logging.info("%s was removed" % local_repository)
                print "%s was removed" % local_repository
        else:
            logging.info("%s is not the class repository!" % local_repository)
            logging.info("git_checkout.py finished")
            sys.exit("%s is not the class repository!" % local_repository)

    # SSH: Disable StrictHostKeyChecking for github.com
    if os.path.isfile(expanduser("~") + "/.ssh/config"):
        f = open(expanduser("~") + "/.ssh/config", "a")
        f.write("Host github.com\n\tStrictHostKeyChecking no\n")
        f.close()
    else:
        f = open(expanduser("~") + "/.ssh/config", "w")
        f.write("Host github.com\n\tStrictHostKeyChecking no\n")
        f.close()

    # Function to parse the output of the verify_ssh command
    def parse_ssh_agent_response(response):
        logging.info("(PSAR) %s" % response.strip())

        # Find SSH_AUTH_SOCK and set it as an environment variable
        if not response.find("SSH_AUTH_SOCK") == -1:
            logging.info("(PSAR) Found SSH_AUTH_SOCK: %s" % response.strip())
            os.environ['SSH_AUTH_SOCK'] = response.split()[0].split("=")[1].replace(";", "")
            logging.info("SSH_AUTH_SOCK environment variable set: %s" % os.environ['SSH_AUTH_SOCK'])

        return False

    # Start the ssh agent
    logging.info("Starting ssh-agent")
    ssh_agent = ["ssh-agent", "-s"]
    run_command(ssh_agent, stdout_call_back=parse_ssh_agent_response, stderr_call_back=parse_ssh_agent_response,
                display=False)

    # Add the ssh key to the ssh agent
    logging.info("Adding SSH key: %s/github_id_rsa" % vault)
    ssh_add = ["ssh-add", "%s/github_id_rsa" % vault]
    run_command(ssh_add, display=False)

    # Function to parse the output of the verify_ssh command
    def parse_verify_ssh_response(response):
        logging.info("(PVSR) %s" % response.strip())

        # Check if SSH returns the successfully authenticated message
        if not response.find("You've successfully authenticated, but GitHub does not provide shell access") == -1:
            logging.info("(PVSR) Successful authentication: %s" % response.strip())
            return True

        return False

    # SSH to github.com to verify the SSH key was successfully added to github.com
    logging.info("Verifying SSH keys by sshing to github.com")
    verify_ssh = ["ssh", "-T", "git@github.com", "-o", "StrictHostKeyChecking=no"]
    if run_command(verify_ssh, stdout_call_back=parse_verify_ssh_response, stderr_call_back=parse_verify_ssh_response,
                   display=False):
        logging.info("SSH test to github.com successful!")
        print "SSH test to github.com successful!"
    else:
        logging.info("SSH test to github.com failed!")
        logging.info("github_add_ssh_key.py finished")
        sys.exit("SSH test to github.com failed!")

    #
    # Clone private repository to local repository
    #
    logging.info("Cloning git@github.com:mas-dse/%s.git to %s" % (args['repository'], local_repository))
    print "Cloning git@github.com:mas-dse/%s.git to %s\nThis make take a few minutes.\n" % (args['repository'],
                                                                                            local_repository)
    git_clone_repository = ["git", "clone", "--progress", "git@github.com:mas-dse/%s.git" % args['repository'],
                            local_repository]
    run_command(git_clone_repository, display=False)
    logging.info("git@github.com:mas-dse/%s.git cloned to %s" % (args['repository'], local_repository))

    # Verify the local repository exists
    if os.path.isdir(local_repository):
        logging.info("%s exists" % local_repository)
    else:
        logging.info("%s does not exist!" % local_repository)
        logging.info("git_checkout.py finished")
        sys.exit("%s does not exist!" % local_repository)

    # Verify the local repository is a clone of the private repository
    if get_git_remote(args['repository'], "origin"):
        logging.info("%s is a clone of git@github.com:mas-dse/%s.git" % (local_repository, args['repository']))
    else:
        logging.info("%s is NOT a clone of git@github.com:mas-dse/%s.git" % (local_repository, args['repository']))
        logging.info("git_checkout.py finished")
        sys.exit("%s is NOT a clone of git@github.com:mas-dse/%s.git" % (local_repository, args['repository']))

    #
    # Add class repository as the upstream master of the local repository
    #
    logging.info("Adding git@github.com:%s as the upstream master to %s" % (upstream_repository, local_repository))
    print "Adding git@github.com:%s as the upstream master to %s\n" % (upstream_repository, local_repository)
    git_add_upstream = ["git", "--git-dir=%s/.git" % local_repository, "--work-tree=%s" % local_repository,
                        "remote", "add", "upstream", "git@github.com:%s" % upstream_repository]
    run_command(git_add_upstream, display=False)
    logging.info("git@github.com:%s added as the upstream master to %s" % (upstream_repository, local_repository))

    # Verify the upstream master of the local repository is the class repository
    if get_git_remote(upstream_repository, "upstream"):
        logging.info("The upstream master of %s is git@github.com:%s" % (upstream_repository, local_repository))
    else:
        logging.info("The upstream master of %s is NOT git@github.com:%s" % (upstream_repository, local_repository))
        logging.info("git_checkout.py finished")
        sys.exit("The upstream master of %s is NOT git@github.com:%s" % (upstream_repository, local_repository))

    #
    # Fetch the updates from the upstream master
    #
    logging.info("Fetching the updates from git@github.com:%s" % upstream_repository)
    print "Fetching the updates from git@github.com:%s\n" % upstream_repository
    git_fetch_upstream = ["git", "--git-dir=%s/.git" % local_repository, "--work-tree=%s" % local_repository,
                          "fetch", "upstream"]
    run_command(git_fetch_upstream, display=False)
    logging.info("Downloaded updated from git@github.com:%s" % upstream_repository)

    # Function to parse the output of the get_git_upstream_added command
    def parse_git_upstream_added_response(response):
        logging.info("(PGUAR) %s" % response.strip())

        # Return true if the upstream master branch is present
        if not response.find("remotes/upstream/master") == -1:
            logging.info("(PGUAR) remotes/upstream/master branch: %s" % response.strip())
            return True

        return False

    # Verify the local repository downloaded a copy of the class upstream master repository
    get_git_upstream_added = ["git", "--git-dir=%s/.git" % local_repository, "--work-tree=%s" % local_repository,
                              "branch", "-a"]
    if run_command(get_git_upstream_added, stdout_call_back=parse_git_upstream_added_response, display=False):
        logging.info("The upstream master of %s has been downloaded" % local_repository)
    else:
        logging.info("The upstream master of %s has NOT been downloaded" % local_repository)
        logging.info("git_checkout.py finished")
        sys.exit("The upstream master of %s has NOT been downloaded" % local_repository)

    #
    # Checkout the master branch of the local repository
    #
    logging.info("Checking out the master branch of %s" % local_repository)
    print "Checking out the master branch of %s\n" % local_repository
    git_checkout_master = ["git", "--git-dir=%s/.git" % local_repository, "--work-tree=%s" % local_repository,
                           "checkout", "master"]
    run_command(git_checkout_master, display=False)
    logging.info("Master branch of %s checked out" % local_repository)

    # Function to parse the output of the get_git_branch command
    def parse_git_branch_response(response):
        logging.info("(PGBR) %s" % response.strip())

        # Return true the current branch is master
        if not response.find("* master") == -1:
            logging.info("(PGBR) The current branch is master: %s" % response.strip())
            return True

        return False

    # Verify the master branch is the current branch
    get_git_branch = ["git", "--git-dir=%s/.git" % local_repository, "--work-tree=%s" % local_repository,
                      "branch"]
    if run_command(get_git_branch, stdout_call_back=parse_git_branch_response, display=False):
        logging.info("Master is the current branch of %s" % local_repository)
    else:
        logging.info("Master is NOT the current branch of %s" % local_repository)
        logging.info("git_checkout.py finished")
        sys.exit("Master is NOT the current branch of %s" % local_repository)

    #
    # Merge the upstream master with the local repository, if there is a conflict choose the updates from the local
    # repository
    #
    logging.info("Merging git@github.com:%s with %s" % (upstream_repository, local_repository))
    print "Merging git@github.com:%s with %s\n" % (upstream_repository, local_repository)
    git_merge_upstream = ["git", "--git-dir=%s/.git" % local_repository, "--work-tree=%s" % local_repository,
                          "merge", "-X", "ours", "upstream/master"]
    run_command(git_merge_upstream, display=False)
    logging.info("Merged git@github.com:%s with %s" % (upstream_repository, local_repository))
    print "Merged git@github.com:%s with %s\n" % (upstream_repository, local_repository)

    logging.info("git_checkout.py finished")