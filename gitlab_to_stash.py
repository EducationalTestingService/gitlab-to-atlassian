#!/usr/bin/env python3
# License: BSD 3 clause
'''
Clone all projects from GitLab and recreate them on Stash

:author: Dan Blanchard (dblanchard@ets.org)
:organization: ETS
:date: June 2014
'''

import argparse
import getpass
import logging
import os
import re
import subprocess
import sys
import tempfile

import stashy
from gitlab import Gitlab as GitLab


__version__ = '0.1.0'


def gen_all_results(method, *args, per_page=20):
    '''
    Little helper function to generate all pages of results for a given method
    in one list.
    '''
    get_more = True
    page_num = 0
    while get_more:
        page_num += 1
        proj_page = method(*args, page=page_num, per_page=per_page)
        get_more = len(proj_page) == per_page
        yield from iter(proj_page)


def main(argv=None):
    '''
    Process the command line arguments and create the JSON dump.

    :param argv: List of arguments, as if specified on the command-line.
                 If None, ``sys.argv[1:]`` is used instead.
    :type argv: list of str
    '''
    # Get command line arguments
    parser = argparse.ArgumentParser(
        description="Transfer all projects/repositories from GitLab to Stash. \
                     Note: This script assumes you have your SSH key \
                     registered with both GitLab and Stash.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        conflict_handler='resolve')
    parser.add_argument('gitlab_url',
                        help='The full URL to your GitLab instance.')
    parser.add_argument('stash_url',
                        help='The full URL to your Stash instance.')
    parser.add_argument('-p', '--password',
                        help='The password to use to authenticate if token is \
                              not specified. If password and token are both \
                              unspecified, you will be prompted to enter a \
                              password.')
    parser.add_argument('-P', '--page_size',
                        help='When retrieving result from GitLab, how many \
                              results should be included in a given page?.',
                        type=int, default=20)
    parser.add_argument('-s', '--verify_ssl',
                        help='Enable SSL certificate verification',
                        action='store_true')
    parser.add_argument('-t', '--token',
                        help='The private GitLab API token to use for \
                              authentication. Either this or username and \
                              password must be set.')
    parser.add_argument('-u', '--username',
                        help='The username to use for authentication, if token\
                              is unspecified.')
    parser.add_argument('-v', '--verbose',
                        help='Print more status information. For every ' +
                             'additional time this flag is specified, ' +
                             'output gets more verbose.',
                        default=0, action='count')
    parser.add_argument('--version', action='version',
                        version='%(prog)s {0}'.format(__version__))
    args = parser.parse_args(argv)

    args.page_size = max(100, args.page_size)

    # Convert verbose flag to actually logging level
    log_levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    log_level = log_levels[min(args.verbose, 2)]
    # Make warnings from built-in warnings module get formatted more nicely
    logging.captureWarnings(True)
    logging.basicConfig(format=('%(asctime)s - %(name)s - %(levelname)s - ' +
                                '%(message)s'), level=log_level)

    # Setup authenticated GitLab and Stash instances
    if args.token:
        git = GitLab(args.gitlab_url, token=args.token,
                            verify_ssl=args.verify_ssl)
    else:
        git = None
    if not args.username:
        print('Username: ', end="", file=sys.stderr)
        args.username = input('').strip()
    if not args.password:
        args.password = getpass.getpass('Password: ')
    stash = stashy.connect(args.stash_url, args.username, args.password)
    if git is None:
        git = GitLab(args.gitlab_url, verify_ssl=args.verify_ssl)
        git.login(args.username, args.password)

    print('Creating project repositories...', end="", file=sys.stderr)
    sys.stderr.flush()
    key_set = {proj['key'] for proj in stash.projects}
    stash_project_names = {proj['name'] for proj in stash.projects}
    cwd = os.getcwd()
    for project in gen_all_results(git.getprojects, per_page=args.page_size):
        stash_project = project['namespace']['name']
        # Create Stash project if it doesn't already exist
        if stash_project not in stash_project_names:
            # Create Stash project key
            key = stash_project
            if key.islower():
                key = key.title()
            key = re.sub(r'[^A-Z]', '', key)
            if len(key) < 2:
                key = re.sub(r'[^A-Za-z]', '', stash_project)[0:2].upper()
            added = False
            suffix = 65
            while key in key_set:
                if not added:
                    key += 'A'
                else:
                    suffix += 1
                    key = key[:-1] + chr(suffix)
            key_set.add(key)

            # Actually add the project to Stash
            stash.projects.create(key, stash_project)
            stash_project_names.add(stash_project)

        # Add repository to Stash project
        stash_repo = stash.projects[key].repos.create(project['name'])
        for clone_link in stash_repo['links']['clone']:
            if clone_link['name'] == 'ssh':
                stash_repo_url = clone_link['href']
                break

        with tempfile.TemporaryDirectory() as temp_dir:
            # Clone repository to temporary directory
            subprocess.check_call(['git', 'clone', '--mirror',
                                   project['ssh_url_to_repo'],
                                   temp_dir])
            # Change remote to Stash and push
            os.chdir(temp_dir)
            subprocess.check_call(['git', 'remote', 'set-url', 'origin',
                                   stash_repo_url])
            subprocess.check_call(['git', 'push', '--mirror'])
            os.chdir(cwd)

        print('.', end="", file=sys.stderr)
        sys.stderr.flush()

    print('done', file=sys.stderr)


if __name__ == '__main__':
    main()
