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

    print('Retrieving existing Stash projects...', end="", file=sys.stderr)
    sys.stderr.flush()
    key_set = {proj['key'] for proj in stash.projects}
    stash_project_names = {proj['name'] for proj in stash.projects}
    names_to_keys = {proj['name']: proj['key'] for proj in stash.projects}
    repo_to_slugs = {}
    print('done', file=sys.stderr)
    sys.stderr.flush()
    cwd = os.getcwd()
    print('Processing GitLab projects...', file=sys.stderr)
    sys.stderr.flush()
    for project in gen_all_results(git.getprojects, per_page=args.page_size):
        proj_name = project['namespace']['name']
        # Create Stash project if it doesn't already exist
        if proj_name not in stash_project_names:
            # Create Stash project key
            key = proj_name
            if key.islower():
                key = key.title()
            key = re.sub(r'[^A-Z]', '', key)
            if len(key) < 2:
                key = re.sub(r'[^A-Za-z]', '', proj_name)[0:2].upper()
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
            print('Creating Stash project "%s" with key %s...' %
                  (proj_name, key), end="", file=sys.stderr)
            sys.stderr.flush()
            stash.projects.create(key, proj_name)
            names_to_keys[proj_name] = key
            stash_project_names.add(proj_name)
            print('done', file=sys.stderr)
            sys.stderr.flush()
        else:
            key = names_to_keys[proj_name]

        stash_project = stash.projects[key]

        # Initialize maping from repository names to slugs for later
        if key not in repo_to_slugs:
            repo_to_slugs[key] = {repo['name']: repo['slug'] for repo in
                                  stash_project.repos}

        # Create Stash-compatible name for repository
        # Repository names are limited to 128 characters.
        # They must start with a letter or number and may contain spaces,
        # hyphens, underscores and periods
        repo_name = project['name']
        if not repo_name[0].isalnum():
            repo_name = 'A ' + repo_name
        repo_name = re.sub(r'[^A-Za-z0-9 _.-]', ' ', repo_name)
        if len(repo_name) > 128:
            repo_name = repo_name[0:128]

        # Add repository to Stash project if it's not already there
        if repo_name not in repo_to_slugs[key]:
            print('Creating Stash repository "%s" in project "%s"...' %
                  (repo_name, proj_name), file=sys.stderr)
            sys.stderr.flush()
            stash_repo = stash_project.repos.create(repo_name)
            repo_to_slugs[key][repo_name] = stash_repo['slug']
            print('done', file=sys.stderr)
            sys.stderr.flush()
        else:
            print('Updating existing Stash repository "%s" in project "%s"' %
                  (repo_name, proj_name), file=sys.stderr)
            sys.stderr.flush()
            repo_slug = repo_to_slugs[key][repo_name]
            stash_repo = stash_project.repos[repo_slug].get()

        for clone_link in stash_repo['links']['clone']:
            if clone_link['name'] == 'ssh':
                stash_repo_url = clone_link['href']
                break

        with tempfile.TemporaryDirectory() as temp_dir:
            # Clone repository to temporary directory
            print('\nCloning GitLab repository...', file=sys.stderr)
            sys.stderr.flush()
            subprocess.check_call(['git', 'clone', '--mirror',
                                   project['ssh_url_to_repo'],
                                   temp_dir])
            # Change remote to Stash and push
            os.chdir(temp_dir)
            print('\nPushing repository to Stash...', file=sys.stderr)
            sys.stderr.flush()
            subprocess.check_call(['git', 'remote', 'set-url', 'origin',
                                   stash_repo_url])
            subprocess.check_call(['git', 'push', '--mirror'])
            os.chdir(cwd)

        print('\n' + ('=' * 80) + '\n', file=sys.stderr)
        sys.stderr.flush()

    print('done', file=sys.stderr)


if __name__ == '__main__':
    main()
