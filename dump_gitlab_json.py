#!/usr/bin/env python3
'''
Export all users/issues from GitLab to JIRA JSON format.

:author: Dan Blanchard (dblanchard@ets.org)
:date: May 2014
'''

import argparse
import getpass
import logging
import re
import readline
from collections import defaultdict
from io import StringIO

import gitlab


__version__ = '0.1.0'


def gen_all_results(git, method, *args, per_page=20):
    '''
    Little helper function to generate all pages of results for a given method
    in one list.
    '''
    get_more = True
    page_num = 0
    while get_more:
        page_num += 1
        proj_page = method(git, *args, page=page_num, per_page=per_page)
        get_more = len(proj_page) == per_page
        yield from iter(proj_page)


def md_to_wiki(md_string):
    '''
    Take Markdown-formatted comments and convert them to Wiki format.
    '''
    output_buf = StringIO()
    for line in md_string.splitlines():
        line = re.sub(r'```([a-z]+)$', r'{code:\1}', line)
        line = re.sub(r'```$', r'{code}', line)
        print(line, file=output_buf)
    return output_buf.getvalue()


def main(argv=None):
    '''
    Process the command line arguments and create the JSON dump.

    :param argv: List of arguments, as if specified on the command-line.
                 If None, ``sys.argv[1:]`` is used instead.
    :type argv: list of str
    '''
    # Get command line arguments
    parser = argparse.ArgumentParser(
        description="Export all users/issues from GitLab to JIRA JSON format.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        conflict_handler='resolve')
    parser.add_argument('gitlab_url',
                        help='The full URL to your GitLab instance.')
    parser.add_argument('-e', '--include_empty',
                        help='Include projects in output that do not have any\
                              issues.',
                        action='store_true')
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
                        help='Should we verify the SSL certificate?',
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
    logger = logging.getLogger(__name__)

    # Setup authenticated GitLab instance
    if args.token:
        git = gitlab.Gitlab(args.gitlab_url, token=args.token,
                            verify_ssl=args.verify_ssl)
    else:
        if not args.username:
            args.username = input('Username: ')
        if not args.password:
            args.password = getpass.getpass('Password: ')
        git = gitlab.Gitlab(args.gitlab_url, verify_ssl=args.verify_ssl)
        git.login(args.username, args.password)

    logger.info('Creating project entries...')
    projects = gen_all_results(git, git.getprojects, per_page=args.page_size)
    output_dict = defaultdict(list)
    for project in projects:
        if project['issues_enabled']:
            project_issues = list(gen_all_results(git, git.getprojectissues,
                                                  project['id'],
                                                  per_page=args.page_size))
            if len(project_issues) or args.include_empty:
                jira_project = {}
                jira_project['name'] = project['name']
                jira_project['description'] = md_to_wiki(project['description'])
                jira_project['created'] = project['created_at']
                jira_project['issues'] = []
                for issue in project_issues:
                    jira_issue = {}
                    jira_issue['externalId'] = issue['iid']
                    jira_issue['status'] = ('Closed' if (issue['state'] ==
                                                         'closed') else 'Open')
                    jira_issue['description'] = md_to_wiki(issue['description'])
                    jira_issue['reporter'] = issue['author']['username']
                    jira_issue['labels'] = issue['labels']
                    jira_issue['summary'] = issue['title']
                    if issue['assignee']:
                        jira_issue['assignee'] = issue['assignee']['username']
                    jira_project['issueType'] = 'Bug'
                    jira_project['comments'] = []
                    # Get all comments/notes
                    for note in gen_all_results(git, git.getissuewallnotes,
                                                project['id'], issue['id'],
                                                per_page=args.page_size):
                        jira_note = {}
                        jira_note['body'] = md_to_wiki(note['body'])
                        jira_note['author'] = note['author']['username']
                        jira_note['created'] = note['created_at']
                        jira_project['comments'].append(jira_note)
                    jira_project['issues'].append(jira_issue)

        output_dict['projects'].append(jira_project)

if __name__ == '__main__':
    main()
