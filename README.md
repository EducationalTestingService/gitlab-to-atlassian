## GitLab to JIRA issue exporter

This script attempts to export all of the issues (and the users associated with
them) from GitLab to JIRA. I wrote it in a few hours, but it got the job done.
I'm posting it on GitHub since other people may also find it useful.

### Requirements

- Python 3 (although pull request to support 2 are welcome)
- [Python GitLab API library](https://github.com/Itxaka/pyapi-gitlab)


### Usage

```
usage: dump_gitlab_json.py [-h] [-e] [-p PASSWORD] [-P PAGE_SIZE] [-s]
                           [-t TOKEN] [-u USERNAME] [-v] [--version]
                           gitlab_url

Export all users/issues from GitLab to JIRA JSON format.

positional arguments:
  gitlab_url            The full URL to your GitLab instance.

optional arguments:
  -h, --help            show this help message and exit
  -e, --include_empty   Include projects in output that do not have any
                        issues. (default: False)
  -p PASSWORD, --password PASSWORD
                        The password to use to authenticate if token is not
                        specified. If password and token are both unspecified,
                        you will be prompted to enter a password. (default:
                        None)
  -P PAGE_SIZE, --page_size PAGE_SIZE
                        When retrieving result from GitLab, how many results
                        should be included in a given page?. (default: 20)
  -s, --verify_ssl      Should we verify the SSL certificate? (default: False)
  -t TOKEN, --token TOKEN
                        The private GitLab API token to use for
                        authentication. Either this or username and password
                        must be set. (default: None)
  -u USERNAME, --username USERNAME
                        The username to use for authentication, if token is
                        unspecified. (default: None)
  -v, --verbose         Print more status information. For every additional
                        time this flag is specified, output gets more verbose.
                        (default: 0)
  --version             show program's version number and exit
```

### License

New BSD License (3-clause)