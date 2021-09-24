import re


  
target_regex = re.compile(r"(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)")


  
credential_regex = re.compile(r"(?:(?:([^/:]*)/)?([^:]*)(?::(.*))?)?")


def parse_target(target):
    """ Helper function to parse target information. The expected format is:

    <DOMAIN></USERNAME><:PASSWORD>@HOSTNAME

    :param target: target to parse
    :type target: string

    :return: tuple of domain, username, password and remote name or IP address
    :rtype: (string, string, string, string)
    """
    domain, username, password, remote_name = target_regex.match(target).groups('')

      
    if '@' in remote_name:
        password = password + '@' + remote_name.rpartition('@')[0]
        remote_name = remote_name.rpartition('@')[2]

    return domain, username, password, remote_name


def parse_credentials(credentials):
    """ Helper function to parse credentials information. The expected format is:

    <DOMAIN></USERNAME><:PASSWORD>

    :param credentials: credentials to parse
    :type credentials: string

    :return: tuple of domain, username and password
    :rtype: (string, string, string)
    """
    domain, username, password = credential_regex.match(credentials).groups('')

    return domain, username, password
