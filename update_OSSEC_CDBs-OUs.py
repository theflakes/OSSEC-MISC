#!/usr/bin/env python
'''
    Author: Brian Kellogg

    Updates CDB files from any AD domain's AD LDAP where possible for OU membership.

    /user/update_OSSEC_CDBs-OUs.ini file read for information to pull OU members from specified OU in specified domain
    INI file section configuration
    # username =  account used to bind to AD LDAP
    ===========================================
    [CONTOSO-Accounts]
    uri = ldap://10.0.0.1
    username = cn=User,ou=users,dc=contoso,dc=com
    password = XXXXXXXX
    base_dn = ou=accounts,dc=contoso,dc=com
    search_filter = (objectClass=user)
    search_attribute = sAMAccountName
    file = /var/ossec/rules/accounts.txt

    [CONTOSO-Service_Accounts]
    uri = ldap://10.0.0.1
    username = cn=User,ou=users,dc=contoso,dc=com
    password = XXXXXXXX
    base_dn = ou=service accounts,dc=contoso,dc=com
    search_filter = (objectClass=user)
    search_attribute = sAMAccountName
    file = /var/ossec/rules/service_accounts.txt
'''

import os
from ConfigParser import SafeConfigParser
from subprocess import call
from shutil import copy
import itertools
import ldap

global undo_changes     # set undo_changes to True if there are any errors that would result in a partial file
global file_list        # will contain a list of all file updated by this script


def initialize_ldap_conn(uri, username, password):
    global undo_changes
    global l
    try:
        l = ldap.initialize(uri)
        # due to LDAP on AD we need to turn referrals off
        # otherwise we run into a credential issue with the referral
        l.set_option(ldap.OPT_REFERRALS, 0)

        # you should  set this to ldap.VERSION2 if you're using a v2 directory
        l.protocol_version = ldap.VERSION3

        # Any errors will throw an ldap.LDAPError exception
        # or related exception so you can ignore the result
        l.simple_bind_s(username, password)
    except ldap.INVALID_CREDENTIALS:
        print 'Your username or password is incorrect.'
        undo_changes = True
    except ldap.LDAPError, e:
        print e
        undo_changes = True


def do_ldap_search(base_dn, search_filter, search_attribute):
    global undo_changes
    search_scope = ldap.SCOPE_SUBTREE
    try:
        ldap_result_id = l.search(base_dn, search_scope, search_filter, search_attribute)
        result_set = []
        while 1:
            result_type, result_data = l.result(ldap_result_id, 0)
            if not result_data:
                break
            else:
                # if you are expecting multiple results you can append them
                # otherwise you can just wait until the initial result and break out
                if result_type == ldap.RES_SEARCH_ENTRY:
                    result_set.append(result_data)
    except ldap.LDAPError, e:
        print e
        undo_changes = True
    finally:
        l.unbind_s()
    return result_set


def write_to_cdb(users, user_domain, cdb_file):
    with open(cdb_file, 'a') as f:
        for account in range(len(users)):
            for username in users[account]:
                name = username[1]['sAMAccountName'][0]
                # CDB lookups are case sensitive so lets generate all possible permutations
                results = map(''.join, itertools.product(*zip(name.upper(), name.lower())))
                for result in results:
                    line = result + ':' + user_domain + '\n'
                    f.write(line)


def backup_file(file_name):
    global file_list
    if file_name not in file_list:
        if os.path.isfile(file_name):
            copy(file_name, file_name + '.bak')
        open(file_name, 'w').close()
    file_list.append(file_name)


def restore_files():
    for file_name in file_list:
        if os.path.isfile(file_name + '.bak'):
            copy(file_name + '.bak', file_name)
    print 'There was an error with an LDAP query.  Therefore ossec-makelists was not run.'
    print 'All files were restored back to their original state.'


def main():
    parser = SafeConfigParser()
    parser.read('/user/update_OSSEC_CDBs-OUs.ini')
    domains = {}
    # build our dictionary of dictionaries
    for section_name in parser.sections():
        tmp = {}
        for option, value in parser.items(section_name):
            tmp[option] = value
        domains[section_name] = tmp
    for domain in domains:
        backup_file(domains[domain]['file'])
        initialize_ldap_conn(domains[domain]['uri'],
                             domains[domain]['username'],
                             domains[domain]['password'])
        user_names = do_ldap_search(domains[domain]['base_dn'],
                                    domains[domain]['search_filter'],
                                    [domains[domain]['search_attribute']])
        write_to_cdb(user_names, domain, domains[domain]['file'])
    if undo_changes:
        restore_files()
    else:
        call('/var/ossec/bin/ossec-makelists')
        # restart OSSEC server processes?
       # call(['/etc/init.d/ossec-hids-server', 'restart'])


if __name__ == '__main__':
    undo_changes = False
    file_list = []
    main()
