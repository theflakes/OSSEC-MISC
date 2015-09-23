#!/usr/bin/env python
'''
    Author: Brian Kellogg

    Pull all AD group members out of specified AD groups to build CDBs in OSSEC for rule use.

    /user/update_OSSEC_CDBs-groups.ini file read for information to pull group members from specified group in specified domain
    INI file section configuration
    ===========================================
    [CONTOSO]
    uri = ldap://10.0.0.1:3268
    username = cn=username,ou=users,dc=contoso,dc=com
    password = XXXXXXXX
    base_dn = cn=Domain Admins,cn=users,dc=contoso,dc=com
    file = /var/ossec/rules/group_name.txt
'''

import os
from ConfigParser import SafeConfigParser
from subprocess import call
from shutil import copy
import itertools
import ldap


global undo_changes     # set undo_changes to True if there are any errors that would result in a partial file
global file_list        # will contain a list of all files updated by this script


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


def do_ldap_group_search(base_dn):
    global undo_changes
    search_scope = ldap.SCOPE_BASE
    try:
        results = l.search_s(base_dn, search_scope)
    except ldap.LDAPError, e:
        undo_change = True
        print e
    return results


def do_ldap_user_search(base_dn):
    search_scope = ldap.SCOPE_BASE
    try:
        results = l.search_s(base_dn, search_scope, '(objectClass=user)', ['sAMAccountName'])
    except ldap.LDAPError, e:
        undo_changes = True
        print e
    return results[0][1]['sAMAccountName'][0]


def write_to_cdb(group_attrs, group, out_file):
    with open(out_file, 'a') as f:
        for results in group_attrs:
            members =  results[1]
            for member in members['member']:
                username = do_ldap_user_search(member)
                print username
                # CDB lookups are case sensitive so lets generate all possible permutations
                results = map(''.join, itertools.product(*zip(username.upper(), username.lower())))
                for result in results:
                    line = result + ':' + group + '\n'
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
    parser.read('/user/update_OSSEC_CDBs-groups.ini')
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
        group_attrs = do_ldap_group_search(domains[domain]['base_dn'])
        write_to_cdb(group_attrs, domain, domains[domain]['file'])
        l.unbind_s()
    if undo_changes:
        restore_files()
    else:
        call('/var/ossec/bin/ossec-makelists')
        # restart ossec server processes?
       # call(['/etc/init.d/ossec-hids-server', 'restart'])


if __name__ == '__main__':
    undo_changes = False
    file_list = []
    main()
