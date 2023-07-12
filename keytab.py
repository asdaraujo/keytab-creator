#  Copyright 2022 Cloudera, Inc. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

import logging
import random
import re
import struct
import time
from getpass import getpass
from impacket.krb5.crypto import string_to_key, Enctype
from optparse import OptionParser
from subprocess import Popen, PIPE

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__file__)

HEADER = struct.pack('>b', 5)
VERSION = struct.pack('>b', 2)  # KRB v5
EOF = struct.pack('>I', 0)
KVNO = struct.pack('>b', 0)

# Kerberos name types - Ref: RFC 4120
KRB_NT_PRINCIPAL = struct.pack('>I', 1)


def validate_keytab(path, principal):
    ccache_name = '/tmp/krb5cc.keytab_{}'.format(random.randint(1, 9999999))
    proc = Popen('export KRB5CCNAME={}; trap "kdestroy" 0; '
                 'KRB5_TRACE=/dev/stderr kinit -kt {} {}'.format(ccache_name, path, principal),
                 shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = proc.communicate()
    return proc.returncode, stdout, stderr


def create_keytab(path, principal, password, salt=None, validate=False, try_alt_salt=True):
    write_keytab(path, principal, password, salt)
    if not validate:
        return

    ret_code, _, stderr = validate_keytab(path, principal)
    if ret_code == 0:
        return

    if try_alt_salt:
        salts = re.findall(r'salt "(.*)", params', stderr.decode())
        if salts:
            LOG.info('Default keytab salt is not valid.'
                     ' Keytab will be created with an alternative salt ({}).'.format(salts[0]))
            write_keytab(path, principal, password, salts[0])
            ret_code, _, stderr = validate_keytab(path, principal)

            if ret_code == 0:
                return

    raise RuntimeError('Keytab validation failed. See trace output below:\n{}'.format(stderr.decode()))


def write_keytab(path, principal, password, salt=None):
    with open(path, 'wb') as file:
        file.write(HEADER)
        file.write(VERSION)
        file.write(encode_entry(principal, Enctype.AES256, password, salt))
        file.write(encode_entry(principal, Enctype.AES128, password, salt))
        file.write(encode_entry(principal, Enctype.RC4, password, salt))


def tokenize_principal(principal):
    m = re.match(r'([^/@]*)(/([^/@]*))?@([^/@]*)', principal)
    if m:
        name, _, instance, realm = m.groups()
        if instance:
            return name, instance, realm
        return name, realm
    raise RuntimeError("Invalid principal name: {}".format(principal))


def encode_timestamp(ts=None):
    if not ts:
        ts = int(time.time())
    return struct.pack('>I', ts)


def encode_data(data):
    if isinstance(data, str):
        data = data.encode()
    return struct.pack('>H', len(data)) + data


def encode_principal(principal):
    tokens = tokenize_principal(principal)
    realm = tokens[-1]
    components = tokens[:-1]
    data = [struct.pack('>H', len(components)), encode_data(realm)] + \
           [encode_data(c) for c in components] + \
           [KRB_NT_PRINCIPAL]
    return b''.join(data)


def encode_key(enctype, password, salt):
    key = string_to_key(enctype, password, salt, None)
    return encode_data(key.contents)


def encode_entry(principal, enctype, password, salt=None):
    if not salt:
        tokens = tokenize_principal(principal)
        salt = tokens[-1] + tokens[0]
    data = (encode_principal(principal) +
            encode_timestamp() +
            KVNO +
            struct.pack('>H', enctype) +
            encode_key(enctype, password, salt) +
            EOF)
    return struct.pack('>I', len(data)) + data


if __name__ == '__main__':
    PARSER = OptionParser()

    PARSER.add_option('--keytab', '-k', action='store',
                      dest='keytab', metavar='PATH', type='string',
                      help='Path of the keytab to be created.')
    PARSER.add_option('--principal', '-u', action='store',
                      dest='principal', metavar='PRINCIPAL', type='string',
                      help='Principal name (including the realm).')
    PARSER.add_option('--password', '-p', action='store',
                      dest='password', metavar='PWD', type='string',
                      help='User\'s Kerberos password.')
    PARSER.add_option('--ask-password', '-P', action='store_true',
                      dest='ask_password', default=False,
                      help='Prompt for password.')
    PARSER.add_option('--salt', '-s', action='store',
                      dest='salt', metavar='PWD', type='string', default=None,
                      help='Salt used for key encryption.')
    PARSER.add_option('--no-alternative-salt', '-n', action='store_false',
                      dest='try_alt_salt', default=True,
                      help='Do not try an alternative salt even if the default one fails.')
    PARSER.add_option('--validate-with-kinit', '-v', action='store_true',
                      dest='validate', default=False,
                      help='Validate the keytab using kinit.')

    (OPTIONS, ARGS) = PARSER.parse_args()
    assert OPTIONS.keytab, "--keytab must be specified"
    assert OPTIONS.principal, "--principal must be specified"
    assert OPTIONS.password or OPTIONS.ask_password, "Either --password or --ask-password must be specified"
    assert not (OPTIONS.password and OPTIONS.ask_password), "--password or --ask-password cannot be specified together"
    assert not ARGS, 'Invalid arguments: {}'.format(ARGS)

    if OPTIONS.ask_password:
        OPTIONS.password = getpass('Password: ')
        confirm = getpass('Confirm Password: ')
        if OPTIONS.password != confirm:
            raise RuntimeError("Passwords do not match.")

    create_keytab(OPTIONS.keytab, OPTIONS.principal, OPTIONS.password, OPTIONS.salt, OPTIONS.validate,
                  OPTIONS.try_alt_salt)
