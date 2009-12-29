#!/usr/bin/env python

import sys
import os
from optparse import OptionParser

from django.core.management import setup_environ

try:
    import settings # Assumed to be in the same directory.
except ImportError:
    import sys
    sys.stderr.write("Error: Can't find the file 'settings.py' in the directory containing %r.\n" % __file__)
    sys.exit(1)


options, args = ({}, [])

def main():
    parse_options()
    setup()
    run()

def setup():
    tests_path = setup_environ(settings)
    sys.path.append(os.path.dirname(tests_path))

def parse_options():
    global options, args
    
    parser = OptionParser("Usage: %prog [options] [test test test ...]")
    parser.add_option("-v", "--verbosity", action="store", dest="verbosity", type="int", default=0,
        help="Verbosity level; 0=minimal output, 1=normal output, 2=all output")
    parser.add_option("--noinput", action="store_false", dest="interactive", default=True,
        help="Tells Django to NOT prompt the user for input of any kind.")
    
    (options, args) = parser.parse_args()

def run():
    from django.test.utils import get_runner
    import django.conf

    test_runner = get_runner(django.conf.settings)
    tests = ['django_auth_ldap.' + arg for arg in args]
    if len(tests) == 0:
        tests = ['django_auth_ldap']

    test_runner(tests, verbosity=options.verbosity, interactive=options.interactive)    


if __name__ == '__main__':
    main()
