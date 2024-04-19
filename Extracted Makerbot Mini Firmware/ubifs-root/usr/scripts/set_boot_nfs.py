#!/usr/bin/env python

import sys
from UBootEnv import UBootEnv

if len(sys.argv) != 2:
    print('Usage: set_boot_nfs.py server_ip:/path/to/nfs')

#TODO: DNS lookup, argument verification

env = UBootEnv()
env.read_env()
env.set_boot_nfs(sys.argv[1])
env.write_env()
