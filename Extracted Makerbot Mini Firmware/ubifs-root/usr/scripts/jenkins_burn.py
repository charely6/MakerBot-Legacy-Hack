#!/usr/bin/env python

import sys
import os
import subprocess
import re
from UBootEnv import UBootEnv

#jenkins='jenkins.soft.makerbot.net:8080'
jenkins='10.1.0.79:8080'

if len(sys.argv) < 2:
    job = 'Birdwing_Filesystem_revE'
else:
    job = sys.argv[1]

env = UBootEnv()
env.read_env()
if 'machine_type' not in env:
    print("Bootloader variables must specify machine_type")
    sys.exit(1)

path = '/home/firmware'
fs = 'rootfs_%s_reve.ubifs'% env['machine_type']
kernel = 'uImage'

subprocess.call(['rm', '-f', fs, kernel], cwd=path)

fs = 'rootfs_platypus_reve.ubifs'

job_page = subprocess.check_output(['wget', 'http://%s/job/%s/'% (jenkins, job), '-O-'])
builds = map(lambda s: 'http://'+jenkins+s[:-7], re.findall('/job/%s/[0-9]*/console'% job, job_page))

good_build = None
for build in builds:
    url = build + "artifact/BuildFS/images/" + fs
    if not subprocess.call(['wget', url], cwd=path):
        good_build = build
        break

if not good_build:
    print("No builds found with " + fs)

url = build + "artifact/BuildFS/images/" + kernel
subprocess.check_call(['wget', url], cwd=path)
subprocess.check_call(['/usr/scripts/firmware_burn.sh', 'both', fs, kernel], cwd=path)
