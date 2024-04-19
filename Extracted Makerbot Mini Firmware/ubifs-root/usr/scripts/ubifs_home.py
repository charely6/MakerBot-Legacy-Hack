#!/usr/bin/env python

# burns a new ubifs image to the user filesystem volume
# usage : ubifs_home.py /path/to/ubifs.img

import sys
from UBI import UBIWriter

if len(sys.argv) < 2:
    image = "/home/temp/firmware/ubifs_user.img"
else:
    image = sys.argv[1]

ubi = UBIWriter()
ubi.write_file('var', image)

