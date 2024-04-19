#!/usr/bin/env python

# burns a new ubifs image to the root filsystem partition
# usage : filesystem_burn.py /path/to/ubifs.img
#
# if no file is specified, the default filepath is /home/temp/firmware/ubifs.img

from UBootEnv import UBootEnv
from UBI import UBIWriter
import sys
import subprocess
import re

def burn(image):
    env = UBootEnv()
    env.read_env()

    current_vol = env['current_root_volume']
    new_vol = env['backup_root_volume']

    ubi = UBIWriter()
    ubi.write_file(new_vol, image)

    env['current_root_volume'] = new_vol
    env['backup_root_volume'] = current_vol

    env.write_env()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        image = "/home/temp/firmware/ubifs.img"
    else:
        image = sys.argv[1]

    if len(sys.argv) < 3:
        print("Burning image " + image)
        burn(image)
    else:
        vol = sys.argv[2]
        ubi = UBIWriter()
        print("Burning image %s to volume %s"% (image, vol))
        ubi.write_file(vol, image)
    print("Filesystem burn successful")

