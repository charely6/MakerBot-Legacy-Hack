#!/usr/bin/env python

# burns a new uImage using the backup kernel location described by the
# machine (uboot) environment variables
#
# usage : burn_kernel.py  /path/to/uImage
#   file_path : path to uImage to burn
#
# example : burn_kernel.py /home/temp/firmware/uImage
#

from UBootEnv import UBootEnv
import subprocess
import sys

def burn(kernel, erase=True, verbose=False):
    env = UBootEnv()
    env.read_env()

    current_addr = env['current_kernel_addr']
    new_addr = env['backup_kernel_addr']

    burn_cmd = [
        'nor_write',
        '-a', new_addr,
        '-i', kernel,
        '-s', '10000000'
    ]
    if erase: burn_cmd.append('-e')
    if verbose: burn_cmd.append('-v')
    subprocess.check_call(burn_cmd)

    env['current_kernel_addr'] = new_addr
    env['backup_kernel_addr'] = current_addr

    env.write_env()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        kernel = "/home/temp/firmware/uImage"
    else:
        kernel = sys.argv[1]

    print("Burning kernel " + kernel)
    burn(kernel, verbose='True')
    print("Kernel burn successful")
