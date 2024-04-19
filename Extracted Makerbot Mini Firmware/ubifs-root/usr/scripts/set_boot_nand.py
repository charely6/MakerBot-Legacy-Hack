#!/usr/bin/env python

import UBootEnv

default = UBootEnv.DEFAULT_ENV

env = UBootEnv.UBootEnv()
env.read_env()
env.set_boot_nand()
env['swap_root'] = default['swap_root']
env['swap_kernel'] = default['swap_kernel']
env['bootcmd'] = default['bootcmd']
env['spi_clock'] = default['spi_clock']
env.write_env()
