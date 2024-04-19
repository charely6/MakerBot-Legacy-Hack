#!/usr/bin/env python

import sys
import socket

if len(sys.argv) < 2:
    file = 'firmware.zip'
else:
    file = sys.argv[1]

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('/tmp/kaiten.socket')
s.send(('{"jsonrpc": "2.0", "method": "brooklyn_upload", "params": ["/firmware/%s"]}'%file).encode('utf-8'))
