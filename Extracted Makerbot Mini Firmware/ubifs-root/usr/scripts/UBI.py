
import sys
import subprocess
import re

VOLUMES = [
    ('root0', '300'),
    ('root1', '300'),
    ('var', 'FILL'),
]

class UnknownVolumeException(Exception):
    pass

class _UBIBase(object):
    def __init__(self):
        self.proc = None

    def _get_count(self, cmd):
        """ Works with 'mtdinfo' and 'ubinfo' to count the number of devices """
        out = subprocess.check_output(cmd)
        return int(re.search(b'Count[^:]*: *([0-9]*)', out).groups()[0])

    def _do_attach(self):
        ATTACH_CMD = ['ubiattach', '-p', '/dev/mtd0', '-O4096']
        subprocess.check_call(ATTACH_CMD)

    def _do_update_file(self, volume, filepath):
        UPDATE_CMD = ['ubiupdatevol', volume, filepath]
        subprocess.check_call(UPDATE_CMD)

    def _do_update_pipe(self, volume, length):
        UPDATE_CMD = ['ubiupdatevol', '-s', str(length), volume, '-']
        self.proc = subprocess.Popen(UPDATE_CMD, stdin=subprocess.PIPE)

    def _get_volume(self, name):
        LOOKUP_CMD = ['ubinfo', '-d0', '-N', name]
        try:
            out = subprocess.check_output(LOOKUP_CMD).decode('utf-8')
        except subprocess.CalledProcessError:
            raise UnknownVolumeException
        return '/dev/ubi0_' + re.search('Volume ID: *([0-9]*)', out).groups()[0]

    def _ubi_check(self, attach=True):
        if self._get_count('mtdinfo') != 1:
            raise Exception('Kernel version is out of date!')
        if attach and self._get_count('ubinfo') < 1:
            self._do_attach()

class UBIWriter(_UBIBase):
    def write_file(self, name, filepath):
        """ Write a ubifs file to the named volume """
        self._ubi_check()
        volume = self._get_volume(name)
        self._do_update_file(volume, filepath)

    @staticmethod
    def open(name, length):
        writer = UBIWriter()
        writer._ubi_check()
        volume = writer._get_volume(name)
        writer._do_update_pipe(volume, length)
        return writer

    def write(self, data):
        self.proc.stdin.write(data)

    def close(self):
        self.proc.stdin.close()
        self.proc.wait()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class UBIFormatter(_UBIBase):
    def _do_detach(self, ubi_number):
        DETACH_CMD = ['ubidetach', '-d', str(ubi_number)]
        subprocess.check_call(DETACH_CMD)

    def _do_format(self):
        FORMAT_CMD = ['ubiformat', '/dev/mtd0', '-O4096', '-y']
        subprocess.check_call(FORMAT_CMD)

    def _do_mkvol(self, name, size):
        MKVOL_CMD = ['ubimkvol', '/dev/ubi0', '-N', name]
        if size == 'FILL':
            MKVOL_CMD.append('-m')
        else:
            MKVOL_CMD.extend(['-S', size])
        subprocess.check_call(MKVOL_CMD)

    def format(self):
        """ (Re)format, attach and setup volumes on ubi0 """
        self._ubi_check(attach=False)
        for n in range(self._get_count('ubinfo')):
            self._do_detach(n)
        self._do_format()
        self._do_attach()
        for name, size in VOLUMES:
            self._do_mkvol(name, size)

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == 'format':
        f = UBIFormatter()
        f.format()
    elif len(sys.argv) == 4 and sys.argv[1] == 'write':
        w = UBIWriter()
        w.write_file(sys.argv[2], sys.argv[3])
