import binascii
import struct
import subprocess
try:
    from collections import UserDict
except ImportError:
    from UserDict import UserDict

DEFAULT_ENV = {
    "current_root_volume": "root0",
    "backup_root_volume": "root1",
    "current_kernel_addr": "0x100000",
    "backup_kernel_addr": "0x800000",
    "spi_clock": "15000000",
    "swap_kernel": '; '.join([
        'temp=${current_kernel_addr}',
        'setenv current_kernel_addr ${backup_kernel_addr}',
        'setenv backup_kernel_addr ${temp}',
    ]),
    "swap_root": '; '.join([
        'temp=${current_root_volume}',
        'setenv current_root_volume ${backup_root_volume}',
        'setenv backup_root_volume ${temp}',
    ]),
    "bootargs": "",
    "bootcmd": '; '.join([
        'run setbootargs',
        'sf probe 0:0 ${spi_clock}',
        'sf read 0xC0000000 ${current_kernel_addr} 0x300000',
        'bootm 0xC0000000',
        'sf read 0xC0000000 ${current_kernel_addr} 0x300000',
        'bootm 0xC0000000',
        'run swap_root',
        'run swap_kernel',
        'saveenv',
        'run setbootargs',
        'sf read 0xC0000000 ${current_kernel_addr} 0x300000',
        'bootm 0xC0000000',
    ]),
    "bootdelay": "1",
}

# List of system environment variables that should be set from boot variables
ENV_COPY = {
    'eth'          : 'macaddr',
    'USB_PID'      : 'pid',
    'USB_ISERIAL'  : 'iserial',
    'MACHINE_TYPE' : 'machine_type',
    'UB_SPI_CLOCK' : 'spi_clock',
}

class MalformedEnvironmentException(Exception):
    pass

def fix_string_in(string):
    """ Python 2/3 compatibility """
    if (type(string) != type('a')):
        string = string.decode('utf-8')
    return string

def fix_string_out(string):
    """ Python 2/3 compatibility """
    if (type(string) != type(b'a')):
        string = string.encode('utf-8')
    return string

class UBootEnv(UserDict):
    def __init__(self, env_addr = 0xF00000, env_len = 0x10000, speed = 5000000):
        self.env_addr = env_addr
        self.env_len = env_len
        self.speed = speed
        self.data = {}

    def set_default_env(self):
        self.data.update(DEFAULT_ENV)

    def read_env(self):
        cmd = [
            'nor_read',
            str(self.env_addr),
            str(self.env_len),
            str(self.speed)
        ]
        byte_data = subprocess.check_output(cmd)
        try:
            return self.read_env_from(byte_data)
        except MalformedEnvironmentException:
            # Try again using the redundant environment
            cmd[1] = str(self.env_addr + self.env_len)
            byte_data = subprocess.check_output(cmd)
            return self.read_env_from(byte_data)

    def write_env(self, env_dict=None):
        byte_data = self.output_env(env_dict)
        cmd = [
            'nor_write',
            '-e',
            '-a', str(self.env_addr),
            '-l', str(self.env_len),
            '-s', str(self.speed),
        ]
        p = subprocess.Popen(cmd, stdin = subprocess.PIPE)
        p.communicate(byte_data)
        p.wait()
        # Also write the redundant environment
        cmd[3] = str(self.env_addr + self.env_len)
        p = subprocess.Popen(cmd, stdin = subprocess.PIPE)
        p.communicate(byte_data)
        p.wait()

    def read_env_from(self, byte_data):
        stored_crc = struct.unpack('<I', bytes(byte_data[0:4]))[0]
        crc = (binascii.crc32(byte_data[4:]) & 0xffffffff)
        if stored_crc != crc:
            raise MalformedEnvironmentException
        env_dict = {}
        for elem in byte_data[4:].split(b'\0'):
            if len(elem) < 1: break
            pair = elem.split(b'=', 1)
            pair = list(map(fix_string_in, pair))
            if len(pair) != 2 or pair[0] in env_dict:
                raise MalformedEnvironmentException
            env_dict[pair[0]] = pair[1]
        self.data.update(env_dict)
        return env_dict

    def output_env(self, env_dict = None):
        if None is env_dict:
            env_dict = self.data
        def fix_pair(p):
            return b'='.join(map(fix_string_out, p))
        pairs = list(env_dict.items())
        pairs.sort(key = lambda p: p[0])
        byte_data = b'\0'.join(map(fix_pair, pairs))
        byte_data += (b'\0' * (self.env_len - 4 - len(byte_data)))
        crc = binascii.crc32(byte_data) & 0xffffffff
        return struct.pack('<I', crc) + byte_data

    def _set_setbootargs(self, *options):
        setbootargs = [
            'setenv', 'bootargs',
            'mem=128M@0xC0000000',
            'console=ttyS1,115200n8',
            'noinitrd',
            'init=/linuxrc',
        ]
        setbootargs.extend(list(options))
        for var in ENV_COPY:
            setbootargs.append('%s=${%s}'% (var, ENV_COPY[var]))
        self.data['setbootargs'] = ' '.join(setbootargs)

    def set_boot_nfs(self, nfsroot):
        self._set_setbootargs(
            'rw',
            'ip=dhcp',
            'root=/dev/nfs',
            'nfsroot=' + nfsroot,
        )

    def set_boot_usb(self):
        self._set_setbootargs(
            'ro',
            'ip=off',
            'rootfstype=ext3',
            'root=/dev/sda1',
            'rootwait'
        )

    def set_boot_nand(self):
        self._set_setbootargs(
            'ro',
            'ip=off',
            'ubi.mtd=0,4096',
            'ubi.fm_autoconvert=1',
            'rootfstype=ubifs',
            'root=ubi0:${current_root_volume}',
            'rootwait'
        )

