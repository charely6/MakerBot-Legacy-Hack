
import kaiten.pymachine
import ctypes
import os
import zipfile

libmachine = ctypes.CDLL(os.path.join(
	    '/',
            'usr',
            'lib',
            'libmachine.so',
        ))

machinedriver = libmachine.CreateMachine()

print ('created machine driver lib')
pymach = kaiten.pymachine.Machine(machinedriver)

print ("created pymachine")
result = False
while result == False:
    libmachine.Iterate(machinedriver)
    result = pymach.is_initialized()

tinything_archive = zipfile.ZipFile("/home/things/20mm_Calibration_Box.tinything", "r")


def do_stuff():
    #yield from pymach.home(0)
    #yield from pymach.home(1)
    #yield from pymach.move([5,5,5,1], 40)
    #yield from pymach.load_print_meta_settings(tinything_archive.read("meta.json").decode("UTF-8"))
    yield from pymach.load_temperature_settings([225,0,0,0])
    yield from pymach.heat()
    yield from pymach.wait_for_heaters_at_target(5)
    yield from pymach.move_axis(0,200,4)
    #for i in range(100):
    #    print(pymach.get_temperature(0))
    #    yield
	
count = 0
for i in do_stuff():
    libmachine.Iterate(machinedriver)

#for i in pymach.shutdown():
#    libmachine.Iterate(machinedriver)
#    #print(pymach.get_axes_position())
    

