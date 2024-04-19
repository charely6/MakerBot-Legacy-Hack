#! /bin/sh

# burns a new firmware image, including kernel and filesystem
# usage : firmware_burn.sh burn_arg [/path/to/filesystem_image] [/path/to/kernel_image]
#       burn_arg: describes whether to burn the kernel or the filesystem or both: options {kernel | filesystem | both}
# examples :
#  to burn a kernel image:      firmware_burn.sh kernel /home/temp/firmware/uImage
#  to burn a filsystem image:   firmware_burn.sh fileystem /home/temp/firmware/ubifs_platypus.img
#  to burn both:                firmware_burn.sh both /home/temp/firmware/ubifs_platypus.img /home/temp/firmware/uImage
#

burn_filesystem=0
burn_kernel=0

if test -z $1
then
    echo "burn argument is required {kernel | filesystem | both}"
    return
elif [ $1 == "kernel" ]
then
    burn_kernel=1
    kernel_name=$2
elif [ $1 == "filesystem" ]
then
    burn_filesystem=1
elif [ $1 == "both" ]
then
    burn_kernel=1
    burn_filesystem=1
    kernel_name=$3
else
    echo $1
    echo "burn argument invalid.  must be {kernel | filesystem | both}"
fi

    
if [ $burn_kernel -eq 1 ]
then
    /usr/scripts/kernel_burn.py $kernel_name
fi

if [ $burn_filesystem -eq 1 ]
then
    /usr/scripts/filesystem_burn.py $2
fi

