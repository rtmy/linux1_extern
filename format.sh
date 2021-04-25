if [ $# == 1 ]
then
	dd if=/dev/zero of=$1 bs=1M count=32
else
	echo "Usage: $0 <filesystem local file name>"
fi;
