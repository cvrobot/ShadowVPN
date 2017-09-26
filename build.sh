#! /bin/sh
if [ -z $1 ] ; then
	echo "./build.sh platform clean"
	echo "\tplatform : w (for Windows), l (for Linux)"
	echo "\tclean: c (for Clean)"
	exit 0
fi

if [ $2 = 'c' ] ; then
  make clean
fi

./autogen.sh

if [ $1 = 'w' ] ; then
	./configure --host=i686-w64-mingw32 --enable-static
else
	./configure --enable-static --sysconfdir=/etc
fi
make
