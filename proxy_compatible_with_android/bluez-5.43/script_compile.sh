#!/bin/sh

aclocal
libtoolize --force --copy
autoheader
automake --add-missing --copy
autoconf
./configure --enable-library --enable-debug CFLAGS="-std=c99 -I/usr/include/dbus-1.0 -I/usr/lib/x86_64-linux-gnu/dbus-1.0/include -ldbus-1 -pthread -I/usr/include/dbus-1.0 -I/usr/lib/x86_64-linux-gnu/dbus-1.0/include -I/usr/include/gio-unix-2.0/ -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include" LIBS="-lgio-2.0 -ldbus-glib-1 -ldbus-1 -lgio-2.0 -lgobject-2.0 -lglib-2.0"

#./configure --enable-library --enable-debug CFLAGS "-std=c99"
#./configure --enable-library --enable-debug CFLAGS="-std=c99 -I/usr/src/linux-headers-4.9.0-2-common/include"

make -j8 && sudo make install
sudo systemctl daemon-reload
#sudo systemctl restart bluetooth
sudo cp attrib/gatttool /usr/local/bin/
sudo hciconfig hci0 up
