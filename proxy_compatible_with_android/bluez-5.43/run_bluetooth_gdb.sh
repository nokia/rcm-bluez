#!/bin/bash
sudo pkill -9 bluetoothd
sudo service bluetooth stop
sudo hciconfig hci0 up
sudo gdb /usr/local/libexec/bluetooth/bluetoothd
#then in gdb type : run -d -n
