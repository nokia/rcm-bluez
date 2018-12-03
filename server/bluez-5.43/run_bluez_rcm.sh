#!/bin/bash
# in case you need to kill the bluetooth daemon, stop bluetooth service, activate your bluetooth interface etc...

#sudo pkill -9 bluetoothd
#sudo service bluetooth stop
#sudo hciconfig hci0 up
sudo gdb /usr/local/libexec/bluetooth/bluetoothd

#then in gdb type :
# client side:
# run -d -n -p rcm_client
# proxy-side:
#run -d -n -p rcm_proxy
