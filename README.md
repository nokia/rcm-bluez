# Remote Connection Manager (RCM)

Remote Connection Manager (RCM) - is a research prototype of the 
["Application-agnostic remote access for Bluetooth Low Energy"](https://ieeexplore.ieee.org/document/8406942/).

##### RCM is:
- An abstract layer on top of BLE Protocol Stack
- Provides a transparent connectivity to remote BLE devices
	Connectivity is said transparent when the native applications can access both local
	and remote short-range devices without any modification

- Has no impact on the Bluetooth applications nor the Bluetooth peripherals
- Easy to deploy: RCM is purely software and can be installed as an update of the Bluetooth Protocol Stack
- Offering real-time communication between clients and remote peripherals as if they were in proximity
- Doesn’t rely on complex infrastructures, dedicated hardware nor advanced network features
- Implemented under Bluez 5.43 and tested on real devices.
 
RCM is a proxy-based solution. Thus, we define two kinds of centrals:
- A client is a central device that runs applications accessing the services offered by a peripheral.
The client role is usually played by powerful devices such as smartphones,
PC, tablets, etc. The client may have Bluetooth capabilities but only requires a BPS for our mechanism. The
client device is supposed to be connected to an IP network (e.g. Internet).

- A proxy is a central device reachable via an IP network and having Bluetooth capabilities.
It may also filter an incoming connection that does not comply with configured privacy rules.
Similarly to central devices, it may be a smartphone, tablet, laptop, etc.
It supposed to be connected to an IP network reachable from the client and located in close proximity to some Bluetooth peripherals.

In the current version of RCM, client and proxy are implemented separately, but it may change lately.
Please note that this implementation is still in its initial state and is currently in progress.

# Content

The repository contains client, proxy, visualizer, app and screenshots folders.
1. The first two of them are the rcm-client and rcm-proxy respectively with the bluez-5.43 sources.
RCM itself is implemented as a plugin.

2. Visualizer provides GTK graphic interfaces for client and proxy side.
The client vis is basically a window to enter the proxy's IP and port number and launch the connection.
It doesn't do anything else.
The proxy side is a bit more complex and represents the topology, logs and a way to configure your proxy.
Everything is tested on debian and ubuntu. Graphic interface is based on css but its representation may differ depending on the installed gui...

3. app folder provides the WebBluetooth applications for the devices we used for testing.
Usually, BLE applications are related to a particular BLE device offering specific UUIDs.
Normally this applications are provided for Android OS, IOS, Windows OS ... 
We only used Linux for the moment, so WebBluetooth was a very interesting to us.
One of the provided applications is [this open-source one](https://github.com/urish/web-lightbulb).
The second one is the same but adjusted for the second device we possess.
To write your own WebBluetooth app in most of cases you may need to reverse engineer your device...
You can read more about it [here](https://medium.com/@urish/start-building-with-web-bluetooth-and-progressive-web-apps-6534835959a6).

Normally, you should be able to use any BLE application.
WebBluetooth is just a framework allowing you to use web pages to communicate to your BLE devices through bluez.
It is available on chromium and google chrom web browsers by activating the following experimental flag:
`chrome://flags/#enable-experimental-web-platform-features`

You may also use `hcitool` or `gatttool` to communicate to your device from the command line.

4. The screenshots of "how it should be" as weel as the explanation of different fields in proxy visualizer are provided in the Screenshots folder.

# Needed packages

The provided code includes the sources of *bluez-5.43*, so you do not need to download them separately. 
The provided sources contain some of our callbacks needed by RCM, so please use our modified version of bluez.

You can check how to install bluez from sources [here](https://www.jaredwolff.com/get-started-with-bluetooth-low-energy/#hide1)

Briefly, you will need the following packages:

`libglib2.0-dev
libdbus-1-dev
libusb-dev
libudev-dev
libical-dev
systemd libreadline-dev`

May be also `automake gcc libtool gdb` etc. if not already installed

For the visualizers:

`libglib2.0-dev
libdbus-glib-1-dev
libgtk-3-dev`

You can use the provided script compile_rcm.sh that combines general steps for successful compilation and installation.
See inside this script for more details.
If it crashes on the configure step, it will usually indicate you what package is missing.
So, just look carefully on the line where the configure script has crashed, install the missing package and run the script again.

To compile the visualizers, just go to a corresponding folder et run make it will create an executable.

# How to run?

1. Install the client and proxy parts on the corresponding Linux machines.
	
`./compile_rcm.sh`

`./run_bluez_rcm.sh`

2. Check with hciconfig that your bluetooth interface is up:

`hciconfig`

If it is marked as down, for example, like this:

![hciconfig output](/screenshots/hciconfig.png)

You may use the following command to activate the corresponding hci (hci0 in my case):

`sudo hciconfig hci0 up`

Note that you do not need a physical bluetooth interface on client side because the communication will pass through the proxy.
So, you can use the emulator provided by bluez and located in the emulator folder. See *"How to create a virtual hci"* section below.

3. Run the bluetooth daemon with the coresponding rcm plugin. Check the run_bluez_rcm.sh script to know how to run it with gdb.

# How to create a virtual hci?

1. First, you need insert the special kernel module by running the following command:

`sudo modprobe hci_vhci`

2. Then, open your script_compile inside the client/bluez-5.43 and add the key --enable-experimental right after the ./configure word, keep everything that follows.

`./configure --enable-experimental ...`

For example, your line will become like this:

`./configure --enable-experimental --enable-library --enable-debug CFLAGS="-std=c99" LIBS="-lgio-2.0 -lgobject-2.0"`

3. Compile everything as for the first time (decomment the first lines inside the compile_rcm.sh)

4. Now, if you enter the emulator folder, you will see `btvirt` appeared.

This is our emulator. We could use it to create a virtual hci with BLE support :

`sudo ./btvirt -l 1 -L`

Now, if you execute `hciconfig`, you will see your virtual interface created, for example something like this should appear. Look at the Bus parameter, it's value is *Virtual*, so we are sure that this is our emulated device:

`hci1:    Type: Primary  Bus: Virtual
    BD Address: 00:AA:01:00:00:23  ACL MTU: 192:1  SCO MTU: 0:0
    DOWN
    RX bytes:0 acl:0 sco:0 events:13 errors:0
    TX bytes:72 acl:0 sco:0 commands:13 errors:0`

You can put it up or down as a normal hci interface. You will also have a folder corresponding to this adapter appeared in /var/lib/bluetooth. As usual, the cache and discovered devices will be stored there. Do not forget to clean it.

# What next?

1. Once you are inside the proxy, it is not listening yet. First, it should be initialized.
Initialize proxy means configuring the list of devices it can see (e.g. to limit the noise and do not discover the devices of your neighbours).
To do so, run the visualizer and click on Initialize button.
A new window will appear and show the discovered devices.
Select the ones you want to keep discovering. By default, this filter is empty.
Later, we plan to save it into a file and load when proxy runs. Bu it is not implemented yet.

When Filter button is clicked, the proxy create its initial filter and starts listening on the port number 1500.

2. Client side, you can run the vis and connect to your proxy IP, port 1500.
3. In the proxy vis you will observe your client appearing.
4. By default, clients are not configured and are now allowed to discover any device.
So, you need to configure the client filters.
Click on the Configure Client button, select the client from the list (click twice on a corresponding line).
Then drag and drop the devices from the proxy init filter (left part) to the client filter (right part) and click on Validate button.
5. Now you can run an application on the client side and try to discover, connect and write a characteristic value.
For the moment, only write is possible.
