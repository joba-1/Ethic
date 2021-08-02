# Ethic 

Ethernet Interface Communication: send and receive raw ethernet frames.

* Author: joachim.banzhaf@gmail.com
* Licence: GPL V3

To build this locally, just change to this directory and call `make`
or `gcc -Wall -o ethic main.c`

To build and install ethic for an OpenWRT target, follow this receipe.
It uses OpenWRT cloned to a jobawrt directory and builds an ipk package
in a local feed joba at ~/openwrt-feed/net/ethic. Adapt it as needed.

```
# prepare the openwrt toolchain, e.g. here in directory jobawrt
cd ~/git/jobawrt
make toolchain/install

# prepare local feed joba with package net/ethic
mkdir -p ~/openwrt-feed/net/ethic

# use the template Makefile in the openwrt folder
vi ~/openwrt-feed/net/ethic/Makefile
echo "src-link joba $HOME/openwrt-feed" >>feeds.conf
./scripts/feeds update joba
./scripts/feeds install -a -p joba

# configure package as module or builtin to a firmware
make menuconfig

# compile the app package separately from the rest of the firmware
make package/ethic/compile

# check the results
ls -la bin/packages/*/joba/

# install the app to a running target with hostname ax1
scp bin/packages/*/joba/ethic_*.ipk ax1:/tmp
ssh ax1 ipkg install /tmp/ethic_*.ipk

# see it running on target ax1
ssh ax1 ethic -h
```

if this receipe is too sparse, check out https://openwrt.org/docs/guide-developer/helloworld/start
