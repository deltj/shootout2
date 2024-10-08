# shootout2

[![SonarCloud](https://sonarcloud.io/images/project_badges/sonarcloud-white.svg)](https://sonarcloud.io/summary/new_code?id=deltj_shootout2)

## Project Overview

Shootout 2 is an evolution of the previous Kismet-based shootout ([kis_shootout_python](https://github.com/deltj/kis_shootout_python)).  The previous shootout tool has some shortcomings that this tool aims to address:
1. Relative Performance - If we only know the total number of packets seen by each interface under test, our ability to detect some performance issues is limited.  This is related to the Missing Packets problem; if interface A sees packet 1 but not packet 2, and interface B sees packet 2 but not packet 1, we'll be tricked into thinking these interfaces have equivalent performance when in fact they do not.
2. Diagnostics - Shootout2 allows missed packets to be saved for later analysis, so that the specific parameters (e.g. modulation type, channel, etc) of missed packets can be understood.
3. Missing Packets - Without a controlled source of 802.11 packets, we can't detect the case of a packet being missed by all interfaces under test.

Shootout2 computes a SHA-256 hash for each observed packet (ignoring the radiotap header and FCS) during the test so that it can know exactly which interfaces received which packets.  This should help identify more specific performance issues, at the cost of some CPU time to compute the hashes.

I plan to add a control interface with packet injection (eventually).  This won't be perfect (unless you use cables and attenuators to directly connect the control interface to the interfaces under test, and maybe use an RF shielded test environment for good measure...) because the interfaces under test may still receive "clutter" packets that are sent by systems not involved in the test that happen to be nearby.

## Status

Shootout2 is still in development.  It may kind of work, but it's certainly not finished yet.

## Building and Usage

### Dependencies

* libpcap
* libnl-3.0
* libmnl
* kernel headers
* openssl
* ncurses
* check

Debian-based distros (Ubuntu, kali, raspbian, etc.):

`sudo apt install libpcap-dev libnl-3-200 libnl-nf-3-dev libmnl0 libmnl-dev libssl1.1 libssl-dev libncurses6 libncurses-dev check`

RPM distros (RHEL, Rocky, etc.):

`sudo dnf install -y glib2 glib2-devel libpcap libpcap-devel libnl3 libnl3-devel libmnl libmnl-devel openssl openssl-devel ncurses ncurses-devel check check-devel`

### Build

```
mkdir build
cd build
cmake ..
make
```

### Usage

The program needs to be run as root to manipulate wifi interfaces and capture from live interfaces.  Use the `-i` argument to specify an interface to test (use this argument multiple times to test many interfaces).

First, use the `iw` command to list wifi interfaces on your system.  You should see something like the following output:

```
$ iw dev
phy#0
	Interface wlp0s20f0u3u1
		ifindex 3
		wdev 0x1
		addr ca:20:4c:xx:yy:zz
		type monitor
		channel 1 (2412 MHz), width: 20 MHz (no HT), center1: 2412 MHz
		txpower 14.00 dBm
		multicast TXQ:
			qsz-byt	qsz-pkt	flows	drops	marks	overlmt	hashcol	tx-bytes	tx-packets
			0	0	0	0	0	0	0	0		0
```

In this case, wlp0s20f0u3u1 is the name of one of the interfaces on my system.  After collecting the interface names, you can run shootout like this:

`sudo ./shootout2 -i wlp0s20f0u3u1`
