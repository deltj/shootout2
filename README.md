# shootout2

[![Build Status](https://travis-ci.com/deltj/shootout2.svg?branch=master)](https://travis-ci.com/deltj/shootout2)

## Project Overview

Shootout 2 is an evolution of the previous Kismet-based shootout [kis_shootout_python](https://github.com/deltj/kis_shootout_python).  The previous shootout tool has some shortcomings that this tool aims to address:
1. Missing Packets - Without a controlled source of 802.11 packets, we can't detect the case of a packet being missed by all interfaces under test.
2. Relative Performance - If we only know the total number of packets seen by each interface under test, our ability to detect some performance issues is limited.  This is related to the Missing Packets problem; if interface A sees packet 1 but not packet 2, and interface B sees packet 2 but not packet 1, we'll be tricked into thinking these interfaces have equivalent performance when in fact they do not.

To address these issues, shootout 2 uses a control interface with packet injection.  This isn't perfect (unless you use cables and attenuators to directly connect the control interface to the interfaces under test...) because the interfaces under test will still receive "clutter" packets that are sent by systems not involved in the test but happen to be nearby, but I think it's an improvement.

Shootout2 also hashes each packet in the test so that it can know exactly which interfaces received which packets.  This should help identify more specific performance issues.

## Status

Shootout2 is still in development; it doesn't work yet.  Sorry.

## Building and Usage

### Dependencies

* libpcap
* boost

On Ubuntu 18.04 LTS:
`sudo apt install libpcap-dev libboost-all-dev`

### Build

The program needs to be run as root to capture from live interfaces.  Use -i to 
specify the interfaces under test.

`sudo ./shootout2 -i wlp7s0 -i wlp6s0 -i wlp8s0`
