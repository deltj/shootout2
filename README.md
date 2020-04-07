# shootout2

https://travis-ci.com/deltj/shootout2.svg?branch=master

## Project Overview

This tool is an evolution of the previous Kismet-based shootout ([https://github.com/deltj/kis_shootout_python]).  The previous shootout tool has some shortcomings that this tool aims to address:
1. Missing Packets - Without a controlled source of 802.11 packets, we can't detect the situation of a packet being missed by all interfaces under test.
2. Relative Performance - If we only know the total number of packets seen by each interface under test, our ability to detect some performance issues is limited.  This is related to the Missing Packets problem; if interface A sees packet 1 but not packet 2, and interface B sees packet 2 but not packet 1, all we know is that both interfaces received one packet - not *which* packet.

To address these issues, shootout 2 uses a control interface with packet injection.  This isn't perfect (unless you use cables and attenuators to directly connect the control interface to the interfaces under test...) because the interfaces under test will still receive "clutter" packets that are sent by systems not involved in the test that happen to be nearby, but I think it's an improvement.

Shootout2 also hashes each packet in the test so that it can know exactly which interfaces received which packets.  This should help identify more specific performance issues.

## Status

Shootout2 is still in development; it doesn't work yet.  Sorry.
