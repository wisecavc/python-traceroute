# Python Traceroute

A Python application that implements Traceroute functionality, built using skeleton code provided by Oregon State University's Intro to Computer Networks course. This project uses Python 3.12.3 and is primarily designed for Windows operating systems.

## Table of Contents
1. [Overview](#overview)
2. [Installation](#installation)
    - [System Requirements](#system-requirements)
    - [Firewall Configuration](#firewall-configuration)
3. [Usage](#usage)
    - [sendPing() Function](#sendping-function)
    - [traceRoute() Function](#traceroute-function)
4. [Known Bugs](#known-bugs)
5. [License](#license)

## Overview
This Python-based Traceroute application sends ICMP Echo Requests and listens for Echo Replies to trace the route packets take to a target host in order to assess round-trip times and connentivity.

## Installation

### System Requirements
- Python 3.12.3
- Windows OS (not tested on Linux or MacOS).

### Firewall Configuration
To use this application, you may need to update your operating system's firewall settings to allow for additional ICMP messages by following this guide to configure your firewall for ICMP traffic.: [Microsoft guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure)

## Usage

### sendPing()

The sendPing() function only requires a target host passed as a parameter to run. It will send 4 packets and validate them using ICMP Echo Replies. 4 packets will be sent and received, which is the same number as was originally defined in the skeleton code for the __sendIcmpEchoRequest() function. To change this, pass a second parameter after host to __sendIcmpEchoRequest() to edit the TTL. Keep the traceroute parameter the same (False) to prevent TTL from decrementing after every hop. All end-of-ping stats (RRT, packet drop percentage, etc.) will be sent after the last packet reply is received.

### traceRoute()

The traceRoute() functions very similarly to the sendPing() function, the only difference is that it integrates a decrementing TTL when sending pings to a host. The number of hops taken by the traceroute is set to 50 as default in __sendIcmpTraceRoute(). If you want to adjust the number of hops, change the “hops” variable in the code (it is one of three lines making up the function, so it is easy to find). The traceRoute() function does not end when the host is reached, instead echo responses are sent until the TTL is depleted.

## Known Bugs
- The Traceroute functionality does not stop after receiving type 0 Echo Reply. It continues running until the TTL limit is reached (TTL = -1).
- TTL should start at 1 to avoid crashes on Linux and potentially MacOS, as TTL = 0 is not valid.
