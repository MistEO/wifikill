Wifi Kill
========

A python program that uses scapy to kick people off of wifi. The script must be run as `sudo`. The script also requires that scapy be installed. To install it, do

    sudo apt-get install python-scapy

The program lists the devices connected to the network then allows you to:
 - Prevent the desired ip from accessing the network
 - Prevent everyone from accessing the network

## Usage

```bash
wifikill.py [-h] [-k ip|mac [ip|mac ...] | -r ip|mac [ip|mac ...] 
                    | -ka | -ra] [-ig ip|mac [ip|mac ...]] [--details] [--lan ip]
```

### Arguments
- `-h, --help`
:    show this help message and exit

- `-k ip|mac [ip|mac ...]`
:    kill the addresses

- `-r ip|mac [ip|mac ...]`
:    restore the addresses

- `-ka`
:    kill all addresses in the LAN

- `-ra`
:    restore all addresseses

- `-ig ip|mac [ip|mac ...]`
:    ignore the addresses

- `--details`
:    show kill details

- `--lan ip`
:    manually specify the lan ip