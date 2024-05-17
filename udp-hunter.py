import argparse
import binascii
import json
import os
import pathlib
import socket
import threading
from time import gmtime, strftime
from paths import UDP_PATH, UDP_HELP_PATH
import ifaddr
from netaddr import IPNetwork


# --file IP_V4Targets.txt --output data.json
# --host 8.8.8.8 --output data.json


def getlocaladdress():
    adapters = ifaddr.get_adapters()
    i = 1
    for adapter in adapters:
        local_ips.append((str(adapter.nice_name), str(adapter.ips[0].ip[0]), str(adapter.ips[1].ip)))
    for localip in local_ips:
        print(i, localip[0], ": IPv6", localip[1], ": IPv4", localip[2])
        i += 1


def gethostdata(name):
    try:
        print(socket.gethostbyname(name))
    except socket.gaierror as err:
        print("Cannot resolve hostname: ", name, err)
    exit()


local_ips = []
banner = "UDP Hunter v0.1beta - Updated on 26 February 2020"
host_ip_v4 = ""
host_ip_v6 = "::"
pack = []
port_list = []
probe_list = []
arg_error = ""
target = []
failed_target = []
filename = ""
help_data = []
output = []
output_tuple = []
output_file_str = ""
output_filename = ""
probe_master_file = UDP_PATH
probe_help = UDP_HELP_PATH
probe_help_list = []
probe_master = []
noise = "False"
timeout = 1.0
probe_display_list = []
probe_display_str = ""

parser = argparse.ArgumentParser(description='UDP Hunter', epilog='UDP Hunter')
parser.add_argument("--hosts", help="Provide host names by commas", dest='host', required=False)
parser.add_argument("--file", help="Provide file input", dest='filename', required=False)
parser.add_argument("--output", help="Provide output", dest='output', required=False)
parser.add_argument("--verbose", help="Ignore verbose output --verbose=false", dest='verbose', required=False)
parser.add_argument("--ports", help="Provide port(s)", dest='ports', required=False)
parser.add_argument("--probes", help="Provide probe(s)", dest='probes', required=False)
parser.add_argument("--retries", help="Provide retries", dest='retries', required=False, type=int, default=3)
parser.add_argument("--noise", help="Provide noise", dest='noise', required=False)
parser.add_argument("--timeout", help="Provide noise", dest='timeout', required=False, type=float, default=0.3)
parser.add_argument("--lhost4", help="Provide IPv4 of listner interface", dest='lhost4', required=False)
parser.add_argument("--lhost6", help="Provide IPv6 of listner interface", dest='lhost6', required=False)
parser.add_argument("--configfile", help="Provide port(s)", dest='configfile', required=False)
parser.add_argument("--probehelp", help="Provide port(s)", dest='probehelp', required=False)
args = parser.parse_args()  # print(args.accumulate(args.integers))

if (args.lhost4 is None) or (args.lhost6 is None):
    if os.name == "posix":
        if args.lhost4 is None:
            host_ip_v4 = ""
        else:
            host_ip_v4 = args.lhost4
        if args.lhost6 is None:
            host_ip_v6 = "::"
        else:
            host_ip_v6 = args.lhost6
    else:
        print(getlocaladdress())
        input_val = input("Select a network adapter to set IPv4 and IPv6 listening hosts:\n")
        if args.lhost6 is None:
            host_ip_v6 = local_ips[int(input_val) - 1][1]
        else:
            host_ip_v6 = args.lhost6
        if args.lhost4 is None:
            host_ip_v4 = local_ips[int(input_val) - 1][2]
        else:
            host_ip_v4 = args.lhost4
else:
    host_ip_v4 = args.lhost4
    host_ip_v6 = args.lhost6

if host_ip_v4 == "":
    print("Listening IPs were set to IPv6 - ", host_ip_v6, " and IPv4 - Default", host_ip_v4)
else:
    print("Listening IPs were set to IPv6 - ", host_ip_v6, " and IPv4 - ", host_ip_v4)
if args.configfile:
    probe_master_file = args.configfile
if args.probehelp:
    probe_help = args.probehelp

# fhelp = probehelp.read_text()
# for line in fhelp:
#     if line != "\n":
#         temp = line.rstrip('\n')
#         tempp = [x.strip() for x in temp.split(',')]
#         flag = 'valid'
#         for i in range(len(probehelplist)):
#             if tempp[0] == probehelplist[i][0]:
#                 flag = 'invalid'
#                 probehelplist[i][1].append(tempp[1])
#                 break
#         if flag == 'valid':
#             probehelplist.append([tempp[0], [tempp[1]]])

# f = probemasterfile.read_text()
# for line in f:
#     if line != "\n":
#         temp = line.rstrip('\n')
#         if temp[:1] != "#":
#             tempp = [x.strip() for x in temp.split(',')]
#             flag = 'valid'
#             for i in range(len(probemaster)):
#                 if int(probemaster[i][0]) == int(tempp[0]):
#                     probemaster[i][1].append((tempp[1], tempp[2]))
#                     flag = 'invalid'
#                     break
#             if flag == 'valid':
#                 probemaster.append((int(tempp[0]), [(tempp[1], tempp[2])]))

if args.host == args.filename:
    print('--host or --filename required')
    exit()

if args.host:
    hosts = args.host
    target = hosts.split(",")
if args.filename:
    filename = args.filename
    f = open(filename, "r")
    for line in f:
        if line != "\n":
            sline = line.rstrip('\n')
        if "/" in sline:
            for ip in IPNetwork(sline):
                target.append(str(ip))
        else:
            target.append(sline)
if args.ports:
    ports = args.ports
    port_list = ports.split(",")
if args.probes:
    probe_list = args.probes
    probe_list = probe_list.split(",")
if args.output:
    output_filename = args.output
if args.retries:
    retries = args.retries
if args.noise is not None:
    noise = args.noise
if args.timeout != "True" and args.timeout is not None:
    timeout = args.timeout

# Create a pack/list which will include the probes and ports to be scanned with probe, servicename, port number etc.
if args.ports or args.probes:
    for i1 in range(len(probe_master)):
        for ports in port_list:
            if probe_master[i1][0] == int(ports):
                for i2 in range(len(probe_master[i1][1])):
                    pack.append((probe_master[i1][0], probe_master[i1][1][i2][0], probe_master[i1][1][i2][1],
                                 binascii.unhexlify(probe_master[i1][1][i2][1])))
        # print probe_list,port_list
        for probes in probe_list:
            if 1 == 1:
                for i2 in range(len(probe_master[i1][1])):
                    if probe_master[i1][1][i2][0] == probes:
                        pack.append((probe_master[i1][0], probe_master[i1][1][i2][0], probe_master[i1][1][i2][1],
                                     binascii.unhexlify(probe_master[i1][1][i2][1])))
else:
    for i1 in range(len(probe_master)):
        for i2 in range(len(probe_master[i1][1])):
            pack.append((probe_master[i1][0], probe_master[i1][1][i2][0], probe_master[i1][1][i2][1],
                         binascii.unhexlify(probe_master[i1][1][i2][1])))
# END OF
# Create a pack/list which will include the probes and ports to be scanned with probe, servicename, port number etc.

print("\nStarting UDP Hunter at " + strftime("%Y-%m-%d %H:%M:%S GMT", gmtime()))
# print("\nCommand with arguments  : " + " ".join(sys.argv))
print("-----------------------------------------------------------------------------")
if len(filename) > 0:
    print("Input File for Ips      : " + filename)
if len(port_list) > 0:
    print("Port List               : " + str(port_list))
elif len(probe_list) > 0:
    print("Probe List              : " + str(probe_list))
else:
    print("Probe List              : ALL")
print_ips = (str(", ".join(target))[:75] + '..') if len(str(", ".join(target))) > 75 else str(", ".join(target))
print("Scanning report for IPs : " + print_ips)
probelist = ""

for probe in pack:
    probelist += probe[1] + ", "
print("Sending probe(s)        : %s to %s IP(s)" % (probelist[:-2], str(len(target))))
print("-----------------------------------------------------------------------------")

target_v4 = []
target_v6 = []

for host_data in target:
    if "." in host_data:
        try:
            target_v4.append(socket.gethostbyname(host_data))
        except socket.gaierror as err:
            failed_target.append(str(host_data) + " : Could not resolve hostname: " + str(err))
    else:
        target_v6.append(host_data)

target = target_v4

sock_add_family = socket.AF_INET
sock_ip_proto = socket.IPPROTO_IP


def udp_sender(target, pack):
    for ip in target:
        for probe in pack:
            try:
                sender = socket.socket(sock_add_family, socket.SOCK_DGRAM)
                sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                for retry in range(retries):
                    sender.sendto(probe[3], (ip, probe[0]))  # sender.sendto(probe[2],(ip,port))
            except Exception as e:
                failed_target.append(str(ip) + " : Could not send probe: " + str(e))
                pass


def getsniffer(host):
    output_file_str = ""
    sniffer = socket.socket(sock_add_family, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sniffer.bind((host, 0))
    sniffer.setsockopt(sock_ip_proto, socket.IP_HDRINCL, 1)
    sniffer.settimeout(int(float(timeout) * 60))  ### Set timeout - 60 seconds

    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  ## might be not necessary in this case

    t = threading.Thread(target=udp_sender, args=(target, pack))
    t.start()
    print_flag = "false"
    final_result = []

    try:
        while True:
            raw_buffer = sniffer.recvfrom(65565)
            snif = binascii.hexlify(raw_buffer[0])
            source_ip = raw_buffer[1][0]

            if "." in source_ip:
                port = str(int(snif[40:44], 16))  # FOR IPv4
            elif ":" in source_ip:
                port = str(int(snif[0:4], 16))  # FOR IPv6

            if snif != "" and print_flag == "false":
                print("%-40s %-10s %-5s %s" % ("IP", "PORT(UDP)", "STAT", "SERVICE"))
                print_flag = "true"

            print_service = ""
            for i in range(len(probe_master)):
                if int(probe_master[i][0]) == int(port):
                    for ii in range(len(probe_master[i][1])):
                        if print_service != "":
                            print_service += "/"
                        print_service += probe_master[i][1][ii][0]
            if print_service == "":
                print_service = "Unknown Service"

            pack_port = []
            for i in range(len(pack)):
                pack_port.append(str(pack[i][0]))
            if '%' in str(source_ip):
                source_ip = str(source_ip)[0:str(source_ip).index('%')]
            if (((port in pack_port) and (str(source_ip) in target) and (noise in ["False", "false"])) or (
                    noise in ["True", "true"])) and ((str(source_ip), port) not in output_tuple):
                if str(source_ip) != "::1":
                    print("%-40s %-10s open  %s" % (str(source_ip), port, print_service))
                output.append([str(source_ip), port, print_service, snif])
                output_tuple.append((str(source_ip), port))

                final_result.append({"Host": str(source_ip),
                                     "Port": str(port),
                                     "State": "open",
                                     "UDP Service": str(print_service)})

                if args.verbose not in ["false", "False"]:
                    output_file_str = "Host: " + str(source_ip) + "; PORT: " + str(
                        port) + ";" + ' STATE: open' + "; UDP Service:" + str(print_service) + "; " + str(snif) + " \n\n"
                else:
                    output_file_str = "Host: " + str(source_ip) + "; PORT: " + str(
                        port) + ";" + ' STATE: open' + "; UDP Service:" + str(print_service) + " \n\n"

    except socket.timeout:
        if float(timeout) >= 1.0:
            print("\nINFO: Sniffer timeout was set to " + str(timeout) + " minutes")
        else:
            print("\nINFO: Sniffer timeout was set to " + str(float(timeout) * 60) + " seconds")

    except Exception as e:
        print("\nError occured: 20001, More information: :" + str(e))

    # handle CTRL-C
    except KeyboardInterrupt:
        # Windows turn off promiscuous mode
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

    finally:
        if args.output:
            root_path = pathlib.Path(__file__).parent
            file_path = root_path.joinpath(args.output)
            file_path.write_text(json.dumps(final_result))


try:
    if len(target) == 0:
        pass
    else:
        getsniffer(host_ip_v4)
except Exception as e:
    print("Error occured: 30001, More information: " + str(e))
finally:
    if len(target_v6) != 0:
        print("Starting testing of IPv6 IP address...")
        target = target_v6
        sock_add_family = socket.AF_INET6
        sock_ip_proto = socket.IPPROTO_IPV6
        getsniffer(host_ip_v6)

