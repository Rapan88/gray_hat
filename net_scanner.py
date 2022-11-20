#!/usr/bin/env python3
import argparse

import scapy.all as scapy


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help='Target IP / IP range')
    return parser.parse_args()


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1)[0]
    client_list = []
    for element in answered_list:
        client_list.append({"ip": element[1].psrc, "mac-address": element[1].hwsrc})
    return client_list


def print_scan(results_list):
    print("IP" + "\t\t\t" + "MAC-ADDRESS")
    for element in results_list:
        print(element["ip"] + "\t\t" + element["mac-address"])


if __name__ == "__main__":
    options = get_arguments()
    print_scan(scan(options.target))
