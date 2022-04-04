import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    return parser.parse_args()


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    # print(arp_request.summary())
    # Shows description of this method
    # scapy.ls(scapy.ARP())
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')  # Creates ethernet packet
    # scapy.ls(scapy.Ether())
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)

    return clients_list


def print_result(result_list):
    print("IP\t\t\tMAC address\n------------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])


options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)
