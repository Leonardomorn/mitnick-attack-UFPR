# Biblioteca que roda qualquer coisa que precise do subprocess
import subprocess

def end_mac():
    """
    Obtém o endereço MAC da interface de rede local.

    Retorna:
        str: O endereço MAC da interface de rede.
    """
    resultado = subprocess.run("ifconfig -a | grep br- -A 3 | sed '4!d' | cut -b 15-31", stdout=subprocess.PIPE, shell=True)
    return resultado.stdout.decode().strip("\n")

def interface():
    """
    Obtém a interface de rede que tem 'br-' no nome.

    Retorna:
        str: O nome da interface de rede.
    """
    resultado = subprocess.run("ifconfig -a | grep br- -A 3 | sed '1!d' | cut -d ':' -f1", stdout=subprocess.PIPE, shell=True)
    return resultado.stdout.decode().strip("\n")

def arp_s():
    """
    Configura a tabela ARP para que o IP 10.9.0.6 esteja associado ao endereço MAC 00:00:00:00:00:00.
    """
    subprocess.run(args="arp -s 10.9.0.6 00:00:00:00:00:00", shell=True)