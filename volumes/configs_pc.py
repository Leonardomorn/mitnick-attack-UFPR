#biblioteca que roda qualquer coisa que precise do subprocess
import subprocess

def end_mac():
    resultado = subprocess.run("ifconfig -a | grep br- -A 3 | sed '4!d' | cut -b 15-31", stdout=subprocess.PIPE, shell=True)
    return resultado.stdout.decode().strip("\n")

# Pega a interface com br- do ifconfig
def interface():
    resultado = subprocess.run("ifconfig -a | grep br- -A 3 | sed '1!d' | cut -d ':' -f1", stdout=subprocess.PIPE, shell=True)
    return resultado.stdout.decode().strip("\n")

def arp_s():
    subprocess.run(args="arp -s 10.9.0.6 00:00:00:00:00:00", shell=True)
