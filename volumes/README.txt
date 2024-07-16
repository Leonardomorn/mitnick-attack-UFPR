Como executar:
1-Subir o docker com --build -d
2-Preparar o ambiente: entrar no x_terminal pelo docker exec e usar o comando echo "10.0.9.6" > root/.rhosts
3-Ctrl + D
3- Entrar na máquina atacante pelo docker exec
4- Usar o comando python3 volumes/main.py
5- Ao terminar, use rsh 10.9.0.5configs_pc.py:


Bibliotecas

configs_pc.py: tudo que é relacionado a subprocessos

end_mac(): Obtém o endereço MAC local.
interface(): Obtém a interface de rede local.
arp_s(): Configura a tabela ARP para associar um IP específico a um endereço MAC inválido.


main.py:

Função main(): Executa o ataque ARP spoofing e a invasão ao servidor, utilizando multiprocessing para rodar o ARP spoofing em paralelo com a invasão.


mitnick.py:

arp_spoof(): Realiza o ARP spoofing para enganar a máquina alvo.
arp_spoofing(): Executa o ARP spoofing contínuo para manter a tabela ARP envenenada.
invade(): Realiza a invasão ao servidor, estabelecendo uma conexão TCP e enviando um comando RSH para modificar o arquivo .rhosts do servidor alvo.

