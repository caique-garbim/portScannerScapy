#!/usr/bin/python

# Importa a biblioteca Sys e Scapy
import sys
from scapy.all import *

# Caso o usuario nao informar os 3 argumentos necessarios
if len(sys.argv) <= 3:
	print ("\n PORT SCANNER - SCAPY \n")
	print (" [*] Modo de uso: ")
	print ("     Informe o IP alvo, porta inicial (min: 1) e porta final (max: 65535).")
	print (" [*] Exemplo: ")
	print ("     python3 port_scan_scapy.py 192.168.15.1 21 443")
else:
	# Verbose desativado (saida limpa)
	conf.verb = 0
	print ("\n PORT SCANNER - SCAPY \n")

	# Laço de repetiçao para criar o range da porta inicial-final. Converte os args em inteiros.
	for portas in range(int(sys.argv[2]),int(sys.argv[3])):
		# Define o IP destino conforme arg 1
		pIP = IP(dst=sys.argv[1])
		# Define a porta e a flag SYN (Syn Scan/Half Open)
		pTCP = TCP(dport=portas,flags="S")
		# Encapsulamento
		pacote = pIP/pTCP
		# Envia o pacote e salva resposta
		resp, noresp = sr(pacote)
		# Salva em var porta a porta da resposta
		porta = resp[0][1][TCP].sport
		# Salva em var flag a flag da resposta
		flag = resp[0][1][TCP].flags
		# Condiçao: se a porta estiver aberta (SA), sera exibido
		if (flag == "SA"):
			# Exibir a porta e a flag correspondente
			print (" [+] Porta",porta,"/ TCP aberta")
