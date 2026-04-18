from scapy.all import sniff
from rich.console import Console
from rich.table import Table
from rich import box

#haslayer pregunta si tiene un protocolo, en este caso IP (pero puede ser TCP, UDP, ICMP, DNS)
#getlayer accede a los protocolos

console = Console()

#Defino variables globales para que se puedan usar en tdoas las funciones

estadisticas = {    #en este caso es un diccionario
    "TCP": 0,
    "UDP": 0,
    "DNS": 0,
    "ICMP": 0,
    "OTRO": 0,
    "PROTOCOLOS TOTALES": 0
}

COLORES = {
    "TCP":  "cyan",
    "UDP":  "yellow",
    "DNS":  "magenta",
    "ICMP": "red",
    "OTRO": "white",
    "PROTOCOLOS TOTALES": "green"
}

def obtener_protocolo(paquete):
    """DEVUELVE EL PROTOCOLO PRINCIPAL DEL PAQUETE COMO UN STRING"""
    if paquete.haslayer("TCP"):
        return "TCP"
    elif paquete.haslayer("UDP"):
        #DNS VA DENTO DE UDP
        if paquete.haslayer("DNS"):
            return "DNS"
        return "UDP"
    elif paquete.haslayer("ICMP"):
        return "ICMP"
    else:
        return "OTRO PROTOCOLO"

def analizar_paquete(paquete):
    global estadisticas
    #Solo procesa los paquetes IP
    if not paquete.haslayer("IP"):
        return
    
    ip = paquete.getlayer("IP")
    protocolo = obtener_protocolo(paquete)
    origen = ip.src
    destino = ip.dst
    color = COLORES[protocolo] #ACA QUEDASTE
    
    puerto_origen = ""
    puerto_destino = ""
    
    if paquete.haslayer("TCP"):
        puerto_origen = paquete.getlayer("TCP").sport
        puerto_destino = paquete.getlayer("TCP").dport
    elif paquete.haslayer("UDP"):
        puerto_origen = paquete.getlayer("UDP").sport
        puerto_destino = paquete.getlayer("UDP").dport
    
    if puerto_origen:
        print(f"[{protocolo}] {origen}:{puerto_origen} -> {destino}:{puerto_destino}")      #el f"" lo que hace es darle un formato de salida al string
    else:
        print(f"[{protocolo}] {origen} -> {destino}")


print("INICIANDO CAPTURA DE PAQUETES || CTL + C PARA DETENER")

sniff(prn = analizar_paquete, store = False, count = 20)
"""
prn es un CallBack que se llama cada que encuentra un paquete
store = False hace que no guarde los paquetes en la RAM para ahoorar recursos
cout = 20 hace que solo registre los primeros 20 paquetes
"""