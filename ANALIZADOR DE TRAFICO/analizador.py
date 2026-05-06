#Comenzando etapa 6

from scapy.all import sniff
from rich.console import Console
from rich.table import Table
from rich import box
from rich.prompt import Prompt, Confirm
from datetime import datetime
from collections import defaultdict, Counter
import sys
import argparse

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
    "total": 0
}

COLORES = {
    "TCP":  "cyan",
    "UDP":  "yellow",
    "DNS":  "magenta",
    "ICMP": "red",
    "OTRO": "white",
    "total": "green"
}

filtro_protocolo = None
archivo_output = None

paquetes_por_ip = Counter()
bytes_por_ip = defaultdict(int)
conexiones = Counter()

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
        return "OTRO"

def guardar_en_archivo(linea):
    """ Abre el archivo en Append y guarda cada linea de los paquetes """
    if archivo_output:
        with open(archivo_output, "a") as f:
            f.write(linea + "\n")

def analizar_paquete(paquete):
    global estadisticas
    #Solo procesa los paquetes IP
    if not paquete.haslayer("IP"):
        return
    
    ip = paquete.getlayer("IP")
    protocolo = obtener_protocolo(paquete)
    origen = ip.src
    destino = ip.dst
    color = COLORES[protocolo]

    if filtro_protocolo and protocolo != filtro_protocolo:
        return

    estadisticas[protocolo] += 1
    estadisticas["total"] += 1

    paquetes_por_ip[origen] += 1
    bytes_por_ip[origen] += len(paquete)
    conexiones[f"{origen} → {destino}"] += 1

    puerto_origen = ""
    puerto_destino = ""
    

    if paquete.haslayer("TCP"):
        puerto_origen = paquete.getlayer("TCP").sport
        puerto_destino = paquete.getlayer("TCP").dport
    elif paquete.haslayer("UDP"):
        puerto_origen = paquete.getlayer("UDP").sport
        puerto_destino = paquete.getlayer("UDP").dport
    
    timestamp = datetime.now().strftime("%H:%M:%S")

    if puerto_origen:
        linea = f"[{protocolo}] {origen}:{puerto_origen} -> {destino}:{puerto_destino}"      #el f"" lo que hace es darle un formato de salida al string
    else:
        linea = f"[{protocolo}] {origen} -> {destino}"
    
    console.print(f"[dim]{timestamp}[/dim] [bold {color}][{protocolo}][/bold {color}] {linea[21:]}")
    guardar_en_archivo(linea)


def mostrar_resumen():
    tabla = Table(title="Resumen de captura", box = box.ROUNDED)

    tabla.add_column("Protocolo", style = "bold")
    tabla.add_column("Paquetes", justify = "right")
    tabla.add_column("Porcentaje", justify = "right")

    total = estadisticas["total"]

    for protocolo in ["TCP", "UDP", "DNS", "ICMP", "OTRO"]:
        cantidad = estadisticas[protocolo]
        if total > 0:
            porcentaje = f"{(cantidad / total *100):.1f}%"
        else:
            porcentaje = "0%"
        color = COLORES[protocolo]
        tabla.add_row(f"[{color}]{protocolo}[/{color}]", str(cantidad), porcentaje)
    
    tabla.add_row("[bold]TOTAL[/bold]", str(total), "100%")
    console.print(tabla)

    if archivo_output:
        console.print(f"[dim]Logs guardados en : {archivo_output}[/dim]")
    
    mostrar_top_talkers()

def mostrar_top_talkers():
    tabla_ips = Table(title="10 IPs mas activas", box=box.ROUNDED)
    tabla_ips.add_column("IP ORIGEN", style="bold cyan")
    tabla_ips.add_column("Paquetes", justify="right")
    tabla_ips.add_column("Datos transferidos", justify="right")

    for ip, cantidad in paquetes_por_ip.most_common(10):
        bytes_total = bytes_por_ip[ip]

        if bytes_total >= 1_000_000:
            tamanio = f"{bytes_total / 1_000_000:.1f} MB"
        elif bytes_total >= 1_000:
            tamanio = f"{bytes_total / 1_000:.1f} KB"
        else:
            tamanio = f"{bytes_total} B"

        tabla_ips.add_row(ip, str(cantidad), tamanio)

    console.print(tabla_ips)

    tabla_frecuentes = Table(title = "Top 5 - Conexiones más frecuentes", box = box.ROUNDED)
    tabla_frecuentes.add_column("Conexión", style = "bold yellow")
    tabla_frecuentes.add_column("Paquetes", justify = "right")

    for conexion, cantidad in conexiones.most_common(5):
        tabla_frecuentes.add_row(conexion, str(cantidad))

    console.print(tabla_frecuentes)

def mostrar_menu():
    console.print("\n[bold cyan]╔══════════════════════════════════════╗[/bold cyan]")
    console.print("[bold cyan]║       NETWORK TRAFFIC ANALYZER       ║[/bold cyan]")
    console.print("[bold cyan]╚══════════════════════════════════════╝[/bold cyan]\n")

    console.print("[bold]1. Filtro de protocolo[/bold]")
    console.print("   [dim]Dejá vacío para capturar todos[/dim]")
    protocolo = Prompt.ask(
        "   Protocolo",
        choices=["TCP", "UCP", "DNS", "ICMP", "TODOS"],
        default="TODOS"
    )

    console.print("\n[bold]2. Guardar log[/bold]")
    guardar = Confirm.ask("   ¿Querés guardar la captura en un archivo?", default=False)

    nombre_archivo = None
    if guardar:
        nombre_archivo = Prompt.ask(
            "   Nombre del archivo",
            default=f"captura_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )

    return protocolo, nombre_archivo


#Punto de entrada con argparser
if len(sys.argv) > 1:
    parser = argparse.ArgumentParser(description = "Analizador de trafico de red")
    parser.add_argument(
        "--protocolo",
        choices = ["TCP", "UCP", "DNS", "ICMP"],
        help = "Filtrar por protocolo exclusivo"
    )
    parser.add_argument(
        "--output",
        help = "Archivo donde guardar el log (ej: captura.log)"
    )
    args = parser.parse_args()
    filtro_protocolo = args.protocolo
    archivo_output = args.output

else:
    protocolo_elegido, archivo_elegido = mostrar_menu()
    filtro_protocolo = None if protocolo_elegido == "TODOS" else protocolo_elegido
    archivo_output = archivo_elegido


#Inicio de captura
if filtro_protocolo:
    console.print(f"[bold green] Filtrando solo: {filtro_protocolo} [/bold green]")
if archivo_output:
    console.print(f"[bold green] Guardando en : {archivo_output}[/bold green]")


console.print("[bold green]INICIANDO CAPTURA DE PAQUETES || CTL + C PARA DETENER[/bold green]")

try:
    sniff(prn = analizar_paquete, store = False, count = 0)
except KeyboardInterrupt:
    pass

console.print("\n[bold yellow]Captura detenida.[/bold yellow]")
mostrar_resumen()

"""
prn es un CallBack que se llama cada que encuentra un paquete
store = False hace que no guarde los paquetes en la RAM para ahoorar recursos
cout = 20 hace que solo registre los primeros 20 paquetes
"""