##SCRIPT CREADO PARA NO SER ATRAPADOS
#EIDDR
#26ERRORS XD
#FAN_TASMA
import os
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP
from rich.console import Console
from datetime import datetime

console = Console()


start_time = time.time()
total_requests = 0  # Contador de peticiones 
current_minute_requests = 0  # Contador de peticiones por minuto
protocols_used = set()  # Protocolos detectados durante la captura (normales)

def process_packet(pkt, target, max_requests_per_minute, start_minute):
    
    global total_requests, current_minute_requests, protocols_used

    if pkt.haslayer(IP):  # Verificamos que tenga capa IP
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        protocol = "Desconocido"

        # Identificamos el protocolo
        if pkt.haslayer(TCP):
            protocol = "TCP"
        elif pkt.haslayer(UDP):
            protocol = "UDP"
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"
        elif pkt.haslayer(HTTP):
            protocol = "HTTP"
        elif pkt.haslayer(HTTPS):
            protocol = "HTTPS"

        # Guard al protocolo utilizado
        protocols_used.add(protocol)

        # Imprimimos la información del paquete
        console.print(f"[green]Protocolo:[/green] {protocol} | "
                      f"[cyan]IP Origen:[/cyan] {src_ip} | "
                      f"[yellow]IP Destino:[/yellow] {dst_ip}")

        # sum los contadores
        total_requests += 1
        current_minute_requests += 1

        # Veri si ha pasado un minuto
        elapsed_time = time.time() - start_minute
        if elapsed_time > 60:
            # Reiniciamos el contador por minuto para falsos positivos
            current_minute_requests = 0
            start_minute = time.time()

        #ver si se ha alcanzado el límite de peticiones por minuto
        if current_minute_requests > max_requests_per_minute:
            console.print("[bold red]¡Límite de peticiones alcanzado! Desconectando el internet...\nPARKER ESTAS DEMENTE[/bold red]")
            disconnect_internet()
            ask_reconnect(target)
            return True, start_minute  # Detenemos el sniff xd

    return False, start_minute

def disconnect_internet():
    """
    Desconecta la interfaz de red (requiere privilegios de administrador) correr con su xd.
    Esto solo en linux.
    """
    try:
        os.system("sudo ifconfig eth0 down")  # Cambia a tu interfaz de red
        console.print("[bold red]Internet desconectado exitosamente.\nDETEN TUS ATAQUES RECUERDA LO QUE PASA XD[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Error al desconectar la red: {e}[/bold red]")

def reconnect_internet():
    """
    Reconecta la interfaz de red.
    """
    try:
        os.system("sudo ifconfig eth0 up")  # Cambia a tu interfaz de red
        console.print("[bold green]Internet reconectado exitosamente.[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Error al reconectar la red: {e}[/bold red]")

def save_report(runtime, target, total_requests, protocols):
   #guuard report
    with open("reporte.txt", "w") as f:
        f.write("Reporte de monitoreo de tráfico:\n")
        f.write(f"Tiempo de ejecución: {runtime:.2f} segundos\n")
        f.write(f"IP/Dominio objetivo: {target}\n")
        f.write(f"Total de peticiones generadas: {total_requests}\n")
        f.write(f"Protocolos utilizados: {', '.join(protocols)}\n")
    console.print("[bold green]Reporte guardado como reporte.txt[/bold green]")

def ask_reconnect(target):
    #preguntamos si reconectamos y si gen report
    response = console.input("[cyan]RECUERDA DETENER TUS ATAQUES LLEGASTE A UN TOTAL DE PETICIONES ALTO Y LOS DEL WAF TE VAN A REPORTAR\n\n¿Deseas reconectar la red? (y/n):[/cyan] ").strip().lower()
    if response == "y":
        reconnect_internet()
        report_response = console.input("[yellow]¿Deseas generar un reporte? (y/n):[/yellow] ").strip().lower()
        if report_response == "y":
            runtime = time.time() - start_time
            save_report(runtime, target, total_requests, protocols_used)
        console.print("[bold red]Terminando el programa.[/bold red]")
        exit()
    else:
        report_response = console.input("[yellow]¿Deseas generar un reporte? (y/n):[/yellow] ").strip().lower()
        if report_response == "y":
            runtime = time.time() - start_time
            save_report(runtime, target, total_requests, protocols_used)
        console.print("[bold red]Terminando el programa.[/bold red]")
        exit()

def main():
    global total_requests, current_minute_requests, start_time

    # Pedimos la IP o dominio objetivo y el límite de peticiones por minuto para que no nos regañen xD
    target = console.input("[cyan]BIENVENIDO AL EVITADOR DE PROBLEMAS\n\nIngresa la IP o dominio a auditar:[/cyan] ").strip()
    try:
        max_requests_per_minute = int(console.input("[yellow]¿Cuántas peticiones máximo por minuto deseas permitir?:[/yellow] ").strip())
    except ValueError:
        console.print("[bold red]Por favor, ingresa un numero válido para el límite de peticiones.[/bold red]")
        return

    console.print(f"[bold green]Iniciando monitoreo hacia {target} con un límite de {max_requests_per_minute} peticiones por minuto.\nsuerte en la cazeria RECUERDA EL CORREO A ENDPOINT[/bold green]\n")

    start_minute = time.time()

    # Captura
    try:
        sniff(filter=f"ip and dst host {target}", 
              prn=lambda pkt: process_packet(pkt, target, max_requests_per_minute, start_minute)[0],
              stop_filter=lambda pkt: process_packet(pkt, target, max_requests_per_minute, start_minute)[0])
    except KeyboardInterrupt:
        # Generamos el reporte cuando se interrumpe con Ctrl + C :3
        runtime = time.time() - start_time
        save_report(runtime, target, total_requests, protocols_used)

if __name__ == "__main__":
    main()
