
import nmap # Libreria de escaneo de redes
import psutil #Libreria par obtener informacion del sistema
import re
import argparse #Libreria de Argumentos
import json # Librerira para manejo de archivos tipo json
import ipaddress
import requests # Libreria para realizar POST

def send_results(data):
    # Envía los resultados en formato JSON mediante una solicitud POST
    try:
        response = requests.post('http://127.0.0.1:5000/example/fake_url.php', json=data)
        if response.status_code == 200:
            print("Resultados enviados correctamente.")
        else:
            print("Error al enviar los resultados:", response.status_code)
    except requests.exceptions.RequestException as e:
        print("Error al enviar los resultados:", e)


def ip_addr(interface): #Obtención del direccionamiento de la interface
    
    ps_dat=str(psutil.net_if_addrs()[interface][1])

    direccion_ip = re.search(r"address='(\d+\.\d+\.\d+\.\d+)'", ps_dat).group(1)
    mascara_red = re.search(r"netmask='(\d+\.\d+\.\d+\.\d+)'", ps_dat).group(1)

    #   Convertimos la dirección IP y la máscara de red a objetos ipaddress.IPv4Address
    direccion_ip_obj = ipaddress.IPv4Address(direccion_ip)
    mascara_red_obj = ipaddress.IPv4Address(mascara_red)

    # Calculamos la dirección de red utilizando la dirección IP y la máscara de red
    network = ipaddress.IPv4Network(str(direccion_ip_obj) + '/' + str(mascara_red_obj), strict=False)
    
    
    if network:
        # Si se encontró, devolvemos el network
        return str(network)
    else:
        print("No se encontró ninguna dirección IP en la cadena.")
        return
        
   

def scanner(arg): #El escaner propiamente dicho
    
    nmp = nmap.PortScanner() #Creamos la instancia
    
    nmp.scan(ip_addr(arg), arguments='-O') # Realizamos el escaneo y llamamos a la función ip_addr
    
    print('%s' % ip_addr(arg)) # Imprimimos la IP
       
    for host in nmp.all_hosts(): # Itermaos por cada ip detectada
        
        if nmp[host].state() == 'up':  # Comprobamos si la ip esta UP 
                             
            if len(nmp[host]['osmatch'])> 0:   # Comprobamos si obtuvimos el nombre de S.O. 
                
                print('----------------------------------------------------\n')
                
                print('Host : %s\t\n' % (host)) # Mostramos IP
                     
                print('OS Info: %s\n' % (nmp[host]['osmatch'][0]['name'])) # Mostramos os info
              
            for proto in nmp[host].all_protocols():
                
                print('====================================\n')
                
                print('Protocol : %s \n' % proto) # Mostrmoas el protocolo

                lport = nmp[host][proto].keys()
            
                for port in lport: # Itermamos por cada puerto
                    
                    if nmp[host][proto][port]['state'] == 'open': # Comprobaos si el puerto está abierto
                        
                        print ('\tport : %s \tservice: %s\n' % (port, nmp[host][proto][port]['name'])) # Mostramos la información de puertos

if __name__ == "__main__": # Función main
    
    parser = argparse.ArgumentParser(description='Descubre IP de la red en una interfaz específica y envía los resultados mediante POST.')
    
    parser.add_argument('-i', '--interface', type=str, help='Interfaz de red', required=True)
    
    args = parser.parse_args() # Capturamos los argumentos ingresados por consola
    
    scanner_results=scanner(args.interface) #Llamamos a la función scanner
    
    json_data = json.dumps(scanner_results, indent=4)
    
    send_results(json_data)

    
    