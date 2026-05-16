---
title: "EL modelo OSI en un pentesting: Guía Teórica de pentesting"
date: 2026-05-16 01:00:00 -0400
categories: [Artículos, Redes, Modelos OSI]
tags: [Redes, guías, articulo]
pin: true
image:
  path: /assets/img/OSI/banner.png
  alt: "Modelo OSI banner"
---

En este articulo se buscara explicar de forma sencilla y practica todas las capas del modelo OSI de cara a un pentesting de ciberseguridad.

# **Que es el modelos OSI**

El Modelo OSI (Interconexión de Sistemas Abiertos) es un marco **conceptual** creado por la ISO en 1984. Estandariza la comunicación en red, dividiéndola en 7 capas jerárquicas. Esto permite que dispositivos y sistemas de diferentes fabricantes y arquitecturas se comuniquen universalmente.
Las capas son las siguientes:

![](/assets/img/OSI/Capas-modelo-OSI.png)

Estas capas se explican generalmente desde las capas superiores hacia las inferiores, pero para efectos prácticos de este articulo de explicaran de forma inversa.

# **Capas inferiores**

## Primera capa - Capa física

Esta primera capa del modelos OSI es el nivel mas bajo y fundamental. Se encarga de transmitir los datos binarios en bruto (ceros y unos) entre dispositivos, a través de medios físicos (cables, fibra óptica, aire), voltajes, conectores y las propiedades mecánicas y eléctricas para establecer la conexión.

Las **funciones principales** de esta capa son:
- **Transmisión de bits:** Convierte los datos en señales eléctricas (cobre), luz (fibra óptica) u ondas electromagnéticas (Wi-Fi).
- **Codificación y modulación:** Modifica las características de la señal (frecuencia, amplitud o fase) para representar los bits de datos.
- **Sincronización:** Mantiene alineados los relojes de los dispositivos transmisor y receptor para interpretar correctamente cada bit.

## Segunda capa - Capa de enlace de datos

La Segunda capa del modelo OSI (Capa de Enlace de Datos) se encarga de transferir información de forma fiable entre dispositivos conectados directamente en una misma red. Transforma los bits de la capa física en bloques llamados tramas, gestiona el direccionamiento físico (direcciones MAC) y controla el flujo del tráfico para evitar

### Subcapas principales

- **LLC (Control de Enlace Lógico):** Identifica el protocolo de la capa de red (Capa 3) y gestiona la verificación de errores.
- **MAC (Control de Acceso al Medio):** Controla cómo los dispositivos acceden físicamente a la red y utiliza las direcciones MAC de 48 bits para identificar cada tarjeta de red de forma única

Es en esta capa se puede acontecer el método de descubrimiento de host mediante **Paquetes ARP**. Funciona enviando mensajes de difusión (broadcast) preguntando qué dispositivo tiene una dirección IP específica; si el host está encendido, responderá revelando su dirección MAC.

![](/assets/img/OSI/what-is-arp.jpg)

## Tercera capa - Capa de red

Esta capa se encarga de determinar la mejor ruta para enviar datos (paquetes) entre redes diferentes. Utiliza direcciones lógicas como la IP para enrutar la información desde el origen hasta el destino final, incluso si ambos equipos están en redes distintas.

### Dispositivos y protocolos
- **Dispositivos clave:** Los **routers** (enrutadores) operan principalmente en esta capa para conectar diferentes redes. También existen switches multicapa que realizan esta función.
- **IP:** Protocolo de Internet, encargado del direccionamiento.
- **ICMP:** Protocolo de Mensajes de Control de Internet, usado para diagnósticos y reportes de error (como en el comando ping).
- **IPSec:** Protocolo para cifrar y asegurar las comunicaciones

En este capa de acontece el metodo de descubrimiento de hosts mediante paquetes **ICMP echo requets**. Esta funcionan enviando paquetes **ICMP echo requets** hacia un rango de IPs, si el de destino esta activo este responde con una paquete **ICMP echo reply**

![](/assets/img/OSI/icmp.png)

## Cuarta capa - Capa de transporte

La Capa 4 del Modelo OSI es la Capa de Transporte, responsable de la comunicación extremo a extremo entre aplicaciones, segmentación de datos, control de flujo y corrección de errores. Asegura que los datos lleguen de forma fiable y ordenada entre dispositivos mediante protocolos clave como TCP y UDP.

### Funciones Clave de la Capa de Transporte (Capa 4):

- **Segmentación y Reensamblaje:** Divide los datos recibidos de la capa de sesión (Capa 5) en trozos más pequeños llamados "segmentos" para enviarlos, y los reensambla en el destino.
- **Comunicación Extremo a Extremo:** Gestiona la conversación lógica entre las aplicaciones emisora y receptora, no solo entre dispositivos físicos.
- **Control de Flujo:** Gestiona la velocidad de transmisión para evitar que un emisor rápido sature a un receptor lento.
- **Control de Errores:** Garantiza la entrega sin errores, solicitando la retransmisión de datos si es necesario (principalmente TCP).
- **Direccionamiento de Puertos:** Utiliza números de puerto (0-65,535) para asegurar que los datos lleguen a la aplicación o servicio correcto.

### Protocolos principales
- **TCP (Transmission Control Protocol):** Orientado a conexión, fiable, garantiza la entrega y el orden de los segmentos.
- **UDP (User Datagram Protocol):** No orientado a conexión, rápido, sin garantía de entrega ni orden, ideal para streaming o juegos.

Es en esta capa en donde **nmap** realiza la mayor parte de su trabajo mediante el análisis de puertos, viéndose aquí escaneo como el **SYN TCP**

![](/assets/img/OSI/synscanning1.png)

# **Capas superiores**

## Quinta capa - Capa de sesión

La Capa 5 (Capa de Sesión) se encarga de establecer, gestionar, coordinar y finalizar las conversaciones (sesiones) entre aplicaciones en ambos extremos. A diferencia de la Capa 4 (Transporte), que solo se asegura de que los datos vayan de A a B mediante puertos TCP/UDP, la Capa 5 maneja la lógica de la conexión, el control del diálogo (quién habla y cuándo) y la recuperación en caso de interrupciones.

### Protocolos comunes

- **RPC (Remote Procedure Call):** Permite a un programa ejecutar código en otra máquina remota.
- **PPTP (Point-to-Point Tunneling Protocol):** Utilizado para crear redes privadas virtuales (VPNs).
- **NetBIOS:** Protocolo que facilita la comunicación entre equipos de una misma red local.

## Sexta capa - Capa de presentación

La sexta capa del modelo OSI es la capa de presentación. Funciona como el "traductor" de la red, encargándose de traducir, cifrar y comprimir los datos para que el sistema receptor pueda interpretarlos correctamente sin importar el software o hardware que utilice.

### Funciones principales
- **Traducción de formatos:** Asegura que los datos enviados por la aplicación de un equipo (ej. formato ASCII o Unicode) sean compatibles y legibles para la aplicación del equipo receptor.
- **Cifrado:** Protege la confidencialidad de los datos durante la transmisión (como en conexiones seguras SSL/TLS) codificándolos antes de enviarlos y decodificándolos al llegar.
- **Compresión:** Reduce el tamaño de los datos para disminuir el tiempo y el ancho de banda necesarios en la transferencia

En esta capa de procesan estándares como:
- **Imágenes:** JPEG, GIF, TIFF.
- **Texto y datos:** ASCII, EBCDIC, Unicode.
- **Sonido/Video:** MPEG, MIDI

## Séptima capa - Capa de aplicación

La capa de aplicación es el séptimo y más alto nivel del modelo OSI, sirviendo como interfaz directa entre las aplicaciones de usuario final (navegadores, clientes de correo) y la red. Define protocolos como HTTP, FTP y SMTP para intercambiar datos, gestionar la presentación y sincronizar la comunicación.

### Protocolos Comunes:
- **HTTP/HTTPS:** Navegación web.
- **SMTP, POP3, IMAP:** Envío y recepción de correo electrónico.
- **FTP/TFTP:** Transferencia de archivos.
- **DNS:** Resolución de nombres de dominio.
- **SSH/Telnet:** Acceso remoto.

En esta capa es donde se acontecen la parte de los ataques comunes como SQLI o XSS, conexiones por SSH y enumeración de archivos y directorios con ffuf o gobuster.