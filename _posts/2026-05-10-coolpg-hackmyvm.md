---
title: "CooLPg HackMyVm - Writeup"
date: 2026-05-10 12:00:00 -0400
categories: [Writeups, HackMyVm]
tags: [web, SQLinjection, sudo-Misconfiguration]
image:
  path: /assets/img/CooLPg-img/coolpg.png
  alt: "CooLpg banner"
---

En esta publicación se relatará cómo se resolvió la máquina CooLPg de la plataforma HackMyVM.

| Autor | Dificultad | Sistema operativo | Plataforma | 
|-------|------------|-------------------|------------|
| cool | Fácil | Linux | HackMyVm |

# Resumen ejecutivo
La máquina **CooLPg** expone dos servicios: **SSH** y **HTTP** (nginx), siendo este último el punto de entrada. Al acceder al sitio se identifica un panel de login con un nombre de dominio asociado; tras añadirlo al `/etc/hosts` se descubren nuevas rutas mediante **fuzzing de directorios**, entre ellas un panel `/panel` con funcionalidad de búsqueda de usuarios. Aprovechando que el término buscado se refleja directamente en la URL, se realiza un ataque de enumeración con **`ffuf`** que revela dos usuarios válidos: `admin` y `cool`. Al no prosperar la fuerza bruta sobre el login, se analiza más detenidamente el panel de búsqueda, detectando que es vulnerable a una **SQL Injection blind boolean-based**. Mediante **`sqlmap`** se vuelca la base de datos y se obtienen credenciales SSH almacenadas en texto plano (`cool:ThisIsMyPGMyAdmin`), logrando así acceso inicial al sistema. Durante la post-explotación se identifica un script ejecutable como `root` sin contraseña vía `sudo`, cuya lógica consiste en buscar archivos `.log` dentro del directorio del usuario y, al encontrarlos, lanzar una **bash**; dado que el archivo `debug.log` ya existe en el directorio, ejecutar el script con `sudo` otorga directamente una shell como `root`. Por estas razones la máquina está catalogada con un nivel de dificultad **fácil**.

---

## Hosts discovery (descubrimiento de hosts)

![](/assets/img/CooLPg-img/1.png)

---

## Enumeración

```bash
# Nmap 7.98 scan initiated Fri Apr 17 22:12:30 2026 as: /usr/lib/nmap/nmap -p 22,80 -sCV -sS -Pn -vvv -oN nmap.txt -oX nmap.xml 192.168.0.169
Nmap scan report for coolpgi (192.168.0.169)
Host is up, received arp-response (0.00023s latency).
Scanned at 2026-04-17 22:12:30 -04 for 6s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 10.0p2 Debian 7 (protocol 2.0)
80/tcp open  http    syn-ack ttl 64 nginx
| http-methods: 
|_  Supported Methods: GET OPTIONS HEAD
|_http-title: CoolPG Internal
MAC Address: 08:00:27:81:5E:CB (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Apr 17 22:12:36 2026 -- 1 IP address (1 host up) scanned in 6.77 seconds
```

| Vector | Servicio (Puerto) | Estado  | Qué permite                            | Qué intentar        | Notas |
| ------ | ----------------- | ------- | -------------------------------------- | ------------------- | ----- |
| 1      | ssh (22)          | Abierto | Acceso autenticado a la máquina        | Buscar credenciales |       |
| 2      | http (80)         | Abierto | Gran abanico de vulnerabilidades web   |                     |       |

### HTTP

Al dirigirme a la página expuesta en el puerto 80 veo un panel de login en el que podemos ver un nombre de dominio:

![panel de login](/assets/img/CooLPg-img/2.png)

Previo a añadir el dominio hice una enumeración de directorios en la que no encontré nada más aparte de login, pero luego de añadir el dominio descubrí los siguientes archivos:

![](/assets/img/CooLPg-img/3.png)

Esto es interesante, tenemos un archivo `/panel` que nos permite buscar usuarios:

![](/assets/img/CooLPg-img/4.png)

Al momento de darle a search podemos ver lo siguiente en la URL:

![](/assets/img/CooLPg-img/5.png)

Con esto en cuenta podemos hacer un ataque de fuerza bruta con `ffuf` para buscar usuarios válidos.
Para hacer el ataque algo más completo vamos a filtrar por respuestas que no contengan el texto `No results`, este es el mensaje que arroja cuando no hay un usuario con el nombre que se indica:

![](/assets/img/CooLPg-img/6.png)

Así fue como conseguí 2 usuarios, `admin` y `cool`.

Luego de conseguir esto intenté hacer fuerza bruta en el panel de login usando `ffuf` con el siguiente comando:

```bash
❯ ffuf -u "http://coolpgi.hmv/login" -X POST -d "username=cool&password=FUZZ" -w /usr/share/wordlists/rockyou.txt -t 250 -fc 401
```

Pero no funcionó con ninguno de los 2 usuarios, así que me puse a revisar otra vez la página.

---

## Explotación

Es así como veo que el panel de search muestra un texto `Query:`:

![](/assets/img/CooLPg-img/7.png)

Por lo que me da por intentar con una SQL Injection (SQLI). Para esto usé `sqlmap`, que mostró que era vulnerable a una `blind boolean-based`:

![](/assets/img/CooLPg-img/8.png)

Ya con esto podemos proceder a volcar información sensible de las bases de datos.
Es así como conseguimos los usuarios y contraseñas de la página y las credenciales `cool:ThisIsMyPGMyAdmin` para SSH:

```
Database: public
Table: secrets
[2 entries]
+----+----------+-------------------+
| id | name     | value             |
+----+----------+-------------------+
| 1  | ssh_user | cool              |
| 2  | ssh_pass | ThisIsMyPGMyAdmin |
+----+----------+-------------------+
```

![](/assets/img/CooLPg-img/9.png)

---

## Post Explotación

En el directorio del usuario `cool` encontramos la primera flag y un archivo `debug.log` que está vacío:

![](/assets/img/CooLPg-img/10.png)

Al hacer un `sudo -l` encontramos un archivo el cual podemos ejecutar como sudo sin proporcionar contraseña:

![](/assets/img/CooLPg-img/11.png)

Este contiene lo siguiente:

```bash
#!/bin/sh
exec /usr/bin/find /home/cool -maxdepth 3 -type f -name "*.log" -exec /bin/bash \; -quit
```

Este script hace lo siguiente:
- `exec /usr/bin/find /home/cool -maxdepth 3 -type f -name "*.log"` — busca archivos con extensión `.log`
- `-exec /bin/bash \; -quit` — al encontrarlos ejecuta una bash

---

## Escalada de privilegios

Con esto en cuenta la escalada es fácil, solo hay que ejecutar el script usando `sudo` al comienzo, para que al encontrar el `debug.log` ejecute una bash como `root`. Máquina pwneada.

![](/assets/img/CooLPg-img/12.png)
