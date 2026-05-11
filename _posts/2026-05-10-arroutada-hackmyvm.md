---
title: "Arroutada - HackMyVm"
date: 2026-03-06 23:00:00 -0400
categories: [Writeups, HackMyVm]
tags: [web, stego, fuzzing, hash, rce, portforwarding]
img_path: /assets/img/arroutada-img/
---

En esta publicación se relatará cómo se resolvió la máquina Arroutada de la plataforma HackMyVM, una máquina que combina esteganografía, análisis de archivos ofuscados y múltiples instancias de RCE para obtener acceso, finalizando con una escalada de privilegios abusando de xargs con permisos sudo.

### Información General
- **IP:** `192.168.0.144`
- **Hostname:** `arroutada`
---
 
## Writeup
 
---
 
### Hosts Discovery (Descubrimiento de hosts)
 
![](/assets/img/Arroutada-img/20260306232319.png)
 
---
 
### Enumeración
 
```bash
# Nmap 7.95 scan initiated Fri Mar  6 23:25:04 2026 as: /usr/lib/nmap/nmap -p 80 -sCV -sS -Pn -vvv -oN nmap.txt -oX nmap.xml 192.168.0.144
Nmap scan report for arroutada (192.168.0.144)
Host is up, received arp-response (0.00023s latency).
Scanned at 2026-03-06 23:25:05 -03 for 6s
 
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.54 ((Debian))
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: Site doesn't have a title (text/html).
| http-methods:
|_  Supported Methods: OPTIONS HEAD GET POST
MAC Address: 08:00:27:58:13:94 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
 
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Mar  6 23:25:11 2026 -- 1 IP address (1 host up) scanned in 6.80 seconds
```
 
| Vector | Servicio (Puerto) | Estado  | Qué permite                          | Qué intentar | Notas |
| ------ | ----------------- | ------- | ------------------------------------ | ------------ | ----- |
| 1      | `http` (80)       | Abierto | Gran abanico de vulnerabilidades web |              |       |
 
#### HTTP
 
En esta máquina por el momento solo hay un puerto abierto, es decir, un único vector de ataque: **HTTP**.
 
Al entrar a la página encontramos solo una imagen, sin nada relevante en el código fuente, así que procedemos con las siguientes acciones:
 
- Descargar la imagen y analizarla en busca de datos ocultos (**esteganografía**)
- Hacer **fuzzing** en busca de directorios
![](/assets/img/Arroutada-img/20260306232811.png)
 
Al analizar la imagen encontramos un directorio:
 
![](/assets/img/Arroutada-img/20260306233229.png)
 
A la par, la enumeración de directorios arroja el mismo resultado:
 
![](/assets/img/Arroutada-img/20260306233349.png)
 
Ahora tenemos una pista: un **path** de destino, pero con un segmento intermedio desconocido:
 
![](/assets/img/Arroutada-img/20260306233416.png)
 
Usando **`ffuf`**, se logra descubrir el directorio faltante:
 
```bash
# Comando ffuf
ffuf -u "http://192.168.0.144/scout/FUZZ/docs/" \
     -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-big.txt \
     -c
 
# Directorio descubierto
j2    [Status: 200, Size: 189767, Words: 15060, Lines: 1017, Duration: 403ms]
```
 
![](/assets/img/Arroutada-img/20260306234117.png)
 
Contenido encontrado en el directorio:
 
![](/assets/img/Arroutada-img/20260306234148.png)
 
![](/assets/img/Arroutada-img/20260306234209.png)
 
![](/assets/img/Arroutada-img/20260306234254.png)
 
![](/assets/img/Arroutada-img/20260307000638.png)
 
Ninguno de los elementos encontrados funciona como contraseña. Al intentar usar **`office2john`** se obtuvo el siguiente error:
 
![](/assets/img/Arroutada-img/20260307000723.png)
 
Se procedió a verificar el archivo con **`binwalk`**:
 
![](/assets/img/Arroutada-img/20260307000821.png)
 
> **Nota:** `binwalk` revela que el archivo es en realidad un **`.zip`**. Al extraerlo no se obtiene nada útil directamente, así que continuamos con la extracción del hash para crackearlo.
 
Extracción del hash:
 
![](/assets/img/Arroutada-img/20260307002743.png)
 
Contraseña crackeada exitosamente:
 
![](/assets/img/Arroutada-img/20260307003103.png)
 
Con la contraseña se accede al archivo y se obtiene la siguiente información:
 
![](/assets/img/Arroutada-img/20260307003202.png)
 
Se realiza **fuzzing** sobre `thejabasshel.php` en busca de parámetros. Se encontró el parámetro `a`, pero su respuesta era la siguiente:
 
![](/assets/img/Arroutada-img/20260307013845.png)
 
Luego de probar algunas cosas rápidas con el parámetro `b`, el fuzzing revela lo siguiente:
 
![](/assets/img/Arroutada-img/20260307013723.png)
 
> Inicialmente se confundió `pass.txt` con algún tipo de mecanismo de login, pero revisando la documentación se confirmó que el parámetro **`a`** corresponde al **comando** y el parámetro **`b`** a la **contraseña**.
 
Esto nos otorga una **RCE (Remote Code Execution)**:
 
![](/assets/img/Arroutada-img/20260307014104.png)
 
---
 
### Explotación
 
Con la **RCE** confirmada, se envía una **reverse shell** hacia la máquina atacante para operar con mayor comodidad:
 
![](/assets/img/Arroutada-img/20260307014810.png)
 
---
 
### Post-Explotación
 
Después de enumerar el sistema, se encuentra el siguiente servicio:
 
![](/assets/img/Arroutada-img/20260307220338.png)
 
> **Problema:** El servicio solo está disponible de forma local en la máquina víctima, por lo que se requiere hacer **Port Forwarding**. Para esto se utilizará **`chisel`**.
 
Primero se identifica la arquitectura del sistema víctima para descargar la versión correcta de `chisel`:
 
![](/assets/img/Arroutada-img/20260307220703.png)
 
La arquitectura es **`amd64`**, así que se descarga la versión correspondiente:
 
![](/assets/img/Arroutada-img/20260307220801.png)
 
Con el **Port Forwarding** establecido, se descubre una cadena en **Brainfuck**:
 
![](/assets/img/Arroutada-img/20260307220841.png)
 
> **Mensaje decodificado:** `all HackMyVM hackers!!`
 
Código fuente del servicio:
 
![](/assets/img/Arroutada-img/20260307221559.png)
 
Al revisar el archivo se identifica que devuelve un script en **PHP**. Analizando su lógica, se determina que:
 
1. Lee el **JSON del cuerpo del request** (`request body`).
2. Lo convierte a un array en **PHP**.
3. Verifica si existe la clave **`command`**.
4. Si existe → ejecuta el comando mediante `system()`.
5. Si no existe → muestra un error.
Esto expone otra **RCE** mediante una petición `POST` con cuerpo en formato **JSON**:
 
![](/assets/img/Arroutada-img/20260308185137.png)
 
![](/assets/img/Arroutada-img/20260308185539.png)
 
Se obtiene una **RCE** como el usuario `drito`. Con esto se puede establecer una nueva shell interactiva:
 
![](/assets/img/Arroutada-img/20260308185933.png)
 
---
 
### Escalada de Privilegios
 
La escalada es bastante directa: el usuario tiene permitido ejecutar **`xargs`** como `root` sin contraseña mediante `sudo`:
 
![](/assets/img/Arroutada-img/20260308191602.png)
 
![](/assets/img/Arroutada-img/20260308191704.png)
