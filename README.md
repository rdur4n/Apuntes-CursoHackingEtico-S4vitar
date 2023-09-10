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

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------
PENTESTING: 5 fases -> Reconocimiento inicial | Busqueda de versiones y exploits | Explotación | Obtención de resultados | Documento ejecutivo y técnico (Auditorias)


FASE DE RECONOCIMIENTO INICIAL - ENUMERACIÓN DE PUERTOS CON NMAP

-ping -c 1 10.0.2.2 -> Envia una trama ICMP a la dirección IP que pongamos (el gateway del router en mi caso). Podemos observar que si el TTL esta cerca de 64, estamos
ante una maquina linux y, por otro lado, si esta cerca de 128 nos estará responiendo una maquina windows.
-nmap 10.0.2.2 -p- --open -T5 -v -n -oG allPorts -> La herramienta nmap nos permite escanear los puertos de una máquina objetivo. Con el argumento '-p-' le marcamos
que queremos escanear los 65535 puertos. El argumento --open lo utilizamos para que nos indique solamente los puertos abiertos. -T sirve para marcar el grado de 
agresividad (cuanto más alto más agresivo y rapido hará el escaneo). Ponemos -v para el verbose y conforme vaya encontrando puertos nos los vaya mostrando sin esperar
a la finalización del escaneo completo. El -n para marcar que no queremos hacer resolución DNS ya que es muy costosa en tiempo. Y por último, lo exportamos en formato 
grepable a un fichero llamado allPorts. 
