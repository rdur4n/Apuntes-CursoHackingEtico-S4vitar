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
