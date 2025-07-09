# 🕵️‍♂️ Apuntes de Ciberseguridad 💻

¡Bienvenido a mi espacio dedicado a la ciberseguridad!  
Aquí encontrarás apuntes, análisis y reflexiones sobre el apasionante (y desafiante) mundo de la seguridad informática. 🔐🦠

---

## ⚠️ Aviso Legal

Estos apuntes son únicamente para fines educativos y de referencia.  
No me hago responsable del uso indebido de la información contenida.

**Recuerda:** con gran poder viene una gran responsabilidad.  
Actúa siempre con ética y respeto en el ciberespacio. ⚡️

---

## 📚 ¿Qué encontrarás en este repositorio?

Recursos prácticos para hackers éticos y entusiastas de la seguridad, organizados para facilitar tu aprendizaje y consulta.

---

## 📑 Índice

- [Linux: comandos útiles](#linux-comandos-útiles)  
- [Comunicación: protocolos y herramientas](#comunicación-protocolos-y-herramientas)  
- [Puertos comunes](#puertos-comunes)  
- [Herramientas online](#herramientas-online-para-análisis)  
- [Buenas prácticas de seguridad](#buenas-prácticas-de-seguridad)  
- [Glosario](#glosario)


---

## 🖥️ Linux: comandos útiles

### 📁 Navegación y manejo de archivos

| Comando                         | Descripción                                                      |
|--------------------------------|------------------------------------------------------------------|
| `pwd`                          | Muestra la ruta absoluta del directorio actual.                  |
| `ls -lah`                      | Lista archivos (incluso ocultos) con detalles y tamaño legible.  |
| `ll`                           | Alias común para `ls -l` (listado detallado).                    |
| `cd ~/Music/`                  | Cambia al directorio `Music` del usuario.                        |
| `cd ./ruta`                    | Entra a una ruta relativa desde el directorio actual.            |
| `mkdir Scripts`                | Crea una carpeta llamada `Scripts`.                              |
| `rmdir ~/Scripts`              | Elimina la carpeta `Scripts` si está vacía.                      |
| `touch archivo.txt`            | Crea un archivo vacío llamado `archivo.txt`.                     |
| `echo "Hola" > data.txt`       | Crea o reemplaza `data.txt` con el texto "Hola".                |
| `cp -a Music/ Documents/`      | Copia la carpeta `Music` a `Documents` con atributos.            |
| `rsync -av origen/ destino/`   | Sincroniza carpetas sin duplicar archivos existentes.            |
| `mv archivo.txt nuevo.txt`     | Renombra `archivo.txt` a `nuevo.txt`.                            |
| `mv archivo.txt destino/`      | Mueve `archivo.txt` al directorio `destino/`.                    |
| `rm -i archivo.txt`            | Pide confirmación antes de eliminar `archivo.txt`.               |
| `rm -rf carpeta/`              | Borra `carpeta` y todo su contenido sin pedir confirmación ⚠️.   |
| `stat archivo.txt`             | Muestra metadatos detallados del archivo.                        |
| `file archivo.txt`             | Muestra el tipo de contenido del archivo.                        |
| `basename /ruta/archivo.txt`   | Extrae el nombre del archivo sin la ruta.                        |
| `dirname /ruta/archivo.txt`    | Extrae el directorio de la ruta del archivo.                     |

### 🔐 Permisos y usuarios

| Comando                       | Descripción                                         |
|------------------------------|-----------------------------------------------------|
| `chmod 777 archivo.txt`       | Da permisos totales a todos (⚠️ muy inseguro).      |
| `chmod +x script.sh`          | Da permiso de ejecución al script.                   |
| `chmod -R 755 carpeta/`       | Da permisos lectura/ejecución recursivos a carpeta. |
| `chown usuario:grupo archivo` | Cambia propietario y grupo de un archivo.           |
| `adduser John`                | Crea un nuevo usuario llamado John.                  |
| `sudo -l`                    | Muestra qué comandos puede ejecutar con sudo.        |
| `whoami`                     | Muestra el usuario actual conectado.                 |

### 🔎 Búsqueda

| Comando                       | Descripción                                         |
|------------------------------|-----------------------------------------------------|
| `locate bash`                 | Busca archivos relacionados con "bash" (requiere actualizar base). |
| `updatedb`                   | Actualiza la base de datos usada por `locate`.       |
| `find / -name archivo.txt`    | Busca archivo por nombre desde la raíz.             |
| `grep "texto" archivo.txt`    | Busca texto dentro de un archivo.                    |
| `cut -d':' -f1 /etc/passwd`   | Extrae campos (ej. nombres de usuario) de archivos delimitados. |
| `xargs`                      | Ejecuta comandos usando salida de otro comando.     |

### ⚙️ Variables y entorno

| Comando                      | Descripción                                         |
|-----------------------------|-----------------------------------------------------|
| `echo $PATH`                | Muestra rutas donde busca comandos el sistema.      |
| `env`                       | Muestra variables de entorno activas.                |
| `export VAR=valor`          | Crea o modifica una variable temporal.               |

### 📑 Procesamiento de texto y logs

| Comando                      | Descripción                                         |
|-----------------------------|-----------------------------------------------------|
| `head -n 10 archivo.txt`    | Muestra las primeras 10 líneas de un archivo.       |
| `tail -n 10 archivo.txt`    | Muestra las últimas 10 líneas de un archivo.        |
| `tail -f archivo.log`       | Muestra en tiempo real las nuevas líneas del log.   |
| `diff archivo1 archivo2`    | Compara línea a línea dos archivos.                  |
| `tr 'a-z' 'A-Z'`            | Convierte texto a mayúsculas.                        |

### 🕒 Programación de tareas

| Comando                      | Descripción                                         |
|-----------------------------|-----------------------------------------------------|
| `crontab -e`                | Edita tareas programadas periódicas del usuario.    |
| `at 12:00`                  | Programa una tarea única para una hora específica.  |

### 📊 Procesos

| Comando                      | Descripción                                         |
|-----------------------------|-----------------------------------------------------|
| `top`                       | Muestra procesos activos en tiempo real.            |
| `htop`                      | Interfaz avanzada para ver procesos (si instalado). |
| `ps aux`                    | Lista todos los procesos en ejecución.               |
| `kill -9 PID`               | Termina un proceso con ID específico.                |
| `history`                   | Muestra historial de comandos ejecutados.            |

### 🌐 Red

| Comando                      | Descripción                                         |
|-----------------------------|-----------------------------------------------------|
| `ifconfig`                  | Configura interfaces de red (obsoleto).              |
| `ip a`                      | Alternativa moderna a `ifconfig`.                    |
| `iwconfig`                  | Configura interfaces inalámbricas.                    |
| `netstat -pbtona`           | Muestra conexiones y puertos abiertos con procesos. |
| `ss -tuln`                  | Alternativa moderna a `netstat`.                      |
| `ping 8.8.8.8`              | Verifica conexión a Internet.                         |
| `arp -a`                    | Muestra tabla ARP (IP-MAC).                           |
| `route`                     | Muestra tabla de rutas IP.                            |
| `scp archivo usuario@IP:/ruta` | Copia archivo a otra máquina por SSH.             |
| `lsof -i`                   | Lista conexiones de red activas.                      |

### 💽 Disco y sistema

| Comando                      | Descripción                                         |
|-----------------------------|-----------------------------------------------------|
| `df -h`                     | Muestra uso del disco en formato legible.            |
| `du -sh /var/lib/*`         | Muestra tamaño de subdirectorios.                     |
| `lsblk`                     | Lista dispositivos de almacenamiento conectados.    |
| `mount`                     | Muestra sistemas montados.                            |
| `umount /dev/sdX`           | Desmonta dispositivo.                                 |
| `uptime`                    | Tiempo que lleva encendido el sistema.                |
| `uname -a`                  | Información del kernel y sistema.                      |
| `date`                      | Muestra fecha y hora actuales.                         |
| `reboot`                    | Reinicia el sistema.                                   |
| `shutdown now`              | Apaga el sistema inmediatamente.                       |

### 🛠️ Archivos comprimidos

| Comando                      | Descripción                                         |
|-----------------------------|-----------------------------------------------------|
| `tar -czvf archivo.tar.gz carpeta/` | Comprime carpeta en archivo .tar.gz.           |
| `tar -xzvf archivo.tar.gz`   | Descomprime archivo .tar.gz.                          |
| `zip archivo.zip archivo.txt` | Comprime archivo en formato .zip.                  |
| `unzip archivo.zip`          | Extrae archivos de un zip.                            |

### 🛡️ Seguridad y análisis

| Comando                      | Descripción                                         |
|-----------------------------|-----------------------------------------------------|
| `history | grep passwd`      | Busca comandos relacionados con "passwd" en historial. |
| `find / -perm -4000 2>/dev/null` | Busca archivos con bit SUID (riesgos potenciales). |
| `netstat -tulnp | grep LISTEN` | Muestra puertos abiertos y en escucha.            |
| `ls -alh /home/*/.ssh/`      | Revisa llaves SSH de todos los usuarios.             |
| `chkrootkit`                 | Escáner básico para detectar rootkits (si instalado). |

---

## 🌐 Comunicación: protocolos y herramientas

Protocolos esenciales: TCP/IP, UDP, HTTP/HTTPS, FTP, SMTP, DNS.  
Protocolos seguros: TLS/SSL, SSH, VPNs.  
Herramientas destacadas: Wireshark, tcpdump, nmap.

Ejemplos prácticos:

```bash
sudo tcpdump -i eth0 port 443          # Captura tráfico HTTPS
nmap -sS -p 1-1000 192.168.1.10       # Escaneo de puertos
```
## 🧰 Comandos y ejemplos prácticos para análisis

```bash
# Buscar en logs mensajes de error
grep -i "error" /var/log/syslog

# Mostrar últimas 50 líneas de un archivo de log
tail -n 50 /var/log/auth.log

# Filtrar procesos por nombre
ps aux | grep sshd

# Mostrar conexiones de red activas
ss -tuln

# Ver permisos y propietario de un archivo
ls -l /etc/passwd
```

## 🔌 Puertos comunes

Estos son los puertos más usados en redes y sistemas. Conocerlos es fundamental para entender qué servicios están activos, sus riesgos asociados y cómo protegerlos. Muchos ataques apuntan a estos puertos, por eso es clave monitorearlos y asegurar su configuración.

| Puerto(s)  | Protocolo | Servicio    | Descripción y Riesgos                         |
|------------|-----------|-------------|----------------------------------------------|
| 20, 21     | TCP       | FTP         | Transferencia sin cifrado, riesgo MITM       |
| 22         | TCP       | SSH         | Acceso remoto seguro                          |
| 23         | TCP       | Telnet      | Sin cifrado, no recomendado                   |
| 25         | TCP       | SMTP        | Envío de correo, riesgo spam y spoofing      |
| 53         | TCP/UDP   | DNS         | Vulnerable a ataques DDoS y spoofing          |
| 67, 68     | UDP       | DHCP        | Riesgo spoofing en asignación IP              |
| 69         | UDP       | TFTP        | Transferencia simple, no seguro               |
| 80         | TCP       | HTTP        | Tráfico sin cifrado                           |
| 110        | TCP       | POP3        | Recepción sin cifrado                         |
| 123        | UDP       | NTP         | Usado para sincronización y amplificación DDoS|
| 143        | TCP       | IMAP        | Gestión remota correo, mejor que POP3         |
| 161, 162   | UDP       | SNMP        | Gestión de red, versiones inseguras           |
| 443        | TCP       | HTTPS       | HTTP seguro con TLS                           |
| 445        | TCP       | SMB         | Compartición Windows, vulnerable ransomware   |
| 3389       | TCP       | RDP         | Escritorio remoto, objetivo común ataques     |
| 5900       | TCP       | VNC         | Control remoto, requiere seguridad adicional  |
| 8080       | TCP       | HTTP alt    | Proxies o servicios web alternativos          |
| 3306       | TCP       | MySQL       | Base de datos, proteger con firewall          |
| 5432       | TCP       | PostgreSQL  | Base de datos, mismo cuidado que MySQL        |


---

## 🛠️ Herramientas online para análisis

Estas herramientas son esenciales para la investigación y análisis en ciberseguridad. Permiten detectar malware, analizar tráfico sospechoso, consultar reputación de IPs o dominios y explorar amenazas. Son recursos clave para analistas, pentesters y equipos de respuesta ante incidentes.

| Herramienta            | Enlace                                                | Descripción                                                                                      |
|-----------------------|------------------------------------------------------|------------------------------------------------------------------------------------------------|
| VirusTotal            | [virustotal.com](https://www.virustotal.com)         | Escanea archivos y URLs con múltiples motores antivirus para detectar amenazas.                |
| urlscan.io            | [urlscan.io](https://urlscan.io)                      | Analiza el comportamiento y contenido de URLs para detectar phishing o malware.                |
| AbuseIPDB             | [abuseipdb.com](https://www.abuseipdb.com)            | Base colaborativa para reportar y consultar IPs maliciosas.                                    |
| IPVoid                | [ipvoid.com](https://www.ipvoid.com)                  | Evalúa la reputación de IPs y detecta si están en listas negras.                               |
| Talos Intelligence    | [talosintelligence.com](https://talosintelligence.com) | Proporciona inteligencia sobre amenazas y reputación de IPs y dominios.                        |
| Shodan                | [shodan.io](https://www.shodan.io)                    | Motor de búsqueda para dispositivos conectados a Internet y detección de vulnerabilidades.    |
| Censys                | [censys.io](https://www.censys.io)                    | Escanea infraestructura pública y certificados SSL para detectar riesgos.                      |
| IP Quality Score      | [ipqualityscore.com](https://www.ipqualityscore.com)  | Evalúa el riesgo de IPs, correos y dispositivos para prevenir fraudes.                         |
| Whois Domain Tools    | [domaintools.com](https://www.domaintools.com)        | Consulta datos de registro y propiedad de dominios.                                           |
| AnyRun                | [any.run](https://any.run)                             | Plataforma interactiva para análisis dinámico de malware en tiempo real.                       |
| Hybrid Analysis       | [hybrid-analysis.com](https://www.hybrid-analysis.com) | Sandbox automatizado que genera reportes detallados de malware.                               |
| Cuckoo                | [cuckoosandbox.org](https://www.cuckoosandbox.org)    | Herramienta open source para análisis automatizado de malware en entornos seguros.            |
| MalwareBazaar         | [bazaar.abuse.ch](https://bazaar.abuse.ch)            | Repositorio público de muestras de malware para investigación.                                |
| ThreatCrowd           | [threatcrowd.org](https://www.threatcrowd.org)        | Relaciona IPs, dominios, hashes y emails maliciosos para análisis de amenazas.                 |
| CIRCL Passive DNS     | [circl.lu](https://www.circl.lu)                       | Consulta histórica de resoluciones DNS para seguimiento y análisis.                            |
| FireEye Threat Intel  | [fireeye.com](https://www.fireeye.com)                 | Informes y datos sobre amenazas avanzadas y ataques dirigidos.                                |
| VirusTotal Intelligence | [virustotal.com/intelligence](https://www.virustotal.com/intelligence) | Versión avanzada para análisis masivo y detección de patrones de amenazas.                     |
| MITRE ATT&CK Navigator | [attack.mitre.org](https://attack.mitre.org)          | Framework que mapea tácticas y técnicas usadas por atacantes para mejorar defensas y detección.|

---

## 🛡️ Buenas prácticas de seguridad

- Mantén el sistema y aplicaciones actualizados regularmente.  
- Usa usuarios con privilegios mínimos para tareas diarias.  
- Evita permisos 777 en archivos o carpetas críticos.  
- Usa firewalls para restringir accesos no autorizados.  
- Realiza backups periódicos y verifica su integridad.  
- Revisa logs y monitorea eventos sospechosos con herramientas adecuadas.

---
📚 Referencias y documentación
Nmap Documentation

Tcpdump Tutorial

Linux Command Cheat Sheet

🚀 ¿Quieres contribuir?
Si tienes trucos, correcciones o nuevos apuntes, ¡haz un pull request!
Aquí fomentamos la colaboración y el aprendizaje continuo. 🤘

💬 Contacto
¿Preguntas o colaboraciones?
Encuéntrame en GitHub y en mis redes sociales.

📜 Licencia
Este repositorio está bajo licencia MIT.

**Recuerda**: En el mundo de la ciberseguridad, el conocimiento es poder. ¡Así que mantente curioso y nunca dejes de aprender! 🔍✨
