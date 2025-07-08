# 🕵️‍♂️ Apuntes de Ciberseguridad 💻

¡Bienvenido a mi espacio dedicado a la ciberseguridad!  
Aquí encontrarás apuntes, análisis y reflexiones sobre el apasionante (y desafiante) mundo de la seguridad informática. 🔐🦠

---

##⚠️ Aviso Legal

Estos apuntes son únicamente para fines educativos y de referencia.  
No me hago responsable por el uso indebido de la información contenida.

**Recuerda:** con gran poder viene una gran responsabilidad.  
Actúa siempre con ética y respeto en el ciberespacio. ⚡️

---

##📚 ¿Qué encontrarás en este repositorio?

Recursos prácticos para hackers éticos y entusiastas de la seguridad, organizados para facilitar tu aprendizaje y consulta.

##📂 Estructura general

- **Linux:** comandos esenciales para terminal y administración segura.  
- **Comunicación:** protocolos, herramientas y mejores prácticas.  
- **Write-ups:** análisis y casos prácticos de vulnerabilidades.  
- **Puertos comunes:** tabla con servicios, riesgos y protocolos.  
- **Herramientas online:** recursos para análisis y detección.

---

##🖥️ Linux: comandos útiles
###📁 Navegación y manejo de archivos
pwd                         / Muestra la ruta del directorio actual
ls -lah                     / Lista archivos, incluso ocultos, en formato legible
ll                          / Alias común de 'ls -l'
cd ~/Music/                 / Entra a la carpeta Music del usuario actual
cd ./ruta                   / Entra a una ruta relativa
mkdir Scripts               / Crea carpeta llamada Scripts
rmdir ~/Scripts             / Elimina carpeta vacía en home
touch archivo.txt           / Crea un archivo vacío
echo "Hola" > data.txt      / Crea o sobreescribe archivo con texto
cp -a Music/ Documents/     / Copia carpetas recursivamente con atributos
rsync -av origen/ destino/  / Sincroniza carpetas copiando solo lo necesario
mv archivo.txt nuevo.txt    / Renombra un archivo
mv archivo.txt destino/     / Mueve archivo a otra carpeta
rm -i archivo.txt           / Elimina archivo con confirmación
rm -rf carpeta/             / Elimina carpeta y contenido sin preguntar ⚠️
stat archivo.txt            / Muestra info detallada de archivo
file archivo.txt            / Indica tipo de archivo (texto, binario, etc.)
basename /ruta/archivo.txt  / Extrae nombre de archivo
dirname /ruta/archivo.txt   / Extrae nombre del directorio

###🔐 Permisos y usuarios
chmod 777 archivo.txt       / Da permisos totales a todos (⚠️ muy inseguro)
chmod +x script.sh          / Da permisos de ejecución
chmod -R 755 carpeta/       / Permisos recursivos lectura/ejecución
chown usuario:grupo archivo / Cambia propietario de archivo
adduser John                / Crea nuevo usuario
sudo -l                     / Muestra privilegios del usuario con sudo
whoami                      / Muestra usuario actual

###🔎 Búsqueda
locate bash                 / Busca rutas relacionadas con "bash" (requiere `updatedb`)
updatedb                    / Actualiza base de datos de locate
find / -name archivo.txt    / Busca archivo desde raíz
grep "texto" archivo.txt    / Busca texto dentro de archivo
cut -d':' -f1 /etc/passwd   / Extrae campo (nombre de usuarios, etc.)
xargs                       / Ejecuta comandos sobre resultados de otro comando

###⚙️ Variables y entorno
echo $PATH                  / Muestra las rutas de búsqueda de comandos
env                         / Lista variables de entorno
export VAR=valor            / Crea/modifica variable temporal

##📑 Procesamiento de texto y logs
head -n 10 archivo.txt      / Muestra las primeras 10 líneas
tail -n 10 archivo.txt      / Muestra las últimas 10 líneas
tail -f archivo.log         / Muestra en tiempo real nuevos registros
diff archivo1 archivo2      / Compara archivos línea por línea
tr 'a-z' 'A-Z'              / Convierte texto a mayúsculas

###🕒 Programación de tareas
crontab -e                  / Edita tareas periódicas del usuario
at 12:00                    / Programa una tarea para una hora concreta

###📊 Procesos
top                         / Muestra procesos en tiempo real
htop                        / Interfaz avanzada para ver procesos (si está instalado)
ps aux                      / Lista todos los procesos
kill -9 PID                 / Termina proceso por su ID
history                     / Muestra historial de comandos

###🌐 Red
ifconfig                    / Configura interfaces de red (obsoleto)
ip a                        / Alternativa moderna a ifconfig
iwconfig                    / Configura interfaces inalámbricas
netstat -pbtona             / Muestra conexiones y puertos abiertos
ss -tuln                    / Alternativa moderna a netstat
ping 8.8.8.8                / Verifica conexión a Internet
arp -a                      / Muestra tabla ARP
route                       / Tabla de rutas IP
scp archivo usuario@IP:/ruta / Copia archivos por SSH
lsof -i                     / Lista conexiones de red activas

###💽 Disco y sistema
df -h                       / Muestra uso del disco
du -sh /var/lib/*           / Muestra tamaño de subdirectorios
lsblk                       / Lista dispositivos de almacenamiento
mount                       / Muestra sistemas montados
umount /dev/sdX             / Desmonta dispositivo
uptime                      / Tiempo encendido del sistema
uname -a                    / Info del kernel
date                        / Fecha y hora actual
reboot                      / Reinicia el sistema
shutdown now                / Apaga el sistema inmediatamente

###🛠️ Archivos comprimidos
tar -czvf archivo.tar.gz carpeta/  / Comprime en formato .tar.gz
tar -xzvf archivo.tar.gz           / Descomprime archivo .tar.gz
zip archivo.zip archivo.txt        / Comprime archivo en .zip
unzip archivo.zip                  / Extrae archivos .zip

###🛡️ Seguridad y análisis
history | grep passwd              / Busca comandos sensibles en historial
find / -perm -4000 2>/dev/null     / Busca archivos con SUID (potenciales riesgos)
netstat -tulnp | grep LISTEN       / Ver puertos en escucha
ls -alh /home/*/.ssh/              / Revisa llaves SSH de usuarios
chkrootkit                         / Escáner básico de rootkits (si está instalado)

//🌐 Comunicación: protocolos y herramientas
Protocolos esenciales: TCP/IP, UDP, HTTP/HTTPS, FTP, SMTP, DNS.

Protocolos seguros: TLS/SSL, SSH, VPNs.

Herramientas destacadas: Wireshark, tcpdump, nmap.

Ejemplos prácticos:
sudo tcpdump -i eth0 port 443          / Captura tráfico HTTPS
nmap -sS -p 1-1000 192.168.1.10       / Escaneo de puertos


##🔌 Puertos comunes

Estos son los puertos más usados en redes y sistemas. Conocerlos es fundamental para entender qué servicios están activos, sus riesgos asociados y cómo protegerlos. Muchos ataques apuntan a estos puertos, por eso es clave monitorearlos y asegurar su configuración.

| Puerto(s)  | Protocolo | Servicio    | Descripción y Riesgos                         |
|------------|-----------|-------------|--------------------------------------------   |
| 20, 21     | TCP       | FTP         | Transferencia sin cifrado, riesgo MITM        |
| 22         | TCP       | SSH         | Acceso remoto seguro                          |
| 23         | TCP       | Telnet      | Sin cifrado, no recomendado                   |
| 25         | TCP       | SMTP        | Envío de correo, riesgo spam y spoofing       |
| 53         | UDP/TCP   | DNS         | Vulnerable a ataques DDoS y spoofing          |
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
L


## 🛠️ Herramientas online para análisis

Estas herramientas son esenciales para la investigación y análisis en ciberseguridad. Permiten detectar malware, analizar tráfico sospechoso, consultar reputación de IPs o dominios y explorar amenazas. Son recursos clave para analistas, pentesters y equipos de respuesta ante incidentes.

| Herramienta            | Enlace                          | Descripción                                          |
|-----------------------|--------------------------------|------------------------------------------------------|
| VirusTotal            | [virustotal.com](https://www.virustotal.com)             | Escanea archivos y URLs con múltiples motores antivirus. |
| urlscan.io            | [urlscan.io](https://urlscan.io)                         | Analiza comportamiento y contenido de URLs.              |
| AbuseIPDB             | [abuseipdb.com](https://www.abuseipdb.com)               | Base colaborativa para reportar IPs maliciosas.          |
| IPVoid                | [ipvoid.com](https://www.ipvoid.com)                     | Reputación de IPs y detección en listas negras.          |
| Talos Intelligence    | [talosintelligence.com](https://talosintelligence.com)   | Intel de amenazas y reputación de IPs y dominios.        |
| Shodan                | [shodan.io](https://www.shodan.io)                       | Motor de búsqueda para dispositivos conectados a internet|
| Censys                | [censys.io](https://censys.io)                           | Escanea infraestructura pública y certificados SSL.      |
| IP Quality Score      | [ipqualityscore.com](https://www.ipqualityscore.com)     | Evalúa riesgo de IPs, emails y dispositivos.             |
| Whois Domain Tools    | [domaintools.com](https://www.domaintools.com)           | Consulta información de registro de dominios.            |
| AnyRun Sandbox        | [any.run](https://any.run)                               | Análisis dinámico interactivo de malware.                |
| Hybrid Analysis       | [hybrid-analysis.com](https://www.hybrid-analysis.com)   | Sandbox para análisis automático de malware.             |
| Cuckoo Sandbox        | [cuckoosandbox.org](https://cuckoosandbox.org)           | Análisis automatizado open source de malware.            |
| MalwareBazaar         | [bazaar.abuse.ch](https://bazaar.abuse.ch)               | Repositorio de muestras de malware.                      |
| ThreatCrowd           | [threatcrowd.org](https://www.threatcrowd.org)           | Relaciona IPs, dominios, hashes y emails maliciosos.     |
| CIRCL Passive DNS     | [circl.lu](https://www.circl.lu)                         | Consulta histórica de resoluciones DNS.                  |
| FireEye Threat Intel  | [fireeye.com](https://www.fireeye.com)                   | Informes y datos sobre amenazas avanzadas.               |
| VirusTotal            | (https://www.virustotal.com/intelligence)                | Versión avanzada para análisis profundo.                 |
| MITRE ATT&CK Navigator | [attack.mitre.org](https://attack.mitre.org)            | Mapea técnicas y tácticas de ataques cibernéticos.       |


🚀 ¿Quieres contribuir?
Si tienes trucos, correcciones o nuevos apuntes, ¡haz un pull request!
Aquí fomentamos la colaboración y el aprendizaje continuo. 🤘

💬 Contacto
¿Preguntas o colaboraciones?
Encuéntrame en GitHub y en mis redes sociales.

📜 Licencia
Este repositorio está bajo licencia MIT.

**Recuerda**: En el mundo de la ciberseguridad, el conocimiento es poder. ¡Así que mantente curioso y nunca dejes de aprender! 🔍✨
