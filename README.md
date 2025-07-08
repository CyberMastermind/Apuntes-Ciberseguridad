# 🕵️‍♂️ Apuntes de Ciberseguridad 💻

¡Bienvenido a mi espacio dedicado a la ciberseguridad!  
Aquí encontrarás apuntes, análisis y reflexiones sobre el apasionante (y desafiante) mundo de la seguridad informática. 🔐🦠

---

## ⚠️ Aviso Legal

Estos apuntes son únicamente para fines educativos y de referencia.  
No me hago responsable por el uso indebido de la información contenida.

**Recuerda:** con gran poder viene una gran responsabilidad.  
Actúa siempre con ética y respeto en el ciberespacio. ⚡️

---

## 📚 ¿Qué encontrarás en este repositorio?

Recursos prácticos para hackers éticos y entusiastas de la seguridad, organizados para facilitar tu aprendizaje y consulta.

### 📂 Estructura general

- **Linux:** comandos esenciales para terminal y administración segura.  
- **Comunicación:** protocolos, herramientas y mejores prácticas.  
- **Write-ups:** análisis y casos prácticos de vulnerabilidades.  
- **Puertos comunes:** tabla con servicios, riesgos y protocolos.  
- **Herramientas online:** recursos para análisis y detección.

---

## 🖥️ Linux: comandos útiles

```bash
ll                  # Muestra info detallada de archivos y carpetas
ls -lt              # Lista archivos ordenados por fecha de modificación (más reciente primero)
ls -lah             # Archivos ocultos, lista y tamaños legibles
cd ~/Music/         # Navega a carpeta Music en home
cp -a Music/ Documents/   # Copia directorios recursivamente con atributos
rsync -av imagenes/ imagenes2/  # Sincroniza carpetas mostrando progreso
mkdir Scripts       # Crea carpeta Scripts
rmdir ~/Scripts     # Borra carpeta Scripts en home
rm -i archivo.txt   # Borra archivo con confirmación
rm -rf carpeta/     # Borra carpeta y todo su contenido sin preguntar (¡cuidado!)
mv text.txt Desktop/       # Mueve archivo a Desktop
echo "Hola" > data.txt      # Crea o sobreescribe archivo con texto
locate bash                # Busca archivos (base de datos actualizada)
adduser John               # Añade usuario John
chmod 777 data.txt         # Permisos totales a todos
chmod +x data.txt          # Permiso de ejecución
cat data.txt               # Muestra contenido sin editar
touch data.txt             # Crea archivo vacío
gedit data.txt             # Editor gráfico
nano data.txt              # Editor texto simple
vi data.txt                # Editor texto avanzado
df -h                      # Espacio libre en disco (legible)
du -sh /var/lib/*          # Tamaño carpetas dentro de /var/lib
stat readme.txt            # Info detallada de archivo
arp -a                     # Tabla ARP y gateway
route                      # Muestra rutas IP
ifconfig                   # Configuración red
iwconfig                   # Configuración interfaces inalámbricas
netstat -pbtona            # Ver conexiones activas
wc -l archivo.txt          # Cuenta líneas de un archivo
sudo -l                    # Privilegios sudo disponibles
🌐 Comunicación: protocolos y herramientas
Protocolos esenciales: TCP/IP, UDP, HTTP/HTTPS, FTP, SMTP, DNS.

Protocolos seguros: TLS/SSL, SSH, VPNs.

Herramientas destacadas: Wireshark, tcpdump, nmap.

Ejemplos prácticos:

bash
Mostrar siempre los detalles

Copiar
sudo tcpdump -i eth0 port 443          # Captura tráfico HTTPS
nmap -sS -p 1-1000 192.168.1.10       # Escaneo de puertos
🔌 Puertos comunes
Puerto(s)	Protocolo	Servicio	Descripción y Riesgos
20, 21	TCP	FTP	Transferencia sin cifrado, riesgo MITM
22	TCP	SSH	Acceso remoto seguro
23	TCP	Telnet	Sin cifrado, no recomendado
25	TCP	SMTP	Envío de correo, riesgo spam y spoofing
53	UDP/TCP	DNS	Vulnerable a ataques DDoS y spoofing
67, 68	UDP	DHCP	Riesgo spoofing en asignación IP
69	UDP	TFTP	Transferencia simple, no seguro
80	TCP	HTTP	Tráfico sin cifrado
110	TCP	POP3	Recepción sin cifrado
123	UDP	NTP	Usado para sincronización y amplificación DDoS
143	TCP	IMAP	Gestión remota correo, mejor que POP3
161, 162	UDP	SNMP	Gestión de red, versiones inseguras
443	TCP	HTTPS	HTTP seguro con TLS
445	TCP	SMB	Compartición Windows, vulnerable ransomware
3389	TCP	RDP	Escritorio remoto, objetivo común ataques
5900	TCP	VNC	Control remoto, requiere seguridad adicional
8080	TCP	HTTP alt	Proxies o servicios web alternativos
3306	TCP	MySQL	Base de datos, proteger con firewall
5432	TCP	PostgreSQL	Base de datos, mismo cuidado que MySQL

🛠️ Herramientas online para análisis y ciberseguridad
Herramienta	Enlace	Descripción
VirusTotal	virustotal.com	Escanea archivos y URLs con múltiples antivirus.
urlscan.io	urlscan.io	Analiza comportamiento y contenido de URLs.
AbuseIPDB	abuseipdb.com	Base colaborativa de IPs maliciosas.
IPVoid	ipvoid.com	Reputación de IPs y detección en listas negras.
Talos Intelligence	talosintelligence.com	Intel de amenazas y reputación de IPs y dominios.
Shodan	shodan.io	Busca dispositivos conectados a internet.
Censys	censys.io	Escanea infraestructura pública y certificados.
IP Quality Score	ipqualityscore.com	Evalúa riesgo de IPs, emails y dispositivos.
Whois Domain Tools	domaintools.com	Consulta info de registro de dominios.
AnyRun Sandbox	any.run	Análisis dinámico interactivo de malware.
Hybrid Analysis	hybrid-analysis.com	Sandbox para análisis automático de malware.
Cuckoo Sandbox	cuckoosandbox.org	Análisis automatizado de malware open source.
MalwareBazaar	bazaar.abuse.ch	Repositorio de muestras de malware.
ThreatCrowd	threatcrowd.org	Relaciona IPs, dominios, hashes y emails maliciosos.
CIRCL Passive DNS	circl.lu	Consulta histórica de resoluciones DNS.
FireEye Threat Intel	fireeye.com	Informes y datos sobre amenazas avanzadas.
VirusTotal Intelligence	virustotal.com/intelligence	Versión avanzada para análisis profundo.
MITRE ATT&CK Navigator	attack.mitre.org	Mapea técnicas y tácticas de ataques cibernéticos.

🚀 ¿Quieres contribuir?
Si tienes trucos, correcciones o nuevos apuntes, ¡haz un pull request!
Aquí fomentamos la colaboración y el aprendizaje continuo. 🤘

💬 Contacto
¿Preguntas o colaboraciones?
Encuéntrame en GitHub y en mis redes sociales.

📜 Licencia
Este repositorio está bajo licencia MIT.
Puedes usar el contenido libremente, pero siempre da crédito a su autor.

Recuerda: En ciberseguridad, la curiosidad y el aprendizaje constante son tu mejor defensa. ¡Sigue explorando! 🔍✨
"""

**Recuerda**: En el mundo de la ciberseguridad, el conocimiento es poder. ¡Así que mantente curioso y nunca dejes de aprender! 🔍✨
