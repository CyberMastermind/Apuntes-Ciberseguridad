# 🕵️‍♂️ Apuntes de Ciberseguridad 💻

¡Bienvenido a mi espacio dedicado a la ciberseguridad!  
Aquí encontrarás apuntes, análisis y reflexiones sobre el apasionante (y desafiante) mundo de la seguridad informática. 🔐🦠

---

## ⚠️ Aviso Legal

Estos apuntes son únicamente para fines educativos y de referencia.  
No me hago responsable por el uso indebido de la información contenida.

Recuerda: **con gran poder viene una gran responsabilidad**.  
Actúa siempre con ética y respeto en el ciberespacio. ⚡️

---

## 📚 ¿Qué encontrarás en este repositorio?

Una colección práctica de recursos para hackers éticos y entusiastas de la seguridad, organizada para facilitar el aprendizaje y la consulta.

### 📂 Estructura

- **Linux**  
  Comandos esenciales para manejar el terminal y configuraciones útiles para administración y seguridad.

- **Comunicación**  
  Protocolos fundamentales y herramientas para mantener comunicaciones seguras y eficientes.

- **Write-ups**  
  Análisis detallados de vulnerabilidades y experiencias reales en ciberseguridad.

- **Puertos comunes**  
  Tabla de puertos, protocolos, servicios y riesgos asociados.

---

## 📖 Contenido destacado

### Linux: Comandos útiles

```bash
ll                  # Muestra información detallada de archivos y carpetas.
ls -lt              # Lista archivos ordenados por fecha de modificación (más reciente primero).
ls -lah             # Muestra archivos ocultos, en formato lista y tamaños legibles.
ls D<TAB><TAB>      # Autocompleta directorios que comienzan con 'D'.
cd ~/Music/         # Navega a la carpeta Music dentro del directorio home.
cd ./ruta           # Navega a la ruta relativa desde el directorio actual.
cp -a Music/ Documents/   # Copia directorios de forma recursiva con atributos.
rsync -av imagenes/ imagenes2/  # Sincroniza carpetas mostrando progreso.
mkdir Scripts       # Crea carpeta Scripts.
rmdir ~/Scripts     # Borra carpeta Scripts en home.
rm Documents/readme.txt       # Borra archivo.
rm -i archivo.txt   # Pide confirmación antes de borrar.
rm -rf carpeta/     # Borra carpeta y todo su contenido sin preguntar (peligroso).
rm -f backup-2021*-12-3  # Borra archivos que coincidan con patrón sin preguntar.
mv text.txt Desktop/       # Mueve archivo a Desktop.
mv text.txt data.txt       # Renombra archivo.
echo "Hi!" > data.txt      # Crea o sobreescribe archivo con texto.
echo "Muy bien y tú" >> data.txt  # Añade línea de texto al final.
locate bash                # Busca archivos, base de datos debe estar actualizada.
adduser John               # Añade usuario John.
chmod 777 data.txt         # Permisos totales para todos.
chmod +x data.txt          # Permiso de ejecución.
cat data.txt               # Muestra contenido sin editar.
touch data.txt             # Crea archivo vacío.
gedit data.txt             # Editor gráfico.
nano data.txt              # Editor texto sencillo.
vi data.txt                # Editor texto avanzado.
df -h                      # Espacio libre en disco (human readable).
du -sh /var/lib/*          # Tamaño carpetas dentro de /var/lib.
stat readme.txt            # Información detallada de archivo.
arp -a                     # Tabla ARP y gateway.
route                      # Muestra rutas IP.
ifconfig                   # Configuración de red.
iwconfig                   # Configuración interfaces inalámbricas.
netstat -pbtona            # Ver conexiones activas.
wc -l archivo.txt          # Cuenta líneas de un archivo.
sudo -l                    # Privilegios sudo disponibles.
Comunicación: Protocolos y herramientas
Protocolos esenciales: TCP/IP, UDP, HTTP/HTTPS, FTP, SMTP, DNS.

Protocolos seguros: TLS/SSL, SSH, VPNs.

Herramientas: Wireshark, tcpdump, nmap.

Ejemplos prácticos:

bash
Mostrar siempre los detalles

Copiar
sudo tcpdump -i eth0 port 443          # Captura tráfico HTTPS.  
nmap -sS -p 1-1000 192.168.1.10       # Escaneo de puertos.  
Puertos comunes
Puerto(s)	Protocolo	Servicio	Descripción y Riesgos
20, 21	TCP	FTP	Transferencia de archivos sin cifrado. Riesgo MITM.
22	TCP	SSH	Acceso remoto seguro.
23	TCP	Telnet	Acceso remoto sin cifrado, no recomendado.
25	TCP	SMTP	Envío de correo. Puede ser vulnerado por spam.
53	UDP/TCP	DNS	Resolución de nombres. Vulnerable a ataques DDoS.
67, 68	UDP	DHCP	Asignación dinámica IP. Riesgo de spoofing.
69	UDP	TFTP	Transferencia simple sin seguridad.
80	TCP	HTTP	Tráfico web sin cifrado.
110	TCP	POP3	Recepción de correo sin cifrado.
123	UDP	NTP	Sincronización horaria. Puede ser usado para DDoS.
143	TCP	IMAP	Gestión remota de correo. Mejor que POP3.
161, 162	UDP	SNMP	Gestión de red. Versiones antiguas inseguras.
443	TCP	HTTPS	HTTP seguro con TLS. Imprescindible para seguridad.
445	TCP	SMB	Compartición de archivos Windows. Vulnerable a ransomware.
3389	TCP	RDP	Escritorio remoto. Objetivo frecuente de ataques.
5900	TCP	VNC	Control remoto, requiere seguridad adicional.
8080	TCP	HTTP alternativo	Usado para proxies o servicios web alternativos.
3306	TCP	MySQL	Base de datos, proteger con firewall y autenticación.
5432	TCP	PostgreSQL	Base de datos, mismo cuidado que MySQL.

Herramientas online para análisis y ciberseguridad
Herramienta	Enlace	Descripción
VirusTotal	https://www.virustotal.com	Escanea archivos y URLs con múltiples antivirus.
urlscan.io	https://urlscan.io	Analiza comportamiento y contenido de URLs.
AbuseIPDB	https://www.abuseipdb.com	Base de datos colaborativa de IPs maliciosas.
IPVoid	https://www.ipvoid.com	Verifica reputación de IPs.
Talos Intelligence	https://talosintelligence.com	Intel de amenazas y reputación IPs y dominios.
Shodan	https://www.shodan.io	Busca dispositivos conectados a internet.
Censys	https://censys.io	Escanea infraestructura pública e identifica hosts.
IP Quality Score	https://www.ipqualityscore.com	Evalúa riesgo de IPs, emails y dispositivos.
Whois Domain Tools	https://whois.domaintools.com	Consulta info de registro de dominios.
AnyRun Sandbox	https://any.run	Análisis dinámico de malware interactivo.
Hybrid Analysis	https://www.hybrid-analysis.com	Sandbox para análisis automático de malware.
Cuckoo Sandbox	https://cuckoosandbox.org	Análisis automatizado de malware open source.
MalwareBazaar	https://bazaar.abuse.ch	Repositorio de muestras de malware.
ThreatCrowd	https://www.threatcrowd.org	Relaciona IPs, dominios, hashes y emails maliciosos.
CIRCL Passive DNS	https://www.circl.lu/services/passive-dns	Consulta histórica de resoluciones DNS.
FireEye Threat Intel	https://www.fireeye.com	Informes y datos sobre amenazas avanzadas.
VirusTotal Intelligence	https://www.virustotal.com/gui/intelligence-overview	Versión avanzada para análisis más profundo.
MITRE ATT&CK Navigator	https://attack.mitre.org/navigator	Mapea técnicas y tácticas de ataques cibernéticos.

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
