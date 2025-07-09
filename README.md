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

📖 Glosario
# 📖 Glosario Completo de Ciberseguridad

## Conceptos y Herramientas Clave

- **ACL (Access Control List):** Lista de reglas que define permisos de acceso a recursos en sistemas o redes.

- **Adware:** Software que muestra publicidad no deseada, a menudo intrusiva o maliciosa.

- **AES (Advanced Encryption Standard):** Algoritmo de cifrado simétrico ampliamente utilizado para proteger datos.

- **API (Application Programming Interface):** Conjunto de reglas para que aplicaciones se comuniquen entre sí.

- **APT (Advanced Persistent Threat):** Ataque dirigido, persistente y sofisticado, generalmente patrocinado por estados o grupos organizados.

- **Antispyware:** Software diseñado para detectar y eliminar spyware.

- **Antivirus:** Programa que detecta, bloquea y elimina malware.

- **Backdoor:** Acceso oculto que permite controlar un sistema sin autorización.

- **Backup (Copia de seguridad):** Copia de datos para recuperación en caso de pérdida o daño.

- **BIA (Business Impact Analysis):** Análisis del impacto de interrupciones en procesos críticos.

- **Bot:** Programa automatizado que puede ser benigno o malicioso.

- **Botnet:** Red de dispositivos infectados controlados remotamente para ataques masivos.

- **Brute Force Attack:** Ataque que prueba todas las combinaciones posibles para obtener acceso.

- **CASB (Cloud Access Security Broker):** Herramienta que controla y protege el uso de servicios cloud.

- **CDE (Cardholder Data Environment):** Zona donde se procesan o almacenan datos de tarjetas de pago.

- **Certificate-Based Authentication:** Autenticación basada en certificados digitales.

- **CISA, CISM, CISSP:** Certificaciones profesionales en auditoría y gestión de seguridad de la información.

- **Cloud Security Posture Management (CSPM):** Herramientas para monitorear y mejorar la seguridad cloud.

- **COBIT:** Marco para gobernanza y gestión de TI.

- **Compliance:** Cumplimiento de leyes, normas y políticas de seguridad y privacidad.

- **Cookies:** Fragmentos de datos almacenados en navegadores para personalizar experiencia.

- **CVE (Common Vulnerabilities and Exposures):** Base pública de vulnerabilidades conocidas.

- **Cryptojacking:** Uso no autorizado de recursos para minar criptomonedas.

- **DLP (Data Loss Prevention):** Tecnologías y políticas para evitar fuga o pérdida de datos sensibles.

- **DNS Spoofing:** Técnica para redirigir tráfico DNS a sitios falsos.

- **Drive-by Download / Attack:** Descarga o ataque que ocurre al visitar un sitio web comprometido.

- **EDR (Endpoint Detection and Response):** Soluciones para detectar y responder amenazas en endpoints.

- **Exploit Kit:** Herramienta automatizada para aprovechar vulnerabilidades y propagar malware.

- **Fileless Malware:** Malware que opera en memoria sin dejar archivos en disco.

- **FIM (File Integrity Monitoring):** Monitoreo de integridad de archivos críticos.

- **Forense Digital:** Investigación y análisis de evidencias digitales tras incidentes.

- **GDPR:** Reglamento europeo sobre protección de datos personales.

- **Honeypot / Honeynet:** Sistemas o redes diseñados para atraer y analizar atacantes.

- **IAM (Identity and Access Management):** Gestión de identidades y permisos.

- **IDS (Intrusion Detection System) / IPS (Intrusion Prevention System):** Sistemas para detectar y bloquear ataques.

- **Insider Threat:** Amenaza originada desde dentro de la organización.

- **IoT (Internet of Things):** Dispositivos conectados a Internet susceptibles a ataques.

- **ISO 27001:** Norma internacional para gestión de seguridad de la información.

- **Key Exchange:** Protocolo para intercambio seguro de claves criptográficas.

- **Keylogger:** Software o hardware que registra pulsaciones para robar información.

- **Lateral Movement:** Técnica para moverse lateralmente dentro de una red tras comprometer un sistema.

- **LDAP (Lightweight Directory Access Protocol):** Protocolo para acceder y mantener servicios de directorio.

- **LFI / RFI:** Inclusión de archivos locales/remotos a través de fallos en aplicaciones web.

- **Logic Bomb:** Código malicioso que se activa bajo ciertas condiciones.

- **MAC Spoofing:** Suplantación de dirección MAC para evadir controles.

- **MFA (Multi-Factor Authentication):** Autenticación que requiere múltiples factores.

- **MITRE ATT&CK:** Base de conocimiento sobre tácticas y técnicas de atacantes. [MITRE ATT&CK](https://attack.mitre.org/)

- **NAC (Network Access Control):** Restricción de acceso a redes según políticas.

- **NIST / NIST CSF:** Instituto de estándares y su marco para gestión de riesgos en ciberseguridad. [NIST CSF](https://www.nist.gov/cyberframework)

- **OAuth:** Protocolo para autorización segura delegada.

- **OWASP:** Comunidad que publica recursos sobre seguridad web. [OWASP Top Ten](https://owasp.org/www-project-top-ten/)

- **PAM (Privileged Access Management):** Gestión de accesos privilegiados.

- **Patch Management:** Proceso de aplicación de parches para corregir vulnerabilidades.

- **PCI DSS:** Estándar para proteger datos de tarjetas de pago.

- **Penetration Testing (Pentest):** Simulación controlada de ataques para evaluar seguridad.

- **Pharming:** Redirección de tráfico legítimo a sitios maliciosos.

- **Phishing:** Técnica de engaño para obtener información confidencial.

- **Pivoting:** Uso de un sistema comprometido para atacar otros sistemas.

- **Privilege Escalation:** Obtención de permisos superiores a los asignados.

- **Ransomware:** Malware que cifra archivos y exige rescate.

- **RAT (Remote Access Trojan):** Malware que proporciona control remoto total.

- **RCE (Remote Code Execution):** Ejecución de código arbitrario de forma remota.

- **Recovery Time Objective (RTO) / Recovery Point Objective (RPO):** Métricas de recuperación tras incidentes.

- **Red Team / Blue Team:** Equipos que simulan ataques (Red) y defienden (Blue).

- **Root Access:** Acceso completo y sin restricciones a un sistema.

- **Rootkit:** Malware que oculta su presencia y la de otros programas maliciosos.

- **S3 Bucket Misconfiguration:** Configuración incorrecta de almacenamiento en la nube que expone datos.

- **SaaS (Software as a Service):** Software entregado vía Internet.

- **Sandboxing:** Ejecución de código en entorno aislado para análisis seguro.

- **Scareware:** Software que asusta al usuario con falsas alertas.

- **SCADA:** Sistemas industriales de control y automatización.

- **Session Hijacking:** Secuestro de sesión activa para acceso no autorizado.

- **SIM Swapping:** Robo del control del número telefónico para interceptar autenticaciones.

- **SIEM:** Plataforma para correlacionar y analizar eventos de seguridad.

- **Social Engineering:** Manipulación psicológica para obtener información o acceso.

- **SOC 2:** Estándar de auditoría para servicios SaaS.

- **Spam:** Correos o mensajes no solicitados, a menudo con fines maliciosos.

- **Spoofing:** Suplantación de identidad en redes o comunicaciones.

- **Spyware:** Software que recopila información sin consentimiento.

- **Supply Chain Attack:** Ataque que compromete proveedores o software de terceros.

- **Threat Hunting:** Búsqueda proactiva de amenazas en sistemas.

- **Threat Intelligence:** Información sobre amenazas actuales para anticipar ataques.

- **TLS / SSL:** Protocolos criptográficos para comunicaciones seguras.

- **Tokenization:** Reemplazo de datos sensibles por tokens para proteger información.

- **Two-Man Rule:** Política que requiere la aprobación de dos personas para acciones críticas.

- **UEBA:** Análisis de comportamiento de usuarios y entidades para detectar anomalías.

- **Vulnerability Assessment:** Evaluación sistemática para identificar debilidades.

- **VPN:** Red privada cifrada para acceso seguro.

- **WAF:** Firewall especializado en proteger aplicaciones web.

- **Watering Hole Attack:** Compromiso de sitios web frecuentados por objetivos específicos.

- **Whaling:** Phishing dirigido a altos ejecutivos o personas de alto perfil.

- **XDR:** Plataforma que unifica detección y respuesta en múltiples dominios.

- **XXE (XML External Entity):** Inyección de entidades externas en XML.

- **YARA:** Herramienta para identificar y clasificar malware mediante reglas.

- **Zero Day:** Vulnerabilidad desconocida sin parche disponible.

- **Zerologon:** Vulnerabilidad crítica en Netlogon que permite escalación de privilegios.

- **Zero Trust:** Modelo de seguridad que no confía automáticamente y siempre verifica.

## Términos adicionales recomendados

- **Análisis de Riesgos:** Proceso para identificar activos, amenazas, vulnerabilidades, impactos y probabilidades para definir controles.

- **Autenticación:** Proceso de verificar la identidad de un usuario o sistema.

- **Autorización:** Proceso que determina qué recursos puede acceder un usuario autenticado.

- **Breach and Attack Simulation (BAS):** Tecnologías que simulan ataques para evaluar controles.

- **Biometría:** Uso de características físicas o de comportamiento para autenticar usuarios.

- **Alta Disponibilidad:** Diseño para minimizar tiempos de inactividad y asegurar continuidad.

- **Ataque Diccionario:** Variante de fuerza bruta que usa listas predefinidas de contraseñas.

- **Ataque Homográfico:** Uso de URLs o dominios visualmente similares para engañar usuarios.

- **Auditoría de Seguridad:** Revisión sistemática para evaluar cumplimiento y efectividad.

- **Cifrado:** Proceso de transformar datos legibles en formato codificado para protegerlos.

- **Control de Acceso:** Mecanismos que regulan quién puede acceder a recursos o datos.

- **Data Breach:** Incidente donde datos sensibles son accedidos sin autorización.

- **Endpoint:** Dispositivo final en una red (PC, móvil, IoT).

- **Firewall:** Dispositivo o software que controla el tráfico de red según reglas.

- **Hashing:** Técnica para transformar datos en cadena fija para verificar integridad.

- **Incident Response:** Proceso para detectar, analizar y mitigar incidentes.

- **Malware:** Software malicioso que incluye virus, troyanos, ransomware, spyware, etc.

- **Multi-Tenancy:** Arquitectura cloud donde múltiples clientes comparten recursos físicos.

- **Patch:** Actualización de software para corregir vulnerabilidades.

- **Privacidad:** Protección de datos personales frente a accesos no autorizados.

- **Riesgo:** Probabilidad de que una amenaza explote una vulnerabilidad causando impacto.

- **Seguridad en la Nube:** Políticas y controles para proteger datos y servicios cloud.

- **Seguridad Perimetral:** Protección de los límites de una red para evitar accesos no autorizados.

## Tipos de Ataques Comunes

- **Brute Force:** Prueba masiva de contraseñas para acceder a un sistema.

- **Credential Stuffing:** Uso masivo de credenciales robadas para acceder a cuentas.

- **Cross-Site Scripting (XSS):** Inyección de scripts maliciosos en páginas web.

- **Denegación de Servicio (DoS/DDoS):** Saturación de servicios para hacerlos inaccesibles.

- **Drive-by Attack:** Infección automática al visitar sitios comprometidos.

- **LFI (Local File Inclusion):** Inclusión de archivos locales vía errores de programación.

- **Malvertising:** Publicidad maliciosa que distribuye malware.

- **Man In The Middle (MITM):** Interceptación activa de comunicaciones.

- **Pharming:** Redirección del tráfico a sitios maliciosos.

- **Phishing / Spear Phishing / Whaling:** Variantes del engaño por correo o medios digitales.

- **RCE (Remote Code Execution):** Ejecución remota de código arbitrario.

- **Shoulder Surfing:** Observación directa para obtener información sensible.

- **SIM Swapping:** Intervención en redes móviles para robar identidad.

- **SQL Injection:** Inyección de código SQL para manipular bases de datos.

- **Tailgating:** Acceso físico no autorizado siguiendo a una persona autorizada.

- **Vishing:** Phishing mediante llamadas telefónicas o mensajes de voz.

- **Watering Hole:** Compromiso de sitios frecuentados por el objetivo.

- **Zero-Day Exploit:** Ataque aprovechando vulnerabilidad aún no conocida públicamente.

---

🚀 ¿Quieres contribuir?
Si tienes trucos, correcciones o nuevos apuntes, ¡haz un pull request!
Aquí fomentamos la colaboración y el aprendizaje continuo. 🤘

💬 Contacto
¿Preguntas o colaboraciones?
Encuéntrame en GitHub y en mis redes sociales.

📜 Licencia
Este repositorio está bajo licencia MIT.

**Recuerda**: En el mundo de la ciberseguridad, el conocimiento es poder. ¡Así que mantente curioso y nunca dejes de aprender! 🔍✨
