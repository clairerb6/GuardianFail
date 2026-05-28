# GuardianFail 🛡️

**Sistema automatizado de inteligencia defensiva basado en logs de Fail2Ban.**

GuardianFail es una herramienta desarrollada en Python que analiza registros generados por Fail2Ban en servidores expuestos a internet. Su objetivo es transformar eventos técnicos de bloqueo en información clara, organizada y útil para la toma de decisiones defensivas.

El sistema permite identificar IPs bloqueadas, jails afectados, eventos nuevos, actividad histórica y nivel de riesgo general. Además, genera reportes automáticos y puede enviarlos mediante Telegram.

---

## 📌 Problema identificado

Los servidores expuestos a internet reciben constantemente intentos automatizados de acceso no autorizado. Estos intentos suelen provenir de bots que buscan servicios vulnerables, credenciales débiles o configuraciones inseguras.

Aunque herramientas como Fail2Ban permiten bloquear direcciones IP sospechosas, muchas veces los eventos quedan almacenados en logs que no son revisados de forma frecuente. Esto dificulta que administradores de pequeñas infraestructuras puedan interpretar el nivel real de exposición o detectar patrones de actividad maliciosa.

---

## 🎯 Objetivo del proyecto

Desarrollar una herramienta simple, automatizada y defensiva que procese logs de Fail2Ban, organice los eventos detectados y genere reportes comprensibles para el administrador del sistema.

---

## ⚙️ Funcionalidades principales

- Lectura de logs de Fail2Ban.
- Extracción de eventos de bloqueo.
- Identificación de direcciones IP bloqueadas.
- Registro histórico en base de datos SQLite.
- Detección de IPs nuevas y previamente registradas.
- Agrupación de eventos por jail o servicio protegido.
- Cálculo de nivel de riesgo general.
- Generación de reportes en texto.
- Envío automático de reportes mediante Telegram.
- Enfoque defensivo y ético.

---

## 🧱 Arquitectura general

```text
Log de Fail2Ban
      ↓
Parser Python
      ↓
Extracción de eventos
      ↓
Base de datos SQLite
      ↓
Clasificación de riesgo
      ↓
Generación de reporte
      ↓
Notificación por Telegram
```
---

## 🛠️ Tecnologías utilizadas

| Tecnología           | Uso                            |
| -------------------- | ------------------------------ |
| Python 3             | Lenguaje principal             |
| Fail2Ban             | Fuente de eventos de seguridad |
| SQLite               | Almacenamiento local           |
| Telegram Bot API     | Envío de reportes              |
| Requests             | Consumo de API HTTP            |
| Linux                | Entorno de ejecución           |
| Cron / systemd timer | Automatización programada      |

---

## 📁 Estructura del proyecto


```text
guardianfail/
├── guardianfail.py
├── config.example.json
├── requirements.txt
├── README.md
├── .gitignore
├── data/
│   └── .gitkeep
├── reports/
│   └── .gitkeep
├── sample/
│   └── fail2ban-sample.log
└── docs/
    └── propuesta.md
```
---

## 🚀 Instalación

Clonar el repositorio:
```bash
git clone https://github.com/USUARIO/guardianfail.git
cd guardianfail
```
Crear entorno virtual:

```bash
python3 -m venv venv
source venv/bin/activate
```
Instalar dependencias:

```bash
pip install -r requirements.txt
```
Crear archivo de configuración:

```bash
cp config.example.json config.json
```
Editar config.json con los datos correspondientes:

```json
{
  "fail2ban_log": "sample/fail2ban-sample.log",
  "database_path": "data/guardianfail.db",
  "telegram_bot_token": "TU_BOT_TOKEN",
  "telegram_chat_id": "TU_CHAT_ID",
  "own_server_ip": "",
  "enable_own_server_audit": false,
  "event_retention_days": 90,
  "log_level": "INFO",
  "geoip_city_db_path": ""
}
```
---

## ▶️ Ejecución

```bash
python guardianfail.py
```

Opciones útiles de CLI:

```bash
python guardianfail.py --config config.json
python guardianfail.py --dry-run
python guardianfail.py --no-telegram
python guardianfail.py --log-level DEBUG
```

- `--config`: usa un archivo de configuración específico.
- `--dry-run`: analiza el log sin persistir eventos ni guardar reporte.
- `--no-telegram`: omite envío a Telegram para esa ejecución.
- `--log-level`: define nivel de logs en runtime (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`).

Ejemplo de salida:

```markdown
🛡️ GuardianFail - Reporte defensivo

Fecha de análisis: 2026-05-27 17:59:58

Eventos analizados: 612
IPs nuevas detectadas: 612
IPs registradas previamente: 0
Nivel de riesgo general: Alto

Eventos por servicio:
- sshd: 612 eventos

Top IPs registradas:
- 103.xxx.xxx.xxx | Jail: sshd | Eventos: 1
- 14.xxx.xxx.xxx | Jail: sshd | Eventos: 1
- 220.xxx.xxx.xxx | Jail: sshd | Eventos: 1
```

Además, GuardianFail aplica retención automática en la tabla `events` según `event_retention_days` y mantiene un índice en `event_datetime` para optimizar la limpieza de eventos antiguos.
---


## 🌍 GeoIP opcional

GuardianFail puede enriquecer el bloque de `Top IPs` con país/ciudad usando base local de MaxMind.

- Descarga GeoLite2 City desde MaxMind (requiere cuenta gratuita): https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
- Descomprime la base y deja el archivo `GeoLite2-City.mmdb` dentro de `GeoIP/` (en cualquier subcarpeta), o define la ruta en `geoip_city_db_path`.
- Las bases GeoIP no deben versionarse en Git por tamaño/actualización frecuente.

Si no hay base disponible, el sistema sigue funcionando sin detenerse.

## 📲 Notificación por Telegram

GuardianFail puede enviar el reporte automáticamente a un chat de Telegram mediante un bot.

Para ello se requiere:

1. Crear un bot con @BotFather.
2. Obtener el token del bot.
3. Obtener el chat_id del usuario o grupo.
4. Configurar ambos valores en config.json.

---
## 🔐 Enfoque ético

GuardianFail es una herramienta defensiva.

El sistema analiza eventos registrados en infraestructura propia y no realiza escaneos ni acciones activas contra direcciones IP externas.

El objetivo del proyecto es mejorar la visibilidad sobre intentos de acceso no autorizados, apoyar la toma de decisiones y fomentar buenas prácticas de seguridad.

---

## 🧪 Datos de prueba

Para efectos académicos, se puede utilizar un archivo de log anonimizado en la carpeta sample/.

Las direcciones IP presentes en reportes, capturas o documentación deben ser anonimizadas parcialmente para evitar exponer información sensible o datos de terceros.

---

## 📈 Impacto esperado

GuardianFail permite que administradores de pequeñas infraestructuras puedan:

Comprender mejor la actividad maliciosa recibida.
Automatizar la revisión de eventos de seguridad.
Recibir alertas sin revisar manualmente archivos de log.
Mantener historial de eventos relevantes.
Mejorar sus prácticas defensivas.

---

## 📌 Estado del proyecto

Prototipo funcional desarrollado como MVP académico para el desafío:

Soluciones Digitales para Problemas Reales – Semana TELCO & IT

---

## 👩‍💻 Autora

Proyecto desarrollado por Katherine Flores.

---
