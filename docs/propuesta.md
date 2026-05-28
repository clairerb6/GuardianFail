
# GuardianFail  
## Sistema automatizado de inteligencia defensiva basado en logs de Fail2Ban

---

## 1. Nombre del proyecto

**GuardianFail**

---

## 2. Descripción del problema identificado

Los servidores conectados a internet se encuentran expuestos constantemente a intentos automatizados de acceso no autorizado. Estos intentos suelen provenir de bots que recorren direcciones IP públicas buscando servicios abiertos, credenciales débiles o configuraciones inseguras.

En servidores personales, académicos o de pequeñas organizaciones, es común utilizar herramientas como Fail2Ban para bloquear direcciones IP sospechosas después de múltiples intentos fallidos. Sin embargo, aunque Fail2Ban cumple una función defensiva importante, sus registros suelen quedar almacenados en archivos de log que no siempre son revisados de forma periódica.

Esto genera un problema práctico: el administrador puede estar recibiendo cientos de eventos de bloqueo sin contar con una visión clara del volumen, frecuencia, origen o criticidad de los intentos registrados.

En una prueba inicial realizada sobre un registro real de Fail2Ban de una VPS expuesta a internet, se detectaron más de 600 eventos de bloqueo asociados al servicio SSH. Este resultado evidencia que incluso infraestructuras pequeñas reciben actividad automatizada constante.

Para efectos de documentación y distribución académica, las direcciones IP utilizadas en capturas y reportes fueron anonimizadas parcialmente.

---

## 3. Justificación de la solución propuesta

GuardianFail busca transformar registros técnicos de seguridad en información clara y útil para la toma de decisiones defensivas.

La solución propuesta permite automatizar el análisis de logs de Fail2Ban, identificar direcciones IP bloqueadas, reconocer eventos nuevos, registrar historial local, clasificar el nivel de riesgo y enviar reportes automáticos por Telegram.

Esto permite que un administrador pueda recibir información resumida sin revisar manualmente archivos de log, facilitando la detección de actividad sospechosa y promoviendo mejores prácticas de seguridad.

El proyecto tiene un enfoque completamente defensivo. No realiza escaneos ni acciones activas contra terceros. Su análisis se limita a eventos ya registrados en infraestructura propia.

Adicionalmente, el sistema incorpora mecanismos de mantenibilidad y operación segura: retención automática de eventos históricos en SQLite para evitar crecimiento indefinido de la base, logging estructurado para trazabilidad y ejecución por línea de comandos con opciones de control por ejecución.

---

## 4. Objetivo general

Desarrollar un prototipo funcional que automatice el análisis de registros de Fail2Ban y genere reportes defensivos para apoyar la administración de servidores expuestos a internet.

---

## 5. Objetivos específicos

- Procesar archivos de log generados por Fail2Ban.
- Extraer eventos de bloqueo asociados a direcciones IP.
- Registrar eventos en una base de datos local.
- Identificar IPs nuevas y previamente registradas.
- Agrupar eventos por jail o servicio protegido.
- Calcular un nivel de riesgo general.
- Generar un reporte automático.
- Enviar el reporte mediante Telegram.
- Mantener un enfoque ético y defensivo.

---

## 6. Descripción de la solución

GuardianFail es una herramienta desarrollada en Python que lee los registros de Fail2Ban, extrae los eventos de bloqueo y los almacena en una base de datos SQLite.

Posteriormente, el sistema analiza la información recopilada y genera un reporte con métricas relevantes, tales como cantidad de eventos analizados, IPs detectadas, servicios afectados, IPs más frecuentes y recomendaciones de seguridad.

El reporte puede ser visualizado en consola, almacenado como archivo de texto y enviado automáticamente mediante Telegram.

La solución contempla una política de retención configurable (`event_retention_days`) que elimina eventos antiguos de la tabla `events` en cada ejecución. Para optimizar esta limpieza, se utiliza un índice en `event_datetime`.

---

## 7. Tecnologías utilizadas

| Tecnología | Uso dentro del proyecto |
|---|---|
| Python 3 | Lenguaje principal del prototipo |
| Fail2Ban | Fuente de eventos defensivos |
| SQLite | Registro histórico local |
| Telegram Bot API | Envío automático de reportes |
| Requests | Comunicación HTTP con Telegram |
| Linux | Entorno natural de ejecución |
| Cron / systemd timer | Automatización por horario |
| argparse | Interfaz CLI con flags de control |
| logging | Registro estructurado de eventos operativos |
| unittest | Pruebas automatizadas del prototipo |

---

## 8. Diagrama de arquitectura

```text
+--------------------+
| Log de Fail2Ban    |
+---------+----------+
          |
          v
+--------------------+
| Parser en Python   |
+---------+----------+
          |
          v
+----------------------------+
| Extracción de IPs y jails  |
+---------+------------------+
          |
          v
+--------------------+
| Base SQLite        |
+---------+----------+
          |
          v
+----------------------------+
| Clasificación de riesgo    |
+---------+------------------+
          |
          v
+--------------------+
| Reporte defensivo  |
+---------+----------+
          |
          v
+--------------------+
| Telegram           |
+--------------------+
```

---

## 9. Flujo de funcionamiento

1. El servidor recibe intentos de acceso no autorizados.
2. Fail2Ban detecta patrones sospechosos.
3. Fail2Ban bloquea temporalmente las IPs ofensivas.
4. GuardianFail lee el archivo de log.
5. El sistema extrae fecha, hora, jail e IP bloqueada.
6. Los eventos se almacenan en SQLite.
7. Se calculan métricas defensivas.
8. Se genera un reporte.
9. El reporte se envía automáticamente por Telegram.

Notas operativas del flujo actual:
- Se aplica retención automática de eventos históricos según la configuración.
- Se emiten logs estructurados para depuración y trazabilidad.
- Puede ejecutarse en modo `dry-run` para análisis sin persistencia.

---

## 10. Ejemplo de reporte generado

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
- 103.xxx.xxx.xxx | Jail: sshd | Eventos: 1 | Primera vez: 2026-05-24 00:23:09
- 14.xxx.xxx.xxx | Jail: sshd | Eventos: 1 | Primera vez: 2026-05-24 00:31:03
- 220.xxx.xxx.xxx | Jail: sshd | Eventos: 1 | Primera vez: 2026-05-24 00:53:15

Recomendaciones:
- Mantener Fail2Ban activo.
- Usar autenticación SSH por llave pública.
- Deshabilitar login SSH para root.
- Revisar puertos expuestos periódicamente.
- Mantener sistema y servicios actualizados.

Nota ética:
Este sistema analiza eventos registrados en infraestructura propia.
No realiza escaneos ni acciones activas contra terceros.
```
---

## 10.1 Configuración y operación CLI

El prototipo permite ejecutar análisis con control operativo por argumentos:

- `--config`: permite seleccionar un archivo de configuración específico.
- `--dry-run`: procesa el log sin persistir eventos ni generar archivo de reporte.
- `--no-telegram`: omite el envío de reporte por Telegram para la ejecución actual.
- `--log-level`: ajusta el nivel de logs en runtime (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`).

Configuración relevante del archivo JSON:

- `event_retention_days`: días de retención de eventos históricos en SQLite.
- `log_level`: nivel de logging por defecto cuando no se especifica `--log-level`.

---

## 10.2 Calidad y pruebas automatizadas

El proyecto incluye pruebas automatizadas con `unittest` para componentes críticos:

- Parsing de eventos de Fail2Ban.
- Validación de configuración (`config.json`).
- Cálculo de nivel de riesgo.
- Retención y poda de eventos antiguos.
- Creación del índice SQLite para rendimiento.
- Parsing de argumentos CLI.

Esto permite validar regresiones funcionales durante la evolución del prototipo.

---

## 11. Enfoque de innovación

GuardianFail incorpora innovación desde la automatización de tareas defensivas que normalmente se realizan de forma manual.

El proyecto toma información técnica que suele quedar oculta en archivos de log y la transforma en un reporte claro, resumido y accionable.

Además, el uso de Telegram permite que el administrador reciba información de seguridad sin necesidad de ingresar directamente al servidor.

El prototipo también puede evolucionar hacia una herramienta más avanzada, incorporando análisis de reputación pública de IPs, geolocalización aproximada, integración con paneles web o uso de inteligencia artificial para generar resúmenes ejecutivos.

---

## 12. Impacto esperado

El impacto esperado de GuardianFail se relaciona con la mejora de la visibilidad y gestión de eventos de seguridad en infraestructuras pequeñas.

Entre sus principales beneficios se encuentran:

- Reducción del tiempo necesario para revisar logs manualmente.
- Mejor comprensión del volumen de actividad maliciosa recibida.
- Mayor capacidad de reacción ante eventos repetitivos.
- Registro histórico de IPs bloqueadas.
- Mejora en la toma de decisiones defensivas.
- Fomento de buenas prácticas de administración de servidores.

---

## 13. Viabilidad técnica

GuardianFail es técnicamente viable porque utiliza herramientas conocidas, livianas y ampliamente disponibles.

Python permite desarrollar el prototipo rápidamente, SQLite evita depender de un servidor de base de datos externo y Telegram facilita el envío de notificaciones sin necesidad de construir una aplicación móvil.

El sistema puede ejecutarse de forma manual, mediante cron o a través de un servicio programado con systemd timer.

Las mejoras incorporadas (retención automática, logging estructurado, CLI configurable y pruebas automatizadas) aumentan la viabilidad operativa y reducen riesgos de mantenimiento a medida que crece el volumen de eventos.

---

## 14. Viabilidad comercial

Aunque el prototipo está orientado a un contexto académico, la idea puede evolucionar hacia una solución útil para pequeñas empresas, administradores independientes, estudiantes o personas que mantienen servidores personales.

Una versión comercial podría incluir:

- Panel web.
- Múltiples servidores.
- Integración con AbuseIPDB u otras fuentes públicas.
- Reportes semanales.
- Alertas por criticidad.
- Recomendaciones generadas por IA.
- Exportación a PDF.
- Integración con correo o Slack.

---

## 15. Consideraciones éticas

El proyecto se diseñó bajo un enfoque defensivo.

GuardianFail no ejecuta escaneos contra direcciones IP externas, no intenta acceder a sistemas de terceros y no realiza pruebas ofensivas.

La herramienta solo procesa información generada por eventos recibidos en infraestructura propia y tiene como finalidad mejorar la administración de seguridad del servidor.

Las direcciones IP utilizadas en reportes o capturas fueron anonimizadas parcialmente para proteger información sensible y evitar exposición innecesaria de datos de terceros.

---

## 16. Conclusión

GuardianFail demuestra cómo una solución simple puede transformar logs técnicos en información útil para la administración defensiva de servidores expuestos a internet.

El prototipo permite automatizar la revisión de eventos de Fail2Ban, registrar información histórica, clasificar riesgo y enviar reportes mediante Telegram.

Su valor principal está en acercar prácticas de ciberseguridad defensiva a contextos pequeños, donde muchas veces no existen herramientas avanzadas de monitoreo o personal dedicado exclusivamente a seguridad.

El proyecto es viable, escalable y responde a un problema real observado en una VPS expuesta a internet.
