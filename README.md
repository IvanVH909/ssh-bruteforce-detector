# SSH-Bruteforce-Detector

Script en Python, sin dependencias externas, que analiza registros de autenticación de **OpenSSH** para identificar posibles ataques de fuerza bruta y generar un informe en Markdown.

La herramienta permite:

1. Identificar las IPs que realizan ataques de fuerza bruta y contabilizar sus intentos.
2. Diferenciar entre ataques de prueba de contraseñas contra un usuario y ataques de diccionario de usuarios.
3. Detectar accesos correctos que se producen después de numerosos intentos fallidos desde una misma IP, un posible indicador de compromiso.

## ¿Por qué desarrollar este detector?

Los registros de autenticación SSH contienen información útil para identificar intentos de acceso no autorizado, pero revisar manualmente grandes cantidades de eventos puede resultar lento.

Por eso, el proyecto automatiza el análisis de los logs de OpenSSH y agrupa los eventos por dirección IP para identificar patrones de fuerza bruta.

Además, diferencia los intentos fallidos de los accesos correctos posteriores, evitando marcar automáticamente como sospechoso cualquier inicio de sesión válido.

El objetivo es facilitar la detección inicial y proporcionar información útil para una investigación de seguridad.

## Características

- Análisis de registros de autenticación de OpenSSH.
- Identificación de direcciones IP sospechosas.
- Recuento de intentos fallidos por IP.
- Identificación de usuarios distintos probados.
- Cálculo del ritmo de intentos por minuto.
- Diferenciación entre ataques de contraseñas y ataques de diccionario de usuarios.
- Detección de accesos correctos posteriores a múltiples fallos.
- Procesamiento de mensajes de syslog comprimidos mediante `message repeated N times`.
- Generación de informes en Markdown.
- Exportación adicional de resultados en JSON.
- Umbral configurable para considerar sospechosa una IP.

## Requisitos

- Python 3.10 o superior.
- Git para clonar el repositorio y descargar los datos de ejemplo.

No es necesario instalar dependencias externas: el script utiliza la biblioteca estándar de Python.

## Instalación y configuración

Clonar el repositorio:

```bash
git clone https://github.com/IvanVH909/ssh-bruteforce-detector
cd ssh-bruteforce-detector
```

Descargar el log de ejemplo:

```bash
./data/download_sample.sh
```

El script descarga el fichero `OpenSSH_2k.log`, procedente del proyecto Loghub.

Ejecutar el detector:

```bash
python detector.py data/OpenSSH_2k.log --year 2024 --threshold 10
```

## Uso

### Analizar un log de OpenSSH

```bash
python detector.py data/OpenSSH_2k.log --year 2024 --threshold 10
```

### Opciones disponibles

| Opción | Significado | Por defecto |
|---|---|---|
| `--threshold N` | Fallos mínimos para considerar una IP sospechosa | 10 |
| `--year AAAA` | Año del log, ya que el syslog clásico no lo almacena | Año actual |
| `--output ruta.md` | Ruta donde guardar el informe | `informe.md` |
| `--json ruta.json` | Guarda también los resultados en JSON | — |

También puede utilizarse con registros propios:

- `/var/log/auth.log` en Debian y Ubuntu.
- `/var/log/secure` en RHEL y CentOS.

El año debe indicarse cuando sea necesario interpretar correctamente las fechas de los registros.

## Cómo funciona

El análisis se divide en varias fases:

1. **Parseo:** una expresión regular separa la cabecera syslog (fecha, host y PID) del mensaje generado por `sshd`.
2. **Identificación de eventos:** otras expresiones regulares extraen los mensajes `Failed password for [invalid user] X from IP` y `Accepted ... for X from IP`.
3. **Expansión de líneas comprimidas:** cuando syslog resume repeticiones mediante `message repeated N times: [...]`, el script las expande para contabilizar correctamente los intentos.
4. **Estadísticas por IP:** se calculan los fallos, los usuarios probados, el primer y último intento y el ritmo de intentos por minuto.
5. **Detección de posible compromiso:** un acceso correcto se marca como sospechoso únicamente si se produce después de alcanzar el umbral de fallos configurado desde esa misma IP.
6. **Generación del informe:** se crea un documento Markdown con tablas y recomendaciones de seguridad.

## Demo y resultados

El proyecto incluye un ejemplo de análisis realizado sobre `OpenSSH_2k.log`, un registro público de 2.000 líneas procedente de un servidor de laboratorio.

Los tres principales resultados del ejemplo son:

| # | IP | Fallos | Usuarios distintos | Intentos/min | Tipo |
|---|---|---:|---:|---:|---|
| 1 | `183.62.140.253` | 286 | 10 | 27.9 | Diccionario de usuarios |
| 2 | `187.141.143.180` | 80 | 28 | 11.1 | Diccionario de usuarios |
| 3 | `103.99.0.122` | 46 | 19 | 0.4 | Diccionario de usuarios |

Informe completo: [`examples/informe_ejemplo.md`](examples/informe_ejemplo.md).

Resultados en JSON: [`examples/resultado_ejemplo.json`](examples/resultado_ejemplo.json).

**Hallazgo destacado:** el 72 % de los intentos fallidos del registro se dirigen a la cuenta `root`.

El único acceso correcto del log, correspondiente al usuario `fztu`, no se marca como sospechoso porque su dirección IP no tenía intentos fallidos previos. Esto evita generar un falso positivo por el simple hecho de encontrar un inicio de sesión correcto.

> Los resultados corresponden a un registro de laboratorio y sirven como demostración del funcionamiento del detector. No representan necesariamente el comportamiento de un servidor en producción.

## Tests unitarios

El proyecto incorpora tests unitarios para comprobar el funcionamiento del detector.

Ejecutar todos los tests:

```bash
python -m unittest discover -s tests -v
```

## Limitaciones

- Solo analiza autenticaciones SSH mediante contraseña.
- No cubre ataques distribuidos en los que muchas IPs realizan pocos intentos cada una.
- No realiza geolocalización ni consulta la reputación de las direcciones IP.
- Los registros syslog clásicos no incluyen el año ni la zona horaria, por lo que es necesario proporcionar el año cuando corresponda.
- La detección de un posible compromiso depende del umbral configurado y de que los eventos relevantes aparezcan en el registro.
- El análisis de una IP no permite confirmar por sí solo que se haya producido un compromiso.

## Posibles mejoras futuras

Las siguientes funcionalidades se plantean como ampliaciones del proyecto y no forman parte de la implementación actual.

### 1. Integración con IOC-Triage

Integrar el detector con [ioc-triage](https://github.com/IvanVH909/ioc-triage) para enriquecer las direcciones IP identificadas durante los ataques.

El objetivo sería:

- Consultar la reputación de las IPs detectadas.
- Obtener información adicional mediante fuentes de inteligencia de amenazas.
- Incorporar el contexto de reputación al informe de análisis.
- Facilitar la priorización de las direcciones IP que requieren investigación.

### 2. Detección de ataques distribuidos

Ampliar la lógica de detección para identificar ataques distribuidos en los que múltiples direcciones IP realizan pocos intentos contra un mismo servidor o conjunto de usuarios.

Esto permitiría detectar patrones que pueden pasar desapercibidos cuando se analiza cada IP de forma independiente.

### 3. Enriquecimiento de las direcciones IP

Incorporar información adicional sobre las IPs detectadas, como:

- Geolocalización.
- Proveedor de red o ASN.
- Reputación en fuentes de inteligencia de amenazas.
- Historial de actividad sospechosa.

Esta información permitiría aportar más contexto a los resultados y facilitar la investigación.

### 4. Mejora de los informes

Ampliar los informes generados para incluir:

- Líneas temporales de los intentos de autenticación.
- Comparativas entre direcciones IP.
- Resúmenes de actividad por usuario.
- Evolución temporal de los ataques.
- Información adicional para facilitar la investigación SOC.

## Créditos

Los datos utilizados en la demostración proceden de [Loghub](https://github.com/logpai/loghub), de Zhu et al., *Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics*, ISSRE 2023.

---

## Autor

**Iván Vázquez Hernández**

GitHub: [@IvanVH909](https://github.com/IvanVH909)

Proyectos relacionados:

- [ssh-bruteforce-detector](https://github.com/IvanVH909/ssh-bruteforce-detector)
- [ioc-triage](https://github.com/IvanVH909/ioc-triage)

---

*Proyecto personal de ciberseguridad orientado a la detección de ataques de fuerza bruta SSH, el análisis de logs y la automatización de tareas de monitorización y respuesta SOC.*
