# 🔐 ssh-bruteforce-detector

Script en Python (sin dependencias) que analiza un log de **OpenSSH** y genera un informe en Markdown con:

- las **IPs que hacen fuerza bruta** y cuántos intentos hacen,
- el **tipo de ataque** (probar contraseñas de un usuario vs. recorrer un diccionario de usuarios),
- los **accesos correctos que ocurren después de muchos fallos** desde la misma IP (el caso más grave: posible compromiso).

## Demo

Informe generado sobre el log público `OpenSSH_2k.log` (2.000 líneas de un servidor real de laboratorio):

| # | IP | Fallos | Usuarios distintos | Intentos/min | Tipo |
|---|---|---|---|---|---|
| 1 | `183.62.140.253` | 286 | 10 | 27.9 | Diccionario de usuarios |
| 2 | `187.141.143.180` | 80 | 28 | 11.1 | Diccionario de usuarios |
| 3 | `103.99.0.122` | 46 | 19 | 0.4 | Diccionario de usuarios |

Informe completo: [`examples/informe_ejemplo.md`](examples/informe_ejemplo.md) · datos en JSON: [`examples/resultado_ejemplo.json`](examples/resultado_ejemplo.json)

> Hallazgo: el 72 % de los intentos fallidos apuntan a la cuenta `root`. El único acceso correcto del log
> (`fztu`) **no** se marca como sospechoso porque su IP no tenía fallos previos: el detector evita ese falso positivo.

## Cómo ejecutarlo

```bash
git clone https://github.com/IvanVH909/ssh-bruteforce-detector
cd ssh-bruteforce-detector
./data/download_sample.sh            # descarga el log de ejemplo (loghub)
python detector.py data/OpenSSH_2k.log --year 2024 --threshold 10
```

Opciones:

| Opción | Significado | Por defecto |
|---|---|---|
| `--threshold N` | Fallos mínimos para considerar una IP sospechosa | 10 |
| `--year AAAA` | Año del log (el syslog clásico no lo guarda) | año actual |
| `--output ruta.md` | Dónde guardar el informe | `informe.md` |
| `--json ruta.json` | Guarda también el resultado en JSON | — |

También funciona con tu propio `/var/log/auth.log` (Debian/Ubuntu) o `/var/log/secure` (RHEL/CentOS).

Tests: `python -m unittest discover -s tests -v`

## Cómo funciona

1. **Parseo**: una expresión regular separa la cabecera syslog (fecha, host, PID) del mensaje de `sshd`.
2. **Eventos**: otras dos expresiones extraen `Failed password for [invalid user] X from IP` y `Accepted ... for X from IP`.
3. **Líneas comprimidas**: syslog resume repeticiones con `message repeated N times: [...]`; el script las expande para no infravalorar los intentos.
4. **Estadísticas por IP**: fallos, usuarios probados, primer/último intento y ritmo (intentos/min).
5. **Detección de compromiso**: un acceso correcto se marca solo si ocurre **después** de ≥ N fallos de la misma IP.
6. **Informe**: Markdown con tablas y recomendaciones (fail2ban, `PermitRootLogin no`, claves SSH).

## Limitaciones y siguientes pasos

- Solo analiza autenticación por contraseña; no cubre ataques distribuidos (muchas IPs, pocos intentos cada una).
- No hace geolocalización ni consulta reputación de IPs (idea: enlazarlo con [`ioc-triage`](../ioc-triage)).
- El syslog no tiene año ni zona horaria; hay que indicarlos a mano.

## Créditos

Datos de ejemplo: [loghub](https://github.com/logpai/loghub) (Zhu et al., *Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics*, ISSRE 2023).
