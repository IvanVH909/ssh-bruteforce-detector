# Informe de fuerza bruta SSH

- **Fichero analizado:** `OpenSSH_2k.log`
- **Lineas leidas:** 2000 (sshd: 2000)
- **Intentos fallidos:** 528
- **Accesos correctos:** 1
- **IPs distintas:** 24
- **IPs sospechosas (>= 10 fallos):** 6

## Posibles accesos conseguidos tras fuerza bruta

No se ha detectado ningun acceso correcto precedido de fuerza bruta.

## IPs atacantes

| # | IP | Fallos | Usuarios distintos | Primer intento | Ultimo intento | Intentos/min | Tipo |
|---|---|---|---|---|---|---|---|
| 1 | `183.62.140.253` | 286 | 10 | 10-Dec 10:54:29 | 10-Dec 11:04:43 | 27.9 | Diccionario de usuarios (spraying) |
| 2 | `187.141.143.180` | 80 | 28 | 10-Dec 09:12:48 | 10-Dec 09:20:02 | 11.1 | Diccionario de usuarios (spraying) |
| 3 | `103.99.0.122` | 46 | 19 | 10-Dec 09:11:21 | 10-Dec 11:04:45 | 0.4 | Diccionario de usuarios (spraying) |
| 4 | `112.95.230.3` | 26 | 3 | 10-Dec 07:27:52 | 10-Dec 07:28:51 | 26.0 | Pocos usuarios |
| 5 | `5.188.10.180` | 18 | 7 | 10-Dec 08:24:35 | 10-Dec 08:26:24 | 9.9 | Diccionario de usuarios (spraying) |
| 6 | `185.190.58.151` | 17 | 3 | 10-Dec 09:07:58 | 10-Dec 09:12:59 | 3.4 | Pocos usuarios |

## Usuarios mas atacados

| Usuario | Intentos |
|---|---|
| `root` | 378 |
| `admin` | 44 |
| `support` | 6 |
| `oracle` | 6 |
| `test` | 5 |
| `uucp` | 5 |
| `user` | 4 |
| `matlab` | 3 |
| `inspur` | 3 |
| `1234` | 3 |

## Recomendaciones

- Bloquear las IPs atacantes (firewall / `fail2ban`).
- Deshabilitar login de `root` por SSH (`PermitRootLogin no`) y usar claves en vez de contraseñas.
- Revisar las cuentas que aparecen en la tabla de accesos conseguidos (cambio de contraseña, auditoria de comandos ejecutados).
