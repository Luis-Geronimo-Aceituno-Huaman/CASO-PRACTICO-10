## Arquitectura de seguridad propuesta

La arquitectura de seguridad implementada en la versión corregida de **FastMarket S.A.C.** se estructura en tres capas defensivas alineadas con el marco **OWASP Top 10 (2021)**: controles preventivos, detectivos y correctivos. Cada control fue diseñado para mitigar las vulnerabilidades identificadas en los Casos 1 al 10 del enunciado, aplicando el principio de **defensa en profundidad** (múltiples capas de seguridad de modo que la falla de una no comprometa todo el sistema).

---

### 1. Controles preventivos

Los controles preventivos tienen como objetivo **impedir que la vulnerabilidad sea explotada** antes de que ocurra. Se implementaron en cada punto de entrada de la aplicación (formularios, parámetros URL, carga de archivos, autenticación).

#### 1.1. Validación de entrada del lado del servidor (Caso 10)

Toda entrada proveniente del usuario se valida en el servidor **antes de procesarla**, independientemente de las validaciones del lado del cliente (que pueden ser ignoradas por un atacante). Se utiliza `filter_var()` con filtros específicos (`FILTER_VALIDATE_EMAIL`, `FILTER_VALIDATE_INT`, `FILTER_SANITIZE_FULL_SPECIAL_CHARS`) y expresiones regulares para validar formatos de nombre (solo letras y espacios, máximo 50 caracteres) y contenido de comentarios (máximo 300 caracteres).

**Nota de diseño:** La validación de entrada es una **capa adicional** de defensa en profundidad. La defensa principal contra XSS es la sanitización de salida (htmlspecialchars), y contra SQL Injection son las consultas parametrizadas. No se debe confiar exclusivamente en la validación de entrada porque un atacante puede enviar requests directamente al servidor saltándose el formulario.

**Archivos implementados:** `registro.php`, `comentarios.php`, `productos.php`

#### 1.2. Consultas parametrizadas — Prepared Statements con PDO (Caso 1)

Todas las consultas SQL que involucran datos del usuario se ejecutan mediante prepared statements de PDO, donde los valores se pasan como parámetros vinculados (`:parametro`) en lugar de concatenarse directamente en la cadena SQL. PDO se encarga de escapar internamente los valores, eliminando la posibilidad de que un payload de SQL Injection modifique la estructura de la consulta.

```php
// Ejemplo de implementación (login.php)
$stmt = $pdo->prepare("SELECT * FROM usuarios WHERE usuario = :usuario");
$stmt->execute([':usuario' => $usuario]);
```

La conexión PDO se configura con `PDO::ATTR_EMULATE_PREPARES => false` para garantizar que los prepared statements se ejecuten a nivel del motor de base de datos (no emulados en PHP), lo cual brinda una protección más robusta contra variaciones de SQL Injection.

**Archivos implementados:** `login.php`, `registro.php`, `comentarios.php`, `perfil.php`, `productos.php`, `panel_logs.php`

#### 1.3. Sanitización de salida — htmlspecialchars() (Caso 2)

Todo dato generado por el usuario que se imprime en HTML se envuelve con `htmlspecialchars($valor, ENT_QUOTES, 'UTF-8')`. Esto convierte los caracteres especiales HTML en sus entidades equivalentes (`<` → `&lt;`, `>` → `&gt;`, `"` → `&quot;`, `'` → `&#039;`), neutralizando cualquier intento de XSS almacenado o reflejado.

- **`ENT_QUOTES`** escapa tanto comillas dobles como simples, necesario porque los valores se usan dentro de atributos HTML (`value="..."`).
- **`'UTF-8'`** maneja correctamente tildes, ñ y caracteres especiales del idioma español.

**Archivos implementados:** `comentarios.php`, `perfil.php`, `upload.php`, `productos.php`, `panel_logs.php`, `error_demo.php`

#### 1.4. Hash de contraseñas — password_hash() / password_verify() (Caso 9)

Las contraseñas se almacenan exclusivamente como hashes generados con `password_hash()` usando el algoritmo `PASSWORD_DEFAULT` (actualmente bcrypt, que genera hashes de 60 caracteres con salt aleatorio integrado). Nunca se almacenan en texto plano.

Al validar el login, se utiliza `password_verify()` para comparar el password ingresado contra el hash almacenado sin exponerlo. Incluso si un atacante obtiene acceso a la base de datos, los hashes son costosos de revertir con fuerza bruta.

```php
// Registro: hash de contraseña
$password_hash = password_hash($password, PASSWORD_DEFAULT);

// Login: verificación sin exponer el hash
password_verify($password, $usuario_db['password']);
```

**Archivos implementados:** `registro.php` (hash), `login.php` (verificación)

#### 1.5. Whitelist de extensiones y validación MIME en carga de archivos (Caso 5)

La carga de archivos aplica **cinco capas de validación** en cascada:

| Capa | Validación | Herramienta | Protege contra |
|------|-----------|-------------|----------------|
| 1 | Extensiones permitidas (whitelist) | `pathinfo()` | Subida de scripts (.php, .sh, .exe) |
| 2 | Tipo MIME real del contenido | `finfo_file()` | Falsificación de Content-Type |
| 3 | Verificación de imagen válida | `getimagesize()` | Archivos con extensión .jpg que no son imágenes |
| 4 | Tamaño máximo (2MB) | Validación en script + php.ini | Denegación de servicio por llenado de disco |
| 5 | Nombre aleatorio | `bin2hex(random_bytes(8))` | Path traversal y sobrescritura |

Adicionalmente, el directorio `/uploads/` contiene un archivo `.htaccess` que bloquea la ejecución de scripts PHP dentro de esa carpeta, actuando como segunda barrera si un archivo malicioso lograse subirse.

**Archivos implementados:** `upload.php`, `uploads/.htaccess`

#### 1.6. Cookies de sesión con atributos de seguridad (Caso 4)

La cookie de sesión se configura **antes** de llamar a `session_start()` en todos los módulos, estableciendo los siguientes atributos:

| Atributo | Valor | Protección |
|----------|-------|-----------|
| `httponly` | `true` | JavaScript no puede acceder a la cookie (previene robo de sesión via XSS) |
| `secure` | `true` | La cookie solo se envía por conexiones HTTPS (previene interceptación en red) |
| `samesite` | `Strict` | La cookie no se envía en requests cross-origin (previene CSRF) |
| `lifetime` | `0` | Cookie de sesión (se elimina al cerrar el navegador) |

Adicionalmente, se ejecuta `session_regenerate_id(true)` después del login exitoso para prevenir **session fixation**: si un atacante conocía el ID de sesión antes del login, después de regenerar ya no sirve.

**Archivos implementados:** `login.php`, `comentarios.php`, `perfil.php`, `upload.php`, `panel_logs.php`, `productos.php`

#### 1.7. HTTPS obligatorio + HSTS (Caso 7)

La comunicación entre el navegador y el servidor se cifra mediante TLS/SSL en todas las páginas. La implementación incluye tres capas:

1. **Redirección PHP:** `config.php` detecta si la conexión es HTTP y redirige a HTTPS con código 301.
2. **Header HSTS:** `Strict-Transport-Security: max-age=31536000; includeSubDomains` le dice al navegador que NUNCA vuelva a intentar HTTP en visitas futuras durante 1 año.
3. **Cookie Secure:** La cookie de sesión tiene `secure => true`, por lo que solo se envía por conexiones HTTPS.

Esto garantiza que las credenciales (usuario + password) y cualquier dato sensible viajen **cifrados** por la red, eliminando la posibilidad de sniffing con herramientas como Wireshark o ataques man-in-the-middle.

**Archivos implementados:** `config.php`, `login.php`

#### 1.8. Control de acceso basado en sesión — prevención de IDOR (Caso 3)

El sistema verifica en cada módulo sensible que:

1. **Exista una sesión activa:** Si `$_SESSION['id_usuario']` no está definido, se redirige al login.
2. **El usuario esté autorizado:** Se compara el ID solicitado por URL (`$_GET['id']`) contra el ID de la sesión. Si no coinciden y el usuario no es admin, se retorna HTTP 403 con un mensaje genérico que **no revela si el recurso existe o no**.
3. **Los admins quedan registrados:** Si un admin accede al perfil de otro usuario, se registra en `logs_seguridad` para auditoría.

**Archivos implementados:** `perfil.php`, `panel_logs.php`, `productos.php`

#### 1.9. Recomendación adicional — WAF (Web Application Firewall)

Como capa perimetral complementaria (no implementada en el código de ejemplo pero recomendada para producción), se recomienda el uso de un **Web Application Firewall (WAF)** como ModSecurity, AWS WAF o Cloudflare WAF. Un WAF actúa como barrera entre la aplicación y el tráfico entrante, inspeccionando las peticiones HTTP en busca de patrones maliciosos (SQL Injection, XSS, path traversal, etc.) **antes de que lleguen al código PHP**. Esto proporciona una capa de protección adicional que puede mitigar vulnerabilidades de día cero y ataques automatizados sin modificar el código de la aplicación.

---

### 2. Controles detectivos

Los controles detectivos permiten **identificar que un incidente de seguridad está ocurriendo o ya ocurrió**, incluso cuando los controles preventivos no lograron bloquear el ataque.

#### 2.1. Tabla logs_seguridad — registro de eventos (Caso 8)

Cada módulo de la aplicación registra eventos de seguridad en la tabla `logs_seguridad` de la base de datos, utilizando la función reutilizable `registrarEvento()` definida en `logger.php`. La tabla almacena:

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `id` | INT AUTO_INCREMENT | Identificador único del evento |
| `tipo_evento` | VARCHAR(50) | Clasificación del evento |
| `usuario` | VARCHAR(50) | Usuario involucrado (puede ser NULL) |
| `ip` | VARCHAR(45) | Dirección IP del cliente (`$_SERVER['REMOTE_ADDR']`) |
| `detalle` | TEXT | Descripción legible del evento |
| `fecha` | DATETIME | Timestamp automático del registro |

Los tipos de evento monitoreados cubren los cuatro escenarios del Caso 8:

| Tipo de evento | Descripción | Módulo que lo registra |
|----------------|-------------|----------------------|
| `intento_fallido` | Credenciales incorrectas en login | `login.php` |
| `cambio_password` | Modificación de contraseña | `registro.php` (futuro módulo de cambio) |
| `acceso_admin` | Administrador accediendo a recursos privilegiados | `login.php`, `perfil.php` |
| `modificacion_producto` | Alta, baja o edición de productos | `productos.php`, `upload.php` |

Eventos adicionales implementados:

| Tipo de evento | Descripción |
|----------------|-------------|
| `intento_sospechoso` | Contenido rechazado en comentarios, acceso no autorizado a perfil, carga de archivo no permitida |
| `acceso_exitoso` | Login exitoso de cliente, registro de nuevo usuario |
| `bloqueo_temporal` | Bloqueo por intentos fallidos consecutivos |
| `error_sistema` | Errores PHP/SQL registrados internamente |

#### 2.2. Panel de auditoría (panel_logs.php)

Panel web **restringido a administradores** que muestra los últimos 50 eventos de seguridad ordenados del más reciente al más antiguo, con las siguientes funcionalidades:

- **Filtros por tipo de evento:** Permite visualizar solo intentos fallidos, cambios de contraseña, accesos de admin o modificaciones de productos.
- **Resumen con indicadores:** Muestra el conteo de eventos por tipo con código de color para identificación rápida.
- **Protección XSS:** Todos los campos se imprimen con `htmlspecialchars()` para prevenir inyección de scripts en los propios logs.
- **Control de acceso:** Solo usuarios con `rol='admin'` pueden acceder; intentos no autorizados se registran como `intento_sospechoso`.

#### 2.3. Recomendación — monitoreo externo

Para un entorno de producción, se recomienda complementar el registro en base de datos con:

- **Alertas automáticas:** Configurar reglas que disparen notificaciones cuando se detecten patrones anómalos (ej: más de 10 intentos fallidos de login desde una misma IP en 5 minutos).
- **fail2ban:** Herramienta a nivel de servidor que analiza los logs de Apache/Nginx y bloquea automáticamente IPs que muestran patrones de fuerza bruta, conectándose directamente con el firewall del sistema operativo.
- **SIEM (Security Information and Event Management):** Para entornos empresariales, herramientas como ELK Stack, Splunk o Wazuh centralizan los logs de seguridad y permiten correlacionar eventos entre múltiples fuentes.

---

### 3. Controles correctivos

Los controles correctivos definen **qué hacer después de detectar un incidente** para contener el daño, recuperar el sistema y prevenir que el incidente se repita.

#### 3.1. Bloqueo temporal por intentos fallidos (Caso 8)

Después de **5 intentos fallidos de login consecutivos** desde la misma dirección IP dentro de los últimos 10 minutos, el sistema bloquea temporalmente el acceso y muestra un mensaje genérico ("Demasiados intentos. Intenta más tarde."). Esto mitiga ataques de fuerza bruta automatizada.

La implementación consulta la tabla `logs_seguridad` para contar los eventos `intento_fallido` recientes desde la IP actual, usando prepared statements para evitar que el propio mecanismo de bloqueo sea vulnerable a inyección SQL.

#### 3.2. Invalidación de sesión

Ante actividad sospechosa detectada (acceso no autorizado a perfiles, intentos de carga de archivos maliciosos, patrones de inyección en comentarios), el sistema:

1. **Registra el evento** como `intento_sospechoso` en `logs_seguridad` con IP, usuario y detalle.
2. **Deniega la operación** con HTTP 403 y mensaje genérico.
3. **No revela información técnica** que pueda ayudar al atacante a refinar su ataque.

En un escenario de producción, se recomienda agregar la invalidación forzada de la sesión del usuario comprometido y la exigencia de cambio de contraseña al detectar actividad sospechosa.

#### 3.3. Plan de respuesta a incidentes

Ante la detección de un incidente de seguridad confirmado, se recomienda seguir el siguiente protocolo:

| Fase | Acción | Responsable |
|------|--------|-------------|
| **1. Aislamiento** | Bloquear la cuenta/IP comprometida. Si se detectó un archivo malicioso (ej: shell subido via upload), renombrarlo o eliminarlo del directorio `/uploads/`. | Equipo de seguridad |
| **2. Análisis** | Revisar la tabla `logs_seguridad` para identificar: horario del ataque, IP de origen, recursos accedidos, datos potencialmente comprometidos. | Equipo de seguridad |
| **3. Notificación** | Informar al usuario afectado (si aplica) sobre el incidente y las acciones tomadas. En producción, esto puede tener requisitos legales (Ley de Protección de Datos Personales). | Administrador |
| **4. Recuperación** | Rotar credenciales de la cuenta comprometida. Si se sospecha compromiso de la base de datos, rotar también las credenciales de la conexión PDO. Restaurar desde backup si se detectaron modificaciones no autorizadas. | Administrador |
| **5. Lecciones aprendidas** | Documentar el incidente, identificar qué control falló o fue evadido, y mejorar la arquitectura de seguridad para prevenir recurrencia. | Equipo de seguridad |

---

### 4. Matriz de controles — Casos 1 al 10

La siguiente tabla relaciona cada Caso del enunciado con la vulnerabilidad OWASP Top 10 que representa y el control (o controles) aplicado para mitigarla:

| Caso | Vulnerabilidad OWASP | Control aplicado | Tipo |
|------|---------------------|------------------|------|
| **Caso 1** | A03:2021 — Injection (SQL Injection) | Consultas parametrizadas con PDO (`prepare`/`execute` con parámetros vinculados) | Preventivo |
| **Caso 2** | A03:2021 — Injection (XSS Almacenado) | Sanitización de salida con `htmlspecialchars($valor, ENT_QUOTES, 'UTF-8')` en toda salida HTML | Preventivo |
| **Caso 3** | A01:2021 — Broken Access Control (IDOR) | Verificación de sesión activa + comparación de ID solicitado vs ID de sesión + control de rol admin | Preventivo |
| **Caso 4** | A07:2021 — Identification and Authentication Failures (Cookies inseguras) | Cookies con `httponly: true`, `secure: true`, `samesite: Strict` + `session_regenerate_id(true)` post-login | Preventivo |
| **Caso 5** | A04:2021 — Insecure Design (Carga de archivos) | Whitelist de extensiones + validación MIME (`finfo_file`) + `getimagesize()` + tamaño máximo + nombre aleatorio + `.htaccess` en `/uploads/` | Preventivo |
| **Caso 6** | A05:2021 — Security Misconfiguration (Errores expuestos) | `display_errors = OFF`, `log_errors = ON`, `set_error_handler()`, `set_exception_handler()`, `register_shutdown_function()`, mensajes genéricos al usuario | Preventivo + Detectivo |
| **Caso 7** | A02:2021 — Cryptographic Failures (Sin HTTPS) | Redirección HTTP → HTTPS, header HSTS (`Strict-Transport-Security`), cookie con flag `Secure` | Preventivo |
| **Caso 8** | A09:2021 — Security Logging and Monitoring Failures (Sin logs) | Tabla `logs_seguridad` + función `registrarEvento()` + `panel_logs.php` (solo admin) | Detectivo |
| **Caso 9** | A07:2021 — Identification and Authentication Failures (Passwords en texto plano) | `password_hash()` con `PASSWORD_DEFAULT` (bcrypt) al registrar + `password_verify()` al autenticar | Preventivo |
| **Caso 10** | A03:2021 — Injection (Sin validación de entrada) | Validación server-side con `filter_var()`, `preg_match()`, `strlen()` + patrones sospechosos rechazados y registrados | Preventivo + Detectivo |

---

### 5. Diagrama de capas defensivas

```
┌─────────────────────────────────────────────────────────────┐
│                    CAPA PERIMETRAL                          │
│         (Recomendada: WAF - ModSecurity, Cloudflare)       │
├─────────────────────────────────────────────────────────────┤
│                    CAPA DE RED                              │
│           HTTPS obligatorio + HSTS (Caso 7)                │
├─────────────────────────────────────────────────────────────┤
│                 CAPA DE APLICACIÓN                          │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  Validación  │  │  Prepared    │  │  htmlspecialchars │  │
│  │  de entrada  │  │  Statements  │  │  (sanitización)  │  │
│  │  (Caso 10)   │  │  (Caso 1)    │  │  (Caso 2)        │  │
│  └─────────────┘  └──────────────┘  └──────────────────┘  │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  password_   │  │  Cookies     │  │  Control de      │  │
│  │  hash/verify │  │  seguras     │  │  acceso (IDOR)   │  │
│  │  (Caso 9)    │  │  (Caso 4)    │  │  (Caso 3)        │  │
│  └─────────────┘  └──────────────┘  └──────────────────┘  │
│  ┌─────────────┐  ┌──────────────┐                        │
│  │  Whitelist   │  │  Manejo de   │                        │
│  │  archivos    │  │  errores     │                        │
│  │  (Caso 5)    │  │  (Caso 6)    │                        │
│  └─────────────┘  └──────────────┘                        │
├─────────────────────────────────────────────────────────────┤
│                 CAPA DE MONITOREO                           │
│  ┌──────────────────┐  ┌──────────────────────────────┐   │
│  │  logs_seguridad   │  │  panel_logs.php (admin)      │   │
│  │  + registrarEvento│  │  + recomendación fail2ban/SIEM│   │
│  │  (Caso 8)         │  │                               │   │
│  └──────────────────┘  └──────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                 CAPA DE RESPUESTA                           │
│  Bloqueo temporal + invalidación de sesión +                │
│  plan de respuesta a incidentes                             │
└─────────────────────────────────────────────────────────────┘
```
