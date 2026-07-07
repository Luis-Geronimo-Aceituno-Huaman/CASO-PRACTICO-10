# Caso Practico 10 - FastMarket S.A.C.

**Curso:** Desarrollo de Sistemas Web (CNA)  
**Universidad:** FISI - UNMSM  
**Fecha:** 07/07/2026  
**Objetivo:** Analizar una aplicacion web vulnerable, identificar riesgos segun OWASP Top 10 y proponer una arquitectura de seguridad.

---

## Descripcion del Proyecto

Esta aplicacion educativa simula una plataforma de venta de productos en linea para la empresa **FastMarket S.A.C.**. Contiene DOS versiones del mismo codigo:

| Version | Descripcion |
|---------|-------------|
| `/vulnerable` | Codigo intencionalmente inseguro para fines pedagogicos |
| `/corregido` | Codigo corregido aplicando buenas practicas de seguridad |

> **ADVERTENCIA:** Esta aplicacion es exclusivamente educativa. **NUNCA** desplegar la version vulnerable en un entorno de produccion.

---

## Requisitos

- [XAMPP](https://www.apachefriends.org/) / [Laragon](https://laragon.org/) / PHP 8.x
- MySQL 5.7+ o MariaDB 10.3+
- Navegador web actualizado

---

## Instalacion

### 1. Clonar o copiar el proyecto

```bash
# Copiar la carpeta proyecto-seguridad dentro de htdocs (XAMPP) o www (Laragon)
# Ejemplo con XAMPP:
# C:\xampp\htdocs\proyecto-seguridad\
```

### 2. Crear la base de datos

Abre phpMyAdmin (http://localhost/phpmyadmin) y ejecuta el archivo `database.sql`:

```sql
-- Opcion 1: desde phpMyAdmin, pestana SQL, pegar el contenido
-- Opcion 2: desde linea de comandos:
mysql -u root < database.sql
```

### 3. Configurar la conexion

Edita `conexion.php` en cada version segun tu configuracion:

```php
$host = 'localhost';
$dbname = 'fastmarket_db';
$user = 'root';      // usuario por defecto de XAMPP
$password = '';       // sin password por defecto en XAMPP
```

### 4. Ejecutar la aplicacion

**Opcion A: PHP built-in server (recomendado)**

```bash
# Terminal 1 - Version vulnerable
cd proyecto-seguridad/vulnerable
php -S localhost:8080

# Terminal 2 - Version corregida
cd proyecto-seguridad/corregido
php -S localhost:8081
```

**Opcion B: XAMPP/Laragon**

Accede a las versiones en:
- http://localhost/proyecto-seguridad/vulnerable/
- http://localhost/proyecto-seguridad/corregido/

### 5. Usuarios de prueba

| Usuario | Password | Rol |
|---------|----------|-----|
| admin | admin123 | admin |
| juan | juan2024 | cliente |
| maria | maria2024 | cliente |

---

## Estructura del Proyecto

```
proyecto-seguridad/
  database.sql              # Schema + datos de prueba
  README.md                 # Este archivo
  /vulnerable/              # Version INSEGURA (educativo)
    conexion.php            # Conexion PDO (sin seguridad)
    login.php               # Login vulnerable
    registro.php            # Registro vulnerable
    comentarios.php         # Comentarios con XSS
    perfil.php              # Perfil con Broken Access Control
    upload.php              # Carga de archivos sin validacion
    error_demo.php          # Errores con info tecnica expuesta
    style.css               # Estilos base
    /uploads/               # Directorio de archivos subidos
  /corregido/               # Version SEGURA
    config.php              # Configuracion global (HTTPS, HSTS, error handlers)
    conexion.php            # Conexion PDO (configuracion segura)
    logger.php              # Sistema de registro de eventos
    login.php               # Login seguro
    registro.php            # Registro seguro
    comentarios.php         # Comentarios sanitizados
    perfil.php              # Perfil con autorizacion
    upload.php              # Carga de archivos validada
    productos.php           # Gestion de productos (CRUD)
    panel_logs.php          # Panel de auditoria admin
    error_demo.php          # Demo de errores seguros
    error_generico.php      # Pagina de error generica (HTTP 500)
    style.css               # Estilos base
    /uploads/               # Directorio de archivos subidos
      .htaccess             # Bloquea ejecucion de PHP en uploads
```

---

## Configuracion HTTPS (Caso 7)

### Que es HTTPS y por que es obligatorio?

HTTPS (HTTP Secure) cifra toda la comunicacion entre el navegador y el servidor usando TLS/SSL. Sin HTTPS, las credenciales viajan en **texto plano** y cualquier dispositivo en la red puede interceptarlas.

### Comparativa: Login Vulnerable vs Corregido

| Aspecto | VULNERABLE (HTTP) | CORREGIDO (HTTPS) |
|---------|-------------------|-------------------|
| **Protocolo** | `http://localhost/login.php` | `https://localhost/login.php` |
| **Credenciales** | Viajan en texto plano | Cifradas con TLS/SSL |
| **Cookie sesion** | Sin flag `Secure` | Con flag `Secure` (solo HTTPS) |
| **Cookie HttpOnly** | No configurado | `httponly => true` |
| **Cookie SameSite** | No configurado | `samesite => 'Strict'` |
| **HSTS** | No existe | `Strict-Transport-Security` activo |
| **Sniffing** | Facil con Wireshark | Imposible (datos cifrados) |
| **MitM** | Ataque trivial | Protegido por cifrado TLS |

**Evidencia para el informe:**

```
VULNERABLE: En la version anterior (HTTP), al enviar el formulario de login:

  POST /login.php HTTP/1.1
  Host: localhost
  Content-Type: application/x-www-form-urlencoded
  
  usuario=admin&password=admin123

=> Las credenciales viajan LECTURABLE por la red.
   Cualquier sniffer (Wireshark, tcpdump) las captura.

CORREGIDO: En la version corregida (HTTPS), la misma peticion:

  POST /login.php HTTPS/1.1
  Host: localhost
  Content-Type: application/x-www-form-urlencoded
  
  [datos cifrados con TLS - NO legibles]

=> Las credenciales estan CIFRADAS.
   Un sniffer solo ve datos encriptados incomprensibles.
```

---

## Configuracion HTTPS en Local (XAMPP/Laragon)

### Opcion A: Certificado autofirmado (Recomendado)

#### Paso 1: Generar el certificado autofirmado

**En Windows (PowerShell como Administrador):**

```powershell
# Crear carpeta para certificados
mkdir C:\xampp\apache\conf\ssl-certs

# Generar certificado autofirmado valido por 365 dias
openssl req -x509 -nodes -days 365 -newkey rsa:2048 `
  -keyout C:\xampp\apache\conf\ssl-certs\localhost.key `
  -out C:\xampp\apache\conf\ssl-certs\localhost.crt `
  -subj "/CN=localhost/O=FastMarket/C=PE"

# Generar archivo .pem (requerido por algunos servidores)
cat C:\xampp\apache\conf\ssl-certs\localhost.crt, `
     C:\xampp\apache\conf\ssl-certs\localhost.key | `
  Set-Content C:\xampp\apache\conf\ssl-certs\localhost.pem
```

**En Linux/Mac:**

```bash
# Crear carpeta para certificados
mkdir -p /opt/lampp/apache2/conf/ssl-certs

# Generar certificado autofirmado
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /opt/lampp/apache2/conf/ssl-certs/localhost.key \
  -out /opt/lampp/apache2/conf/ssl-certs/localhost.crt \
  -subj "/CN=localhost/O=FastMarket/C=PE"
```

#### Paso 2: Habilitar mod_ssl en Apache

**En XAMPP:** Edita `C:\xampp\apache\conf\httpd.conf`:

```apache
# Descomentar (quitar el #) estas lineas:
LoadModule ssl_module modules/mod_ssl.so
Include conf/extra/httpd-ssl.conf
```

**En Laragon:** Ve a Menu > Apache > httpd.conf y busca las mismas lineas.

#### Paso 3: Configurar VirtualHost SSL

Edita `C:\xampp\apache\conf\extra\httpd-ssl.conf`:

```apache
<VirtualHost _default_:443>
    DocumentRoot "C:/xampp/htdocs/proyecto-seguridad-segura"
    ServerName localhost
    
    SSLEngine on
    SSLCertificateFile "conf/ssl-certs/localhost.crt"
    SSLCertificateKeyFile "conf/ssl-certs/localhost.key"
    
    <Directory "C:/xampp/htdocs/proyecto-seguridad-segura">
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

#### Paso 4: Actualizar el puerto en config.php

En `corregido/config.php`, la deteccion automatica de HTTPS funciona sin cambios adicionales. Si usas un puerto diferente a 443, ajusta la condicion:

```php
// Si HTTPS esta en puerto 8443 (puerto no estandar):
$es_https = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'
            || ($_SERVER['SERVER_PORT'] ?? 80) == 443
            || ($_SERVER['SERVER_PORT'] ?? 80) == 8443;
```

#### Paso 5: Reiniciar Apache

En XAMPP/Laragon, haz clic en "Restart" para Apache.

#### Paso 6: Probar

1. Abre `https://localhost/proyecto-seguridad-segura/corregido/login.php`
2. El navegador mostrara una advertencia de certificado autofirmado (es normal)
3. Haz clic en "Avanzado" > "Continuar a localhost (no seguro)"
4. La pagina cargara por HTTPS
5. Verifica en DevTools (F12) > Network que las peticiones son HTTPS

### Opcion B: Desarrollo sin HTTPS (temporal)

Si no puedes configurar SSL, descomenta temporalmente en `config.php`:

```php
// TEMPORAL - solo para desarrollo sin SSL:
// if (!$es_https) {
//     $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'];
//     $uri  = $_SERVER['REQUEST_URI'] ?? '/';
//     header("Location: https://$host$uri", true, 301);
//     exit;
// }
```

Y en `login.php`, cambia `'secure' => true` a `'secure' => false`:

```php
session_set_cookie_params([
    'secure' => false,  // TEMPORAL - en produccion debe ser true
    // ... demas parametros
]);
```

---

## Configuracion HTTPS en Produccion (Let's Encrypt)

### Paso 1: Tener un dominio real

Necesitas un dominio (ej: `fastmarket.com`) apuntando a tu servidor.

### Paso 2: Instalar Certbot

**Ubuntu/Debian:**

```bash
sudo apt update
sudo apt install certbot python3-certbot-apache
# O para Nginx:
sudo apt install certbot python3-certbot-nginx
```

### Paso 3: Obtener el certificado

**Apache:**

```bash
sudo certbot --apache -d fastmarket.com -d www.fastmarket.com
```

**Nginx:**

```bash
sudo certbot --nginx -d fastmarket.com -d www.fastmarket.com
```

**Standalone (sin modificar configuracion del servidor):**

```bash
sudo certbot certonly --standalone -d fastmarket.com
```

Certbot configurara automaticamente:
- Certificado SSL valido por 90 dias
- Redireccion HTTP → HTTPS
- Renovacion automatica (via cron/systemd)

### Paso 4: Verificar renovacion automatica

```bash
# Probar que la renovacion funciona
sudo certbot renew --dry-run

# Ver cron de renovacion
systemctl list-timers | grep certbot
```

### Paso 5: Configurar HSTS en el servidor

**Apache** (`/etc/apache2/sites-available/fastmarket-ssl.conf`):

```apache
<VirtualHost *:443>
    ServerName fastmarket.com
    
    # ... configuracion SSL existente ...
    
    # HSTS - Strict-Transport-Security
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
</VirtualHost>

# Redireccion HTTP → HTTPS
<VirtualHost *:80>
    ServerName fastmarket.com
    Redirect permanent / https://fastmarket.com/
</VirtualHost>
```

**Nginx** (`/etc/nginx/sites-available/fastmarket`):

```nginx
server {
    listen 80;
    server_name fastmarket.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name fastmarket.com;
    
    ssl_certificate /etc/letsencrypt/live/fastmarket.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/fastmarket.com/privkey.pem;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    
    # ... demas configuracion ...
}
```

---

## Headers de Seguridad Implementados

El archivo `config.php` configura los siguientes headers HTTP:

| Header | Valor | Proteccion |
|--------|-------|------------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Fuerza HTTPS por 1 ano |
| `X-Content-Type-Options` | `nosniff` | Evita MIME sniffing |
| `X-Frame-Options` | `DENY` | Evita clickjacking (iframe) |
| `X-XSS-Protection` | `1; mode=block` | XSS filter del navegador |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Controla envio de referrer |

---

## Matriz de Vulnerabilidades OWASP Top 10

| # | Archivo | Vulnerabilidad OWASP | Caso PDF | Descripcion |
|---|---------|---------------------|----------|-------------|
| 1 | `login.php` / `comentarios.php` | **A03:2021 - Injection** | Caso 1 | SQL Injection por concatenacion de queries |
| 2 | `comentarios.php` | **A03:2021 - Injection** | Caso 2 | XSS almacenado en formulario de comentarios |
| 3 | `perfil.php` | **A01:2021 - Broken Access Control** | Caso 3 | Acceso a perfiles de otros usuarios cambiando URL |
| 4 | `login.php` | **A07:2021 - Auth Failures** | Caso 4 | Cookies de sesion sin atributos HttpOnly/Secure/SameSite |
| 5 | `upload.php` | **A04:2021 - Insecure Design** | Caso 5 | Carga de archivos sin validacion de tipo/contenido |
| 6 | `error_demo.php` | **A05:2021 - Security Misconfiguration** | Caso 6 | Mensajes de error exponiendo info tecnica del servidor |
| 7 | `login.php` | **A02:2021 - Crypto Failures** | Caso 7 | Transmision de credenciales por HTTP sin HTTPS |
| 8 | Todos | **A09:2021 - Logging Failures** | Caso 8 | Ausencia total de registros de eventos de seguridad |
| 9 | `conexion.php` (vulnerable) | **A07:2021 - Auth Failures** | Caso 9 | Contraseñas almacenadas en texto plano |
| 10 | `registro.php` / `comentarios.php` | **A03:2021 - Injection** | Caso 10 | Formularios sin validacion de entrada |

---

## Controles de Seguridad Implementados (Version Corregida)

| Control | Archivo | Implementacion |
|---------|---------|----------------|
| Consultas parametrizadas | `conexion.php` + modulos | PDO con prepared statements |
| Sanitizacion de entrada | `comentarios.php`, `registro.php` | `htmlspecialchars()`, `filter_var()` |
| Hash de contrasenas | `registro.php`, `login.php` | `password_hash()` + `password_verify()` |
| Control de sesiones | `login.php` | `session_regenerate_id()`, cookies con atributos |
| Validacion de archivos | `upload.php` | Extension, MIME type, tamano maximo |
| Mensajes de error seguros | `error_demo.php` | Mensajes genericos sin info tecnica |
| Registro de eventos | `logger.php` | Tabla `logs_seguridad` + funcion centralizada |
| Autenticacion y autorizacion | `perfil.php`, `upload.php` | Verificacion de sesion y rol |
| HTTPS obligatorio | `config.php` | Redireccion HTTP → HTTPS + HSTS |
| Headers de seguridad | `config.php` | X-Frame-Options, X-Content-Type-Options, etc. |
| Proteccion uploads | `uploads/.htaccess` | Bloqueo de ejecucion de PHP |
| Gestion de productos | `productos.php` | CRUD con logging de cada operacion |
| Panel de auditoria | `panel_logs.php` | Visualizacion de logs (solo admin) |
| Manejo de errores | `config.php` | `set_error_handler()`, `set_exception_handler()`, `register_shutdown_function()` |

---

## Actividades del Caso Practico

1. **Analisis:** Identificar vulnerabilidades, clasificarlas segun OWASP, calcular riesgo
2. **Diseno:** Arquitectura de seguridad con controles preventivos, detectivos y correctivos
3. **Desarrollo:** Modificar fragmentos vulnerables con consultas parametrizadas, validacion, sanitizacion, hash, etc.
4. **Validacion:** Demostrar efectividad con pruebas antes/despues
5. **Informe Final:** Documento tecnico completo con diagnostico, soluciones y evidencias

---

## Tecnologias

- **Backend:** PHP 8.x
- **Base de datos:** MySQL / MariaDB
- **Frontend:** HTML5, CSS3, JavaScript
- **Seguridad:** OWASP Top 10 (2021)

---

## Notas Academicas

- Este proyecto es **exclusivamente educativo**
- La version vulnerable contiene codigo inseguro **intencionalmente**
- **NUNCA** usar la version vulnerable en produccion
- El objetivo es aprender a identificar y corregir vulnerabilidades
- Desarrollado para el curso de Desarrollo de Sistemas Web - FISI UNMSM
