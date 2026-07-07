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
    conexion.php            # Conexion PDO (configuracion segura)
    login.php               # Login seguro
    registro.php            # Registro seguro
    comentarios.php         # Comentarios sanitizados
    perfil.php              # Perfil con autorizacion
    upload.php              # Carga de archivos validada
    error_demo.php          # Errores personalizados
    logger.php              # Sistema de registro de eventos
    style.css               # Estilos base
    /uploads/               # Directorio de archivos subidos
```

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
| Hash de contraseñas | `registro.php`, `login.php` | `password_hash()` + `password_verify()` |
| Control de sesiones | `login.php` | `session_regenerate_id()`, cookies con atributos |
| Validacion de archivos | `upload.php` | Extension, MIME type, tamaño maximo |
| Mensajes de error seguros | `error_demo.php` | Mensajes genericos sin info tecnica |
| Registro de eventos | `logger.php` | Tabla `logs_seguridad` + funcion centralizada |
| Autenticacion y autorizacion | `perfil.php`, `upload.php` | Verificacion de sesion y rol |
| HTTPS | Configuracion del servidor | Redireccion HTTP -> HTTPS |

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
