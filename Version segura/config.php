<?php
/**
 * config.php - Configuracion global de seguridad (VERSION CORREGIDA)
 * CASO PRACTICO 10 - FastMarket S.A.C.
 *
 * Este archivo debe incluirse al inicio de TODOS los modulos corregidos
 * (login.php, registro.php, comentarios.php, upload.php, perfil.php, etc.)
 * para garantizar que ningun error se filtre al usuario.
 *
 * Este archivo configura:
 *   - HTTPS obligatorio + HSTS (Caso 7)
 *   - display_errors = OFF (nunca mostrar errores en pantalla) (Caso 6)
 *   - log_errors = ON (registrar errores en archivo del servidor) (Caso 6)
 *   - set_exception_handler() para excepciones no manejadas (Caso 6)
 *   - set_error_handler() para errores PHP no fatales (Caso 6)
 */

// =============================================================
// CORREGIDO (Caso 7): Forzar HTTPS y configurar HSTS
// =============================================================
// VULNERABLE: La version anterior no forzaba HTTPS. El login se
// accedia por HTTP (http://localhost/login.php), y las credenciales
// (usuario + password) viajaban en TEXTO PLANO por la red.
//
// Cualquier dispositivo en la misma red (router, punto de acceso
// WiFi, ISP) podia interceptar las credenciales con herramientas
// como Wireshark, tcpdump o Firesheep.
//
// CORREGIDO: Ahora forzamos HTTPS con 3 capas:
//
//   1. Redireccion a HTTPS en codigo PHP (esta linea)
//   2. Header HSTS (Strict-Transport-Security) para que el navegador
//      NUNCA vuelva a intentar HTTP en visitas futuras
//   3. Cookie con flag Secure (en login.php) para que solo se envie
//      por conexion HTTPS
//
// NOTA IMPORTANTE PARA DESARROLLO LOCAL:
// Si no tienes certificado SSL en tu servidor local (XAMPP/Laragon),
// la redireccion a HTTPS mostrara un error de certificado en el navegador.
// Para desarrollo local, tienes 2 opciones:
//
//   Opcion A: Desactivar temporalmente esta redireccion
//     Comentar el bloque if() de abajo. La cookie Secure tambien
//     debe cambiarse a false en login.php.
//
//   Opcion B: Crear un certificado autofirmado (RECOMENDADO)
//     Ver instrucciones en README.md -> seccion "Configuracion HTTPS"
//
// EN PRODUCCION (hosting real):
//   Usar Let's Encrypt (certbot) para certificado SSL gratuito.
//   Ver instrucciones en README.md -> seccion "Configuracion HTTPS"
// =============================================================

// detectar si estamos en HTTPS (funciona detras de proxies/load balancers)
$es_https = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'
            || ($_SERVER['SERVER_PORT'] ?? 80) == 443
            || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';

if (!$es_https) {
    // Redireccionar a HTTPS
    $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'];
    $uri  = $_SERVER['REQUEST_URI'] ?? '/';
    header("Location: https://$host$uri", true, 301);
    exit;
}

// =============================================================
// CORREGIDO (Caso 7): Header HSTS (Strict-Transport-Security)
// =============================================================
// HSTS le dice al navegador: "Nunca accedas a este dominio por HTTP,
// incluso si el usuario escribe http://manualmente o hace clic en
// un link HTTP".
//
// max-age=31536000 → 1 ano. Despues de la primera visita HTTPS,
// el navegador FORZARA HTTPS automaticamente durante 1 ano.
//
// includeSubDomains → Aplica tambien a subdominios
//   (ej: api.fastmarket.com tambien usa HTTPS)
//
// preload → Permite incluir el dominio en la lista de precompilacion
//   de navegadores (solo para sitios en produccion publicos)
//
// VULNERABLE: La version anterior no tenia este header. El navegador
// podia acceder por HTTP si el usuario escribia la URL manualmente.
// =============================================================

header('Strict-Transport-Security: max-age=31536000; includeSubDomains', false);

// =============================================================
// CORREGIDO (Caso 7): Headers de seguridad adicionales
// =============================================================
// Estos headers refuerzan la seguridad a nivel de navegador.
// VULNERABLE: La version anterior no configuraba ningun header.
// =============================================================

header('X-Content-Type-Options: nosniff', false);    // Evita MIME sniffing
header('X-Frame-Options: DENY', false);               // Evita clickjacking (iframe)
header('X-XSS-Protection: 1; mode=block', false);     // XSS filter del navegador
header('Referrer-Policy: strict-origin-when-cross-origin', false);

ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
ini_set('log_errors', '1');

// =============================================================
// CORREGIDO (Caso 6): Configurar nivel de errores a registrar
// =============================================================
// Reportar todos los errores excepto notices y deprecated notices
// (que son molestos en produccion pero no son errores de seguridad).
// =============================================================

error_reporting(E_ALL & ~E_NOTICE & ~E_DEPRECATED & ~E_STRICT);

// =============================================================
// CORREGIDO (Caso 6): Manejador global de errores PHP
// =============================================================
// set_error_handler() captura errores PHP que normalmente mostraria
// en pantalla (warnings, notices, errores fatales no capturados).
//
// En la version vulnerable, estos errores se mostraban al usuario
// con informacion tecnica completa (ruta del archivo, linea, etc.).
//
// Ahora, todo error PHP se redirige a una funcion que:
//   1. Registra el detalle real en error_log() (para el admin)
//   2. Redirige al usuario a error_generico.php (mensaje generico)
//
// NOTA: set_error_handler() NO captura errores fatales de PHP
// (out of memory, etc.). Para eso se necesita set_exception_handler()
// y/o shutdown_function.
// =============================================================

set_error_handler(function (int $errno, string $errstr, string $errfile, int $errline) {

    // Solo procesar errores realmente problematicos (no notices ni warnings)
    if (!in_array($errno, [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR])) {
        return false; // Dejar que PHP maneje notices y warnings normalmente
    }

    // =============================================================
    // CORREGIDO (Caso 6): Registrar error REAL en log del servidor
    // =============================================================
    // error_log() escribe en el archivo de log configurado en php.ini.
    // Solo el administrador del servidor puede acceder a este archivo.
    // El error incluye: nivel, mensaje, archivo, linea, fecha/hora.
    // =============================================================

    error_log("PHP Error [$errno]: $errstr in $errfile on line $errline");

    // =============================================================
    // CORREGIDO (Caso 6): Redirigir a pagina de error generica
    // =============================================================
    // El usuario NUNCA ve el error tecnico. Solo ve una pagina
    // amigable con un mensaje generico y codigo HTTP 500.
    //
    // VULNERABLE: La version anterior mostraba el error directamente:
    //   "Parse error: syntax error, unexpected '=' in C:\xampp\htdocs..."
    //
    // Ahora el usuario ve:
    //   "Ha ocurrido un error. Por favor intenta mas tarde."
    // =============================================================

    http_response_code(500);
    require __DIR__ . '/error_generico.php';
    exit;
});

// =============================================================
// CORREGIDO (Caso 6): Manejador global de excepciones no capturadas
// =============================================================
// set_exception_handler() captura excepciones que NO fueron
// atrapadas por ningun try/catch en el codigo. Sin esto, una
// excepcion no manejada causaria un error fatal de PHP que se
// mostraria al usuario (si display_errors esta ON) o generaria
// una pagina de error generica del servidor (sin informacion
// util para debug, pero tampoco registration).
//
// Ahora capturamos la excepcion, la registramos, y mostramos
// la pagina de error generica con HTTP 500.
// =============================================================

set_exception_handler(function (Throwable $exception) {

    // =============================================================
    // CORREGIDO (Caso 6 + Caso 8): Registrar excepcion completa
    // =============================================================
    // El detalle tecnico completo se guarda en:
    //   1. error_log() → archivo de log del servidor
    //   2. logs_seguridad → tabla de auditoria (si PDO esta disponible)
    //
    // NUNCA se muestra al usuario.
    // =============================================================

    error_log("Excepcion no manejada: " . $exception->getMessage() .
              " in " . $exception->getFile() .
              " on line " . $exception->getLine() .
              "\nStack trace:\n" . $exception->getTraceAsString());

    // Intentar registrar en logs_seguridad si PDO esta disponible
    if (isset($pdo) && $pdo instanceof PDO) {
        try {
            $stmt = $pdo->prepare(
                "INSERT INTO logs_seguridad (tipo_evento, usuario, ip, detalle)
                 VALUES (:tipo, :usuario, :ip, :detalle)"
            );
            $stmt->execute([
                ':tipo'    => 'error_sistema',
                ':usuario' => $_SESSION['usuario'] ?? null,
                ':ip'      => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
                ':detalle' => "Excepcion: " . $exception->getMessage() .
                              " | Archivo: " . $exception->getFile() .
                              " | Linea: " . $exception->getLine(),
            ]);
        } catch (PDOException $e) {
            // Si falla el registro en BD, al menos queda en error_log
            error_log("Error al registrar excepcion en logs_seguridad: " . $e->getMessage());
        }
    }

    http_response_code(500);
    require __DIR__ . '/error_generico.php';
    exit;
});

// =============================================================
// CORREGIDO (Caso 6): Manejador de errores fatales al shutdown
// =============================================================
// register_shutdown_function() se ejecuta SIEMPRE, incluso cuando
// PHP termina con un error fatal (out of memory, stack overflow, etc.).
// Verifica si el script termino con un error fatal y lo maneja.
// =============================================================

register_shutdown_function(function () {
    $error = error_get_last();

    if ($error !== null && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {

        error_log("PHP Fatal Error: " . $error['message'] .
                  " in " . $error['file'] .
                  " on line " . $error['line']);

        // Solo mostrar la pagina de error si no se ya mostro antes
        if (http_response_code() === 200 || http_response_code() === 0) {
            http_response_code(500);
            require __DIR__ . '/error_generico.php';
        }
    }
});
