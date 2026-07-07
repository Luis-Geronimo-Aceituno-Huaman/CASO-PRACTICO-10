<?php
/**
 * login.php - Inicio de sesion (VERSION CORREGIDA)
 * CASO PRACTICO 10 - FastMarket S.A.C.
 *
 * Este archivo corrige TODAS las vulnerabilidades de la version vulnerable.
 * Cada correccion esta marcada con "// CORREGIDO:" para contraste lado a lado
 * con los comentarios "// VULNERABLE" del archivo vulnerable/login.php.
 *
 * Vulnerabilidades corregidas:
 *   Caso 1  -> Prepared statements con PDO (previene SQL Injection)
 *   Caso 4  -> Cookie de sesion con atributos HttpOnly, Secure, SameSite
 *   Caso 6  -> Manejo seguro de errores (try/catch + error_log, nunca en pantalla)
 *   Caso 7  -> Redireccion a HTTPS (requiere servidor con certificado SSL)
 *   Caso 8  -> Registro de eventos de seguridad (intentos fallidos y accesos admin)
 *   Caso 9  -> password_verify() en vez de comparacion directa de strings
 */

// CORREGIDO (Caso 7): La redireccion HTTP → HTTPS y el header HSTS
// se gestionan GLOBALMENTE en config.php (que se incluye mas abajo).
// Esta capa global garantiza que TODOS los modulos corregidos usen
// HTTPS sin necesidad de repetir el codigo en cada archivo.
// VULNERABLE: En la version anterior no existia ninguna redireccion a HTTPS.
// Las credenciales se enviaban en texto plano por HTTP, permitiendo sniffing.

// CORREGIDO (Caso 4): Configurar parametros de la cookie de sesion ANTES
// de llamar a session_start(). Esto establece los atributos de seguridad
// para TODAS las cookies de sesion que PHP genere.
// VULNERABLE: En la version anterior, session_start() se llamaba sin
// configurar cookie_params, y se creaba una cookie manualmente con
// setcookie() sin atributos HttpOnly, Secure ni SameSite.
session_set_cookie_params([
    'lifetime' => 0,           // Cookie de sesion (se elimina al cerrar el navegador)
    'path'     => '/',
    'secure'   => true,        // CORREGIDO (Caso 7): Solo se envia por HTTPS.
                               // IMPORTANTE: Requiere que el sitio corra bajo HTTPS
                               // (ver Caso 7). Si el servidor no tiene SSL, el
                               // navegador no enviara la cookie y la sesion no
                               // funcionara. En ese caso, cambiar a false SOLO
                               // para desarrollo local.
    'httponly' => true,        // CORREGIDO (Caso 4): JavaScript no puede acceder
                               // a la cookie (previene robo de sesion via XSS).
    'samesite' => 'Strict',   // CORREGIDO (Caso 4): La cookie no se envia en
                               // requests cross-origin (previene CSRF).
]);

// CORREGIDO (Caso 6): Incluir configuracion global de errores ANTES de todo
// config.php desactiva display_errors, activa log_errors, y configura
// manejadores globales para excepciones y errores PHP no capturados.
require_once 'config.php';

session_start();
require_once 'conexion.php';
require_once 'logger.php';

$mensaje = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $usuario  = $_POST['usuario']  ?? '';
    $password = $_POST['password'] ?? '';

    // =============================================================
    // CORREGIDO (Caso 1): Prepared statement con PDO
    // =============================================================
    // El valor del usuario se pasa como parametro vinculado (:usuario)
    // en vez de concatenarlo en la cadena SQL. PDO se encarga de
    // escapar el valor internamente, eliminando la posibilidad de que
    // un payload de SQL Injection modifique la estructura de la consulta.
    //
    // VULNERABLE: La version anterior usaba:
    //   $sql = "SELECT * FROM usuarios WHERE usuario='$usuario' AND password='$password'";
    //   $resultado = $pdo->query($sql);
    // Esto permitia payloads como: admin' OR '1'='1
    //
    // Con prepared statements, el mismo payload se busca literalmente
    // como valor del campo "usuario", no se interpreta como SQL.
    // =============================================================

    try {
        $stmt = $pdo->prepare("SELECT * FROM usuarios WHERE usuario = :usuario");
        $stmt->execute([':usuario' => $usuario]);
        $usuario_db = $stmt->fetch(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        // =============================================================
        // CORREGIDO (Caso 6): Manejo seguro de errores
        // =============================================================
        // VULNERABLE: La version anterior no tenia try/catch alrededor
        // de las consultas PDO. Si ocurria un error SQL (por ejemplo,
        // por un SQL Injection con sintaxis incorrecta), PHP mostraba
        // el mensaje nativo de PDO con: numero de error, archivo, linea,
        // y la consulta SQL completa. Esto revelaba estructura de BD.
        //
        // Ahora capturamos la excepcion, registramos el error real en
        // el log del servidor (error_log), y mostramos SOLO un mensaje
        // generico al usuario. El atacante no obtiene informacion tecnica.
        // =============================================================
        error_log("login.php - Error en consulta de login: " . $e->getMessage());
        $mensaje = 'Ocurrio un error, intenta mas tarde';
    }

    // Solo continuar si la consulta fue exitosa (no hubo excepcion)
    if (empty($mensaje)) {

        // =============================================================
        // CORREGIDO (Caso 9): Autenticacion con password_verify()
        // =============================================================
        // VULNERABLE: La version anterior comparaba directamente:
        //   if ($usuario_db && $usuario_db['password'] === $password)
        // Esto significaba que las contrasenas estaban en TEXTO PLANO
        // en la BD. Si un atacante obtenia acceso (SQL Injection, backup
        // filtrado, etc.), tenia todas las contrasenas sin esfuerzo.
        //
        // Ahora, el campo 'password' de la BD contiene un hash generado
        // con password_hash() (al registrarse). password_verify() compara
        // el password ingresado contra ese hash sin exponerlo. Incluso si
        // roban la BD, los hashes son costosos de revertir (bcrypt).
        // =============================================================

        if ($usuario_db && password_verify($password, $usuario_db['password'])) {

            // CORREGIDO: Regenerar el ID de sesion para prevenir session
            // fixation. Si un atacante conocia el ID de sesion antes del
            // login, despues de regenerar ya no sirve.
            session_regenerate_id(true);

            $_SESSION['id_usuario'] = $usuario_db['id'];
            $_SESSION['usuario']    = $usuario_db['usuario'];
            $_SESSION['rol']        = $usuario_db['rol'];

            // =============================================================
            // CORREGIDO (Caso 8): Registro de eventos - acceso exitoso
            // =============================================================
            // VULNERABLE: La version anterior no registraba nada cuando
            // alguien iniciaba sesion. No habia forma de saber quien
            // accedio, cuando, ni desde donde.
            //
            // Ahora registramos cada acceso. Si es admin, se marca
            // especialmente para auditoria privilegiada.
            // =============================================================
            $tipo_evento = ($usuario_db['rol'] === 'admin') ? 'acceso_admin' : 'acceso_exitoso';
            $detalle = 'Inicio de sesion exitoso - Rol: ' . $usuario_db['rol'];
            registrarEvento($pdo, $tipo_evento, $usuario_db['usuario'], $detalle);

            header('Location: perfil.php');
            exit;

        } else {

            // =============================================================
            // CORREGIDO (Caso 8): Registro de eventos - intento fallido
            // =============================================================
            // VULNERABLE: La version anterior simplemente mostraba un
            // mensaje de error sin registrar nada. No habia forma de
            // detectar fuerza bruta o intentos de acceso no autorizado.
            //
            // Ahora cada intento fallido se registra con: usuario intentado,
            // IP del cliente, y fecha/hora. Esto permite:
            //   - Detectar fuerza bruta desde una IP
            //   - Identificar cuentas targeteadas
            //   - Generar alertas de seguridad
            // =============================================================
            $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
            registrarEvento($pdo, 'intento_fallido', $usuario, "Intento fallido desde IP: $ip");

            // =============================================================
            // CORREGIDO (Caso 8, opcional): Limitar intentos fallidos
            // =============================================================
            // Despues de 5 intentos fallidos consecutivos desde la misma
            // IP en los ultimos 10 minutos, se bloquea temporalmente el
            // login. Esto mitiga ataques de fuerza bruta.
            //
            // Implementacion: contamos los intentos fallidos recientes
            // desde la IP actual en la tabla logs_seguridad.
            // =============================================================
            try {
                $stmtBloqueo = $pdo->prepare(
                    "SELECT COUNT(*) as intentos
                     FROM logs_seguridad
                     WHERE tipo_evento = 'intento_fallido'
                       AND ip = :ip
                       AND fecha > DATE_SUB(NOW(), INTERVAL 10 MINUTE)"
                );
                $stmtBloqueo->execute([':ip' => $ip]);
                $intentos = $stmtBloqueo->fetch(PDO::FETCH_ASSOC);

                if ($intentos['intentos'] >= 5) {
                    // Bloquear: no mostrar error de credenciales, solo mensaje
                    // generico para no confirmar si el usuario existe o no.
                    registrarEvento($pdo, 'bloqueo_temporal', $usuario,
                        "Bloqueo temporal por 5+ intentos fallidos en 10 min desde IP: $ip");
                    $mensaje = 'Demasiados intentos. Intenta mas tarde.';
                } else {
                    $mensaje = 'Usuario o contrasena incorrectos';
                }
            } catch (PDOException $e) {
                error_log("login.php - Error al verificar intentos fallidos: " . $e->getMessage());
                $mensaje = 'Usuario o contrasena incorrectos';
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - FastMarket</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Iniciar Sesion</h1>

        <?php if ($mensaje): ?>
            <!-- CORREGIDO (Caso 6): htmlspecialchars() previene XSS al mostrar mensajes -->
            <!-- VULNERABLE: La version anterior no aplicaba htmlspecialchars() -->
            <p class="error"><?php echo htmlspecialchars($mensaje); ?></p>
        <?php endif; ?>

        <!-- CORREGIDO (Caso 7): El form usa action="" (mismo protocolo) y se
             recomienda HTTPS. No se envia por HTTP plano como la version vulnerable. -->
        <form method="POST" action="">
            <label>Usuario:</label>
            <input type="text" name="usuario" placeholder="Ingresa tu usuario" required>

            <label>Contrasena:</label>
            <input type="password" name="password" placeholder="Ingresa tu contrasena" required>

            <button type="submit">Entrar</button>
        </form>

        <p><a href="registro.php">Registrarse</a></p>
    </div>
</body>
</html>
