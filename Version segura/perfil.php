<?php
/**
 * perfil.php - Perfil de usuario (VERSION CORREGIDA)
 * CASO PRACTICO 10 - FastMarket S.A.C.
 *
 * Este archivo corrige TODAS las vulnerabilidades de la version vulnerable.
 * Cada correccion esta marcada con "// CORREGIDO:" para contraste lado a lado
 * con los comentarios "// VULNERABLE" del archivo vulnerable/perfil.php.
 *
 * Vulnerabilidades corregidas:
 *   Caso 3  -> Broken Access Control / IDOR (verificacion de sesion y autorizacion)
 *   Caso 1  -> Prepared statements en SELECT (previene SQL Injection)
 *   Caso 8  -> Registro de eventos (accesos admin y accesos no autorizados)
 *   Caso 2  -> htmlspecialchars() en toda salida (previene XSS)
 *   Caso 6  -> Mensajes genericos sin revelar informacion tecnica
 */

// CORREGIDO (Caso 6): Incluir configuracion global de errores ANTES de todo
require_once 'config.php';

// CORREGIDO (Caso 4): Configurar parametros de la cookie de sesion ANTES
// de session_start(). Mismos atributos de seguridad que login.php.
// VULNERABLE: session_start() sin configurar cookie_params.
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'secure'   => true,
    'httponly' => true,
    'samesite' => 'Strict',
]);

session_start();
require_once 'conexion.php';
require_once 'logger.php';

// =============================================================
// CORREGIDO (Caso 3): Verificar sesion activa
// =============================================================
// VULNERABLE: La version anterior NO verificaba si existia una sesion
// activa. Cualquier visitante (incluso sin loguearse) podia acceder
// directamente a perfil.php?id=1 y ver los datos del usuario.
//
// Ahora, si no hay $_SESSION['id_usuario'], se redirige al login.
// Esto es la primera barrera: sin sesion, no hay acceso.
// =============================================================

if (!isset($_SESSION['id_usuario'])) {
    header('Location: login.php');
    exit;
}

// =============================================================
// CORREGIDO (Caso 3): Verificar autorizacion (IDOR)
// =============================================================
// El parametro ?id= de la URL indica QUE perfil se quiere ver.
// Debemos verificar que el usuario autenticado TENGA DERECHO
// a ver ese perfil. Las reglas son:
//
//   1. Un cliente normal SOLO puede ver su propio perfil.
//      Es decir, $_GET['id'] debe coincidir con $_SESSION['id_usuario'].
//
//   2. Un admin puede ver CUALQUIER perfil, pero eso se registra
//      en logs_seguridad para auditoria.
//
//   3. Si un cliente intenta ver un id que no le corresponde,
//      se deniega el acceso y se registra como intento sospechoso.
//
// VULNERABLE: La version anterior NO verificaba nada.
// Un usuario con id=2 podia cambiar la URL a ?id=1 y ver los
// datos del admin. Esto es un ataque IDOR (Insecure Direct
// Object Reference): simplemente se modifica el identificador
// directo en la URL para acceder a objetos (perfiles) ajenos.
//
// Ejemplo de ataque en la version vulnerable:
//   1. juan (id=2) se loguea y accede a perfil.php?id=2
//   2. Cambia la URL a perfil.php?id=1 (el admin)
//   3. Ve todos los datos del admin: nombre, email, rol, etc.
//   4. Sin ninguna restriccion ni registro.
// =============================================================

// Obtener y validar el ID solicitado desde la URL
$id_solicitado = filter_var($_GET['id'] ?? $_SESSION['id_usuario'], FILTER_VALIDATE_INT);

// Si el id no es numerico valido, usar el id de la sesion
if ($id_solicitado === false) {
    $id_solicitado = $_SESSION['id_usuario'];
}

$id_sesion = $_SESSION['id_usuario'];
$rol       = $_SESSION['rol'];

// Verificar autorizacion: ¿el usuario tiene derecho a ver este perfil?
if ($id_solicitado != $id_sesion && $rol !== 'admin') {

    // =============================================================
    // CORREGIDO (Caso 3 + Caso 8): Denegar acceso y registrar
    // =============================================================
    // VULNERABLE: La version anterior simplemente mostraba los datos
    // sin verificar nada. No habia denegacion ni registro.
    //
    // Ahora:
    //   1. Se retorna HTTP 403 (Forbidden)
    //   2. Se muestra un mensaje GENERICO (no revela si el id existe)
    //   3. Se registra el intento en logs_seguridad
    //
    // IMPORTANTE: El mensaje es deliberadamente generico. No decimos
    // "Usuario no encontrado" porque eso revelaria si el id solicitado
    // existe o no. Tampoco decimos "No tienes acceso a este perfil"
    // porque eso confirmaria que hay un perfil con ese id. El mensaje
    // "No tienes permiso para ver este recurso" es ambiguo: no confirma
    // ni niega la existencia del recurso.
    // =============================================================

    registrarEvento(
        $pdo,
        'intento_sospechoso',
        $_SESSION['usuario'],
        "Intento de acceso no autorizado - Usuario ID $id_sesion intento ver perfil ID $id_solicitado"
    );

    // Retornar HTTP 403 Forbidden
    http_response_code(403);
    ?>
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Acceso denegado - FastMarket</title>
        <link rel="stylesheet" href="style.css">
    </head>
    <body>
        <div class="container">
            <h1>Acceso denegado</h1>
            <!-- CORREGIDO (Caso 6): Mensaje generico, sin revelar informacion tecnica -->
            <!-- VULNERABLE: La version anterior nunca denegaba el acceso -->
            <p class="error">No tienes permiso para ver este recurso.</p>
            <nav>
                <a href="perfil.php?id=<?php echo $id_sesion; ?>">Ver mi perfil</a> |
                <a href="login.php">Cerrar sesion</a>
            </nav>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// =============================================================
// CORREGIDO (Caso 8): Registrar acceso de admin a perfil ajeno
// =============================================================
// VULNERABLE: La version anterior no registraba nada cuando un admin
// veia el perfil de otro usuario. No habia forma de auditar quien
// accedio a que perfil y cuando.
//
// Ahora, si un admin accede al perfil de OTRO usuario, se registra
// en logs_seguridad con tipo_evento = 'acceso_admin'. Esto permite:
//   - Auditar el uso de privilegios de administrador
//   - Detectar abusos de acceso
//   - Mantener un registro de compliance
// =============================================================

if ($rol === 'admin' && $id_solicitado != $id_sesion) {
    $nombre_objetivo = ''; // Se llenara despues de la consulta
}

// =============================================================
// CORREGIDO (Caso 1): Prepared statement en SELECT
// =============================================================
// VULNERABLE: La version anterior concatenaba el id directamente:
//   $sql = "SELECT * FROM usuarios WHERE id = $id";
//   $usuario = $pdo->query($sql)->fetch(PDO::FETCH_ASSOC);
//
// Esto permitia payloads como:
//   ?id=1 OR 1=1
//   ?id=1 UNION SELECT 1,2,3,4,5,6,7,8--
//
// Con prepared statements, el id se pasa como parametro vinculado.
// PDO lo escapa internamente, eliminando la inyeccion SQL.
// =============================================================

try {
    $stmt = $pdo->prepare("SELECT * FROM usuarios WHERE id = :id");
    $stmt->execute([':id' => $id_solicitado]);
    $usuario = $stmt->fetch(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    // CORREGIDO (Caso 6): Manejo seguro de errores
    // VULNERABLE: La version anterior no capturaba errores PDO.
    error_log("perfil.php - Error al consultar perfil: " . $e->getMessage());
    $usuario = null;
}

// =============================================================
// CORREGIDO (Caso 6): Manejo seguro de "usuario no encontrado"
// =============================================================
// VULNERABLE: La version anterior usaba die("Usuario no encontrado"),
// lo cual revelaba que el id solicitado NO existe en la BD.
//
// Ahora, si el usuario no existe, mostramos el mismo mensaje generico
// "No tienes permiso para ver este recurso" sin revelar si el id
// existe o no. Esto aplica incluso para admins.
// =============================================================

if (!$usuario) {
    http_response_code(403);
    ?>
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Acceso denegado - FastMarket</title>
        <link rel="stylesheet" href="style.css">
    </head>
    <body>
        <div class="container">
            <h1>Acceso denegado</h1>
            <p class="error">No tienes permiso para ver este recurso.</p>
            <nav>
                <a href="perfil.php?id=<?php echo $id_sesion; ?>">Ver mi perfil</a> |
                <a href="login.php">Cerrar sesion</a>
            </nav>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// Si es admin viendo perfil ajeno, registrar el acceso ahora que tenemos el nombre
if ($rol === 'admin' && $id_solicitado != $id_sesion) {
    registrarEvento(
        $pdo,
        'acceso_admin',
        $_SESSION['usuario'],
        "Admin " . $_SESSION['usuario'] . " vio perfil de " . $usuario['usuario'] . " (ID: $id_solicitado)"
    );
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Perfil - FastMarket</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>
            <?php
            // CORREGIDO (Caso 6): Titel dinamico sin revelar informacion innecesaria
            // Si es admin viendo perfil ajeno, muestra "Perfil de [usuario]"
            // Si es el propio perfil, muestra "Mi Perfil"
            if ($rol === 'admin' && $id_solicitado != $id_sesion) {
                echo 'Perfil de ' . htmlspecialchars($usuario['usuario'], ENT_QUOTES, 'UTF-8');
            } else {
                echo 'Mi Perfil';
            }
            ?>
        </h1>

        <!--
            CORREGIDO (Caso 2 + Caso 3): XSS + Access Control

            TODOS los campos del perfil se muestran con htmlspecialchars()
            para prevenir XSS. Pero ademas, estos datos SOLO se muestran
            porque ya pasamos la verificacion de autorizacion arriba.

            VULNERABLE: La version anterior mostraba los datos SIN
            htmlspecialchars() y SIN verificar que el usuario tuviera
            derecho a verlos.
        -->
        <div class="perfil">
            <p><strong>Nombre:</strong>
                <?php echo htmlspecialchars($usuario['nombre'], ENT_QUOTES, 'UTF-8'); ?></p>
            <p><strong>Email:</strong>
                <?php echo htmlspecialchars($usuario['email'], ENT_QUOTES, 'UTF-8'); ?></p>
            <p><strong>Usuario:</strong>
                <?php echo htmlspecialchars($usuario['usuario'], ENT_QUOTES, 'UTF-8'); ?></p>
            <p><strong>Rol:</strong>
                <?php echo htmlspecialchars($usuario['rol'], ENT_QUOTES, 'UTF-8'); ?></p>
            <p><strong>Fecha registro:</strong>
                <?php echo htmlspecialchars($usuario['fecha_registro'], ENT_QUOTES, 'UTF-8'); ?></p>
        </div>

        <!--
            CORREGIDO: Info de la sesion actual.
            VULNERABLE: La version anterior mostraba "Sesion activa: [usuario]"
            incluso cuando el visitante NO tenia sesion, revelando que el
            sistema no validaba autenticacion.
        -->
        <div style="background:#f8f9fa;padding:10px;border-radius:5px;margin-bottom:15px;font-size:0.9em;">
            <strong>Sesion activa:</strong>
            <?php echo htmlspecialchars($_SESSION['usuario'], ENT_QUOTES, 'UTF-8'); ?>
            (ID: <?php echo $id_sesion; ?>, Rol: <?php echo htmlspecialchars($rol, ENT_QUOTES, 'UTF-8'); ?>)
            <?php if ($rol === 'admin' && $id_solicitado != $id_sesion): ?>
                &mdash; <em>Viendo perfil de otro usuario (acceso admin registrado)</em>
            <?php endif; ?>
        </div>

        <nav>
            <a href="comentarios.php">Comentarios</a> |
            <a href="upload.php">Subir imagen</a> |
            <a href="login.php">Cerrar sesion</a>
        </nav>
    </div>
</body>
</html>
