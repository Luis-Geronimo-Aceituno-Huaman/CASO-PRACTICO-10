<?php
/**
 * panel_logs.php - Panel de auditoria de seguridad (VERSION CORREGIDA)
 * CASO PRACTICO 10 - FastMarket S.A.C.
 *
 * CORREGIDO (Caso 8 - Logging y monitoreo):
 * Panel exclusivo para administradores que muestra los ultimos 50
 * eventos de seguridad registrados en la tabla logs_seguridad.
 *
 * Cubre los 4 tipos de eventos solicitados por el Caso 8:
 *   1. intento_fallido  → Intentos fallidos de login
 *   2. cambio_password  → Cambios de contrasena
 *   3. acceso_admin     → Accesos de administradores
 *   4. modificacion_producto → Modificaciones de productos
 *
 * Acceso restringido: solo usuarios con rol='admin'.
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
// CORREGIDO (Caso 3 + Caso 8): Verificar sesion y rol de admin
// =============================================================
// VULNERABLE: La version anterior no tenia panel de logs. No habia
// forma de auditar la actividad de seguridad del sistema.
//
// Ahora, este panel SOLO es accesible para usuarios con rol='admin'.
// Se reutiliza la logica de verificacion de autorizacion del Caso 3.
// =============================================================

if (!isset($_SESSION['id_usuario'])) {
    header('Location: login.php');
    exit;
}

if ($_SESSION['rol'] !== 'admin') {
    // =============================================================
    // CORREGIDO (Caso 3 + Caso 6): Denegar acceso sin revelar info
    // =============================================================
    // No decimos "Acceso solo para administradores" porque eso revelaria
    // que existe un panel de admin. Mensaje generico igual que perfil.php.
    // =============================================================
    registrarEvento($pdo, 'intento_sospechoso', $_SESSION['usuario'],
        "Intento de acceso no autorizado al panel de logs");

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
            <nav><a href="perfil.php">Volver al perfil</a></nav>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// =============================================================
// CORREGIDO (Caso 8): Obtener los ultimos 50 eventos
// =============================================================
// Se consultan los ultimos 50 registros de logs_seguridad,
// ordenados del mas reciente al mas antiguo.
//
// VULNERABLE: La version anterior no tenia esta tabla ni este panel.
// No habia forma de:
//   - Detectar intentos de fuerza bruta
//   - Auditar accesos de administradores
//   - Rastrear cambios de contrasena
//   - Monitorear modificaciones de productos
// =============================================================

try {
    $stmt = $pdo->prepare(
        "SELECT id, tipo_evento, usuario, ip, detalle, fecha
         FROM logs_seguridad
         ORDER BY fecha DESC
         LIMIT 50"
    );
    $stmt->execute();
    $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("panel_logs.php - Error al consultar logs: " . $e->getMessage());
    $logs = [];
    $error_logs = 'Error al cargar los registros de seguridad.';
}

// Colores para cada tipo de evento (para la interfaz)
$colores_evento = [
    'intento_fallido'       => '#e74c3c',  // Rojo
    'cambio_password'       => '#f39c12',  // Naranja
    'acceso_admin'          => '#3498db',  // Azul
    'modificacion_producto' => '#27ae60',  // Verde
    'intento_sospechoso'    => '#e74c3c',  // Rojo
    'acceso_exitoso'        => '#27ae60',  // Verde
    'bloqueo_temporal'      => '#8e44ad',  // Morado
    'error_sistema'         => '#95a5a6',  // Gris
];

// Iconos/emojis para cada tipo de evento
$iconos_evento = [
    'intento_fallido'       => '&#x1f6ab;',  // Prohibido
    'cambio_password'       => '&#x1f511;',  // Llave
    'acceso_admin'          => '&#x1f6e1;',  // Escudo
    'modificacion_producto' => '&#x270f;',   // Lapiz
    'intento_sospechoso'    => '&#x26a0;',   // Advertencia
    'acceso_exitoso'        => '&#x2714;',   // Check
    'bloqueo_temporal'      => '&#x1f512;',  // Cerradura
    'error_sistema'         => '&#x26a0;',   // Advertencia
];
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Panel de Seguridad - FastMarket</title>
    <link rel="stylesheet" href="style.css">
    <style>
        .log-filters { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 20px; }
        .log-filters a { padding: 6px 12px; border-radius: 4px; text-decoration: none; font-size: 0.85em; color: #fff; }
        .log-table { width: 100%; border-collapse: collapse; font-size: 0.9em; }
        .log-table th { background: #2c3e50; color: #fff; padding: 10px 8px; text-align: left; }
        .log-table td { padding: 8px; border-bottom: 1px solid #eee; }
        .log-table tr:hover { background: #f8f9fa; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 3px; color: #fff; font-size: 0.8em; font-weight: bold; }
        .detail-cell { max-width: 300px; word-break: break-word; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Panel de Seguridad</h1>

        <div style="background:#e8f5e9;border-left:4px solid #27ae60;padding:15px;border-radius:5px;margin-bottom:20px;">
            <strong style="color:#27ae60;">CORREGIDO (Caso 8 - Logging y monitoreo):</strong>
            <p style="margin:5px 0 0 0;color:#555;">
                Este panel muestra los ultimos 50 eventos de seguridad registrados.
                Acceso restringido a administradores. Los 4 tipos de eventos del Caso 8:
                intentos fallidos de login, cambios de contrasena, accesos de admin,
                y modificaciones de productos.
            </p>
        </div>

        <!-- Filtros por tipo de evento -->
        <div class="log-filters">
            <a href="?filtro=todos" style="background:#34495e;">Todos</a>
            <a href="?filtro=intento_fallido" style="background:#e74c3c;">Intentos fallidos</a>
            <a href="?filtro=cambio_password" style="background:#f39c12;">Cambios de contrasena</a>
            <a href="?filtro=acceso_admin" style="background:#3498db;">Accesos admin</a>
            <a href="?filtro=modificacion_producto" style="background:#27ae60;">Mod. productos</a>
        </div>

        <?php if (isset($error_logs)): ?>
            <p class="error"><?php echo htmlspecialchars($error_logs, ENT_QUOTES, 'UTF-8'); ?></p>
        <?php endif; ?>

        <?php
        // Aplicar filtro si se especifica
        $filtro = $_GET['filtro'] ?? 'todos';
        $logs_filtrados = $logs;

        if ($filtro !== 'todos') {
            $logs_filtrados = array_filter($logs, function ($log) use ($filtro) {
                return $log['tipo_evento'] === $filtro;
            });
        }
        ?>

        <p style="color:#666;font-size:0.9em;">
            Mostrando <?php echo count($logs_filtrados); ?> eventos
            <?php if ($filtro !== 'todos'): ?>
                del tipo: <strong><?php echo htmlspecialchars($filtro, ENT_QUOTES, 'UTF-8'); ?></strong>
            <?php endif; ?>
        </p>

        <?php if (empty($logs_filtrados)): ?>
            <p>No hay eventos registrados<?php if ($filtro !== 'todos'): ?> para este tipo<?php endif; ?>.</p>
        <?php else: ?>
            <table class="log-table">
                <thead>
                    <tr>
                        <th>Fecha</th>
                        <th>Tipo de evento</th>
                        <th>Usuario</th>
                        <th>IP</th>
                        <th>Detalle</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($logs_filtrados as $log): ?>
                        <tr>
                            <!-- CORREGIDO (Caso 2): htmlspecialchars() en cada campo -->
                            <!-- VULNERABLE: La version anterior no existia este panel -->
                            <td><?php echo htmlspecialchars($log['fecha'], ENT_QUOTES, 'UTF-8'); ?></td>
                            <td>
                                <?php
                                $color = $colores_evento[$log['tipo_evento']] ?? '#95a5a6';
                                $icono = $iconos_evento[$log['tipo_evento']] ?? '';
                                ?>
                                <span class="badge" style="background:<?php echo $color; ?>">
                                    <?php echo $icono . ' ' . htmlspecialchars($log['tipo_evento'], ENT_QUOTES, 'UTF-8'); ?>
                                </span>
                            </td>
                            <td><?php echo htmlspecialchars($log['usuario'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></td>
                            <td><?php echo htmlspecialchars($log['ip'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></td>
                            <td class="detail-cell">
                                <?php echo htmlspecialchars($log['detalle'] ?? '', ENT_QUOTES, 'UTF-8'); ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>

        <!-- Resumen de eventos por tipo -->
        <h2 style="margin-top:30px;">Resumen</h2>
        <div style="display:flex;flex-wrap:wrap;gap:15px;">
            <?php
            $conteo = array_count_values(array_column($logs, 'tipo_evento'));
            $todos_tipos = ['intento_fallido', 'cambio_password', 'acceso_admin', 'modificacion_producto'];
            foreach ($todos_tipos as $tipo):
                $count = $conteo[$tipo] ?? 0;
                $color = $colores_evento[$tipo];
            ?>
                <div style="background:<?php echo $color; ?>22;border-left:4px solid <?php echo $color; ?>;padding:12px 16px;border-radius:4px;min-width:180px;">
                    <strong style="color:<?php echo $color; ?>;"><?php echo $count; ?></strong>
                    <span style="color:#555;">
                        <?php
                        $nombres = [
                            'intento_fallido' => 'Intentos fallidos',
                            'cambio_password' => 'Cambios de contrasena',
                            'acceso_admin' => 'Accesos admin',
                            'modificacion_producto' => 'Mod. productos',
                        ];
                        echo $nombres[$tipo] ?? $tipo;
                        ?>
                    </span>
                </div>
            <?php endforeach; ?>
        </div>

        <nav style="margin-top:30px;">
            <a href="perfil.php">Volver al perfil</a> |
            <a href="productos.php">Gestionar productos</a>
        </nav>
    </div>
</body>
</html>
