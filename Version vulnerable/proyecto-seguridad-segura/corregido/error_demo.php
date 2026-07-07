<?php
/**
 * error_demo.php - Demostracion de errores (VERSION CORREGIDA)
 * CASO PRACTICO 10 - FastMarket S.A.C.
 *
 * Este archivo corrige TODAS las vulnerabilidades de la version vulnerable.
 * Cada correccion esta marcada con "// CORREGIDO:" para contraste lado a lado
 * con los comentarios "// VULNERABLE" del archivo vulnerable/error_demo.php.
 *
 * Vulnerabilidades corregidas:
 *   Caso 6  -> display_errors OFF, error_log activo, mensajes genericos
 *              Sin exponer version PHP, rutas, estructura BD, ni queries
 *
 * Este archivo demuestra como los MISMOS errores del Caso 6 ahora se
 * manejan de forma segura: el usuario solo ve un mensaje generico,
 * mientras el detalle tecnico queda registrado internamente.
 */

// =============================================================
// CORREGIDO (Caso 6): Incluir configuracion global de errores
// =============================================================
// config.php configura:
//   - display_errors = OFF (nunca mostrar errores en pantalla)
//   - log_errors = ON (registrar en archivo del servidor)
//   - set_exception_handler() para excepciones no capturadas
//   - set_error_handler() para errores PHP no fatales
//
// VULNERABLE: La version anterior no tenia ningun manejador global.
// Los errores se mostraban directamente al usuario.
// =============================================================

require_once 'config.php';
require_once 'conexion.php';

$mensaje = '';

// =============================================================
// CORREGIDO (Caso 6): Todos los errores se manejan con try/catch
// =============================================================
// VULNERABLE: La version anterior capturaba el error pero mostraba
// $e->getMessage() y $e->getCode() DIRECTAMENTE al usuario:
//
//   $mensaje = $e->getMessage();  ← esto expone el error completo
//   $detalle = $e->getCode();    ← esto expone el codigo SQLSTATE
//
// El usuario veia algo como:
//   "SQLSTATE[42S02]: Base table or view not found: 1146
//    Table 'fastmarket_db.tabla_inexistente' doesn't exist"
//
// Esto revela: nombre de BD, nombre de tabla, codigo de error MySQL.
//
// Ahora, CADA operacion PDO esta envuelta en try/catch, y el catch:
//   1. Registra el error COMPLETO en error_log() (para el admin)
//   2. Registra en logs_seguridad con tipo 'error_sistema'
//   3. Muestra SOLO un mensaje GENERICO al usuario
// =============================================================

if (isset($_GET['error'])) {

    $tipo_error = $_GET['error'];

    try {

        switch ($tipo_error) {

            // ---------------------------------------------------
            // Error 1: Consultar una tabla que NO existe
            // ---------------------------------------------------
            // VULNERABLE mostraba:
            //   "SQLSTATE[42S02]: Base table or view not found: 1146
            //    Table 'fastmarket_db.tabla_inexistente' doesn't exist"
            //
            // CORREGIDO: el usuario solo ve "Ha ocurrido un error"
            // el detalle queda en error_log()
            // ---------------------------------------------------
            case 'tabla':
                $sql = "SELECT * FROM tabla_inexistente";
                $pdo->query($sql);
                break;

            // ---------------------------------------------------
            // Error 2: Syntax error por comilla simple sin cerrar
            // ---------------------------------------------------
            // VULNERABLE mostraba:
            //   "SQLSTATE[42000]: Syntax error... near 'admin'' at line 1"
            //   + la consulta SQL completa con la variable insertada
            //
            // CORREGIDO: el usuario solo ve "Ha ocurrido un error"
            // el payload del atacante queda registrado en error_log()
            // ---------------------------------------------------
            case 'syntax':
                $buscar = $_GET['buscar'] ?? "admin'";
                $sql    = "SELECT * FROM usuarios WHERE usuario = '$buscar'";
                $pdo->query($sql);
                break;

            // ---------------------------------------------------
            // Error 3: Consulta con columna inexistente
            // ---------------------------------------------------
            // VULNERABLE mostraba:
            //   "Unknown column 'password_hash' in 'field list'"
            //   Esto revela que la columna REAL se llama 'password'
            //
            // CORREGIDO: el usuario solo ve "Ha ocurrido un error"
            // ---------------------------------------------------
            case 'columna':
                $sql = "SELECT password_hash FROM usuarios WHERE id = 1";
                $pdo->query($sql);
                break;

            // ---------------------------------------------------
            // Error 4: INSERT con tipos de dato incompatibles
            // ---------------------------------------------------
            // VULNERABLE mostraba:
            //   "Incorrect integer value: 'texto' for column 'id'"
            //   Esto revela que 'id' es de tipo entero
            //
            // CORREGIDO: el usuario solo ve "Ha ocurrido un error"
            // ---------------------------------------------------
            case 'tipo':
                $sql = "INSERT INTO usuarios (id, nombre) VALUES ('texto', 'test')";
                $pdo->query($sql);
                break;

            // ---------------------------------------------------
            // Error 5: Dividir por cero en SQL
            // ---------------------------------------------------
            // VULNERABLE mostraba un warning de MySQL
            // CORREGIDO: el usuario solo ve "Ha ocurrido un error"
            // ---------------------------------------------------
            case 'math':
                $sql = "SELECT 1/0 AS resultado";
                $pdo->query($sql);
                break;

            default:
                $mensaje = "Tipo de error no reconocido.";
        }

    } catch (PDOException $e) {

        // =============================================================
        // CORREGIDO (Caso 6 + Caso 8): Manejo seguro de errores
        // =============================================================
        //
        // VULNERABLE: La version anterior hacía:
        //
        //   $mensaje = $e->getMessage();   ← ERROR: expone todo
        //   $detalle = $e->getCode();     ← ERROR: expone codigo
        //
        // Y luego imprimía en HTML:
        //   <pre><?php echo $mensaje; ?></pre>  ← el usuario ve el error SQL
        //   <p>Codigo: <?php echo $detalle; ?></p>  ← el usuario ve SQLSTATE
        //
        // Ademas, la version vulnerable mostraba:
        //   - phpversion() → revela version de PHP
        //   - $_SERVER['SERVER_SOFTWARE'] → revela Apache/Nginx
        //   - __FILE__ → revela ruta absoluta del servidor
        //   - SELECT VERSION() → revela version de MySQL
        //   - Usuario de BD → revela 'root'
        //
        // CORREGIDO: Ahora hacemos 3 cosas:
        //
        // 1. error_log() → el error COMPLETO se registra en el archivo
        //    de log del servidor. Solo el admin puede verlo.
        //
        // 2. logs_seguridad → el error se registra en la tabla de
        //    auditoria para analisis de seguridad.
        //
        // 3. Mensaje generico → el usuario ve SOLO "Ha ocurrido un error"
        //    sin NINGUNA informacion tecnica.
        //
        // Comparemos lo que ve cada persona:
        //
        //   ANTES (vulnerable):
        //     USUARIO ve: "SQLSTATE[42S02]: Table 'fastmarket_db.tabla_inexistente'
        //                  doesn't exist" + PHP 8.1.5 + Apache/2.4.51
        //
        //   AHORA (corregido):
        //     USUARIO ve: "Ha ocurrido un error. Por favor intenta mas tarde."
        //     ADMIN ve (en error_log): "[07-Jul-2026 12:00:00] PDO Error: SQLSTATE[42S02]:
        //                  Table 'fastmarket_db.tabla_inexistente' doesn't exist
        //                  in /var/www/html/corregido/error_demo.php on line 65"
        // =============================================================

        // Paso 1: Registrar en error_log() (archivo del servidor)
        error_log("error_demo.php - Error tipo '$tipo_error': " . $e->getMessage());

        // Paso 2: Registrar en logs_seguridad (tabla de auditoria)
        try {
            $stmt = $pdo->prepare(
                "INSERT INTO logs_seguridad (tipo_evento, usuario, ip, detalle)
                 VALUES (:tipo, :usuario, :ip, :detalle)"
            );
            $stmt->execute([
                ':tipo'    => 'error_sistema',
                ':usuario' => $_SESSION['usuario'] ?? null,
                ':ip'      => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
                ':detalle' => "Error tipo '$tipo_error': " . $e->getMessage(),
            ]);
        } catch (PDOException $logEx) {
            // Si falla el registro en BD, al menos queda en error_log
            error_log("error_demo.php - Error al registrar en logs_seguridad: " . $logEx->getMessage());
        }

        // Paso 3: Mensaje GENERICO al usuario (sin info tecnica)
        // =============================================================
        // CORREGIDO (Caso 6): Mensaje deliberadamente generico
        // =============================================================
        // El usuario NO debe saber:
        //   - Si la tabla existe o no
        //   - Si la consulta tiene error de sintaxis
        //   - Si la columna existe o no
        //   - Si el tipo de dato es correcto
        //
        // Cualquier informacion sobre el TIPO de error ayuda al atacante
        // a refinar su ataque. Por eso el mensaje es identico para todos
        // los tipos de error.
        // =============================================================

        $mensaje = 'Ha ocurrido un error. Por favor intenta mas tarde.';
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Demo Errores SQL - FastMarket</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Demostracion de Errores SQL</h1>

        <div style="background:#e8f5e9;border-left:4px solid #27ae60;padding:15px;border-radius:5px;margin-bottom:20px;">
            <strong style="color:#27ae60;">VERSION CORREGIDA</strong>
            <p style="margin:5px 0 0 0;color:#555;">
                Esta pagina ejecuta los MISMOS errores SQL que la version vulnerable,
                pero el usuario solo ve un mensaje generico. El detalle tecnico queda
                registrado en el log del servidor (error_log) y en logs_seguridad.
            </p>
        </div>

        <h2>Provocar errores:</h2>
        <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:20px;">
            <a href="?error=tabla"
               style="padding:8px 12px;background:#27ae60;color:#fff;border-radius:4px;text-decoration:none;font-size:0.9em;">
                Tabla inexistente
            </a>
            <a href="?error=syntax"
               style="padding:8px 12px;background:#27ae60;color:#fff;border-radius:4px;text-decoration:none;font-size:0.9em;">
                Error de sintaxis
            </a>
            <a href="?error=columna"
               style="padding:8px 12px;background:#27ae60;color:#fff;border-radius:4px;text-decoration:none;font-size:0.9em;">
                Columna inexistente
            </a>
            <a href="?error=tipo"
               style="padding:8px 12px;background:#27ae60;color:#fff;border-radius:4px;text-decoration:none;font-size:0.9em;">
                Tipo incompatible
            </a>
            <a href="?error=math"
               style="padding:8px 12px;background:#27ae60;color:#fff;border-radius:4px;text-decoration:none;font-size:0.9em;">
                Division por cero
            </a>
        </div>

        <!-- Busqueda con SQL Injection (para error de sintaxis) -->
        <h2>Busqueda de usuario:</h2>
        <form method="GET">
            <input type="hidden" name="error" value="syntax">
            <label>Buscar:</label>
            <input type="text" name="buscar" placeholder="admin' OR '1'='1" style="width:300px;">
            <button type="submit">Buscar</button>
        </form>

        <?php if ($mensaje): ?>
            <!-- =============================================================
                 CORREGIDO (Caso 6): Mensaje generico sin info tecnica
                 =============================================================
                 VULNERABLE: La version anterior mostraba:
                   <pre>SQLSTATE[42S02]: Table 'fastmarket_db.tabla_inexistente'
                   doesn't exist</pre>
                   <p>Codigo: 42S02</p>
                   + tabla con PHP Version, Server Software, Ruta absoluta,
                     Base de datos, Motor BD, Usuario BD

                 AHORA el usuario ve SOLO:
                   "Ha ocurrido un error. Por favor intenta mas tarde."
                 Sin NINGUNA informacion tecnica.
                 ============================================================= -->
            <div style="background:#fff3cd;border-left:4px solid #ffc107;padding:15px;border-radius:5px;margin-top:20px;">
                <strong style="color:#856404;">Lo que ve el USUARIO:</strong>
                <p style="margin:5px 0 0 0;font-size:1.1em;">
                    <?php echo htmlspecialchars($mensaje, ENT_QUOTES, 'UTF-8'); ?>
                </p>
            </div>

            <div style="background:#f8f9fa;border-left:4px solid #6c757d;padding:15px;border-radius:5px;margin-top:10px;">
                <strong style="color:#6c757d;">Lo que queda registrado en error_log() (solo admin):</strong>
                <pre style="background:#2c3e50;color:#ecf0f1;padding:10px;border-radius:3px;font-size:12px;overflow-x:auto;margin-top:5px;">
[<?php echo date('d-M-Y H:i:s'); ?>] error_demo.php - Error tipo '<?php echo htmlspecialchars($tipo_error, ENT_QUOTES, 'UTF-8'); ?>': [mensaje PDO oculto - visible solo en el log real del servidor]
                </pre>
                <p style="margin:5px 0 0 0;font-size:0.85em;color:#888;">
                    Nota: En produccion, el mensaje PDO real aparece aqui.
                    En esta demostracion, el error se registro via error_log() y logs_seguridad.
                </p>
            </div>

            <div style="background:#e8f5e9;border-left:4px solid #27ae60;padding:15px;border-radius:5px;margin-top:10px;">
                <strong style="color:#27ae60;">Comparacion lado a lado:</strong>
                <table style="width:100%;border-collapse:collapse;margin-top:10px;font-size:0.9em;">
                    <thead>
                        <tr style="background:#c8e6c9;">
                            <th style="padding:8px;border:1px solid #ddd;text-align:left;">Que se expone</th>
                            <th style="padding:8px;border:1px solid #ddd;text-align:center;color:#e74c3c;">VULNERABLE</th>
                            <th style="padding:8px;border:1px solid #ddd;text-align:center;color:#27ae60;">CORREGIDO</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td style="padding:8px;border:1px solid #ddd;">Mensaje de error SQL</td>
                            <td style="padding:8px;border:1px solid #ddd;text-align:center;color:#e74c3c;">SI (completo)</td>
                            <td style="padding:8px;border:1px solid #ddd;text-align:center;color:#27ae60;">NO (generico)</td>
                        </tr>
                        <tr style="background:#f8f9fa;">
                            <td style="padding:8px;border:1px solid #ddd;">Codigo de error SQLSTATE</td>
                            <td style="padding:8px;border:1px solid #ddd;text-align:center;color:#e74c3c;">SI</td>
                            <td style="padding:8px;border:1px solid #ddd;text-align:center;color:#27ae60;">NO</td>
                        </tr>
                        <tr>
                            <td style="padding:8px;border:1px solid #ddd;">Consulta SQL completa</td>
                            <td style="padding:8px;border:1px solid #ddd;text-align:center;color:#e74c3c;">SI (en errores de sintaxis)</td>
                            <td style="padding:8px;border:1px solid #ddd;text-align:center;color:#27ae60;">NO</td>
                        </tr>
                        <tr style="background:#f8f9fa;">
                            <td style="padding:8px;border:1px solid #ddd;">Nombre de BD / tablas / columnas</td>
                            <td style="padding:8px;border:1px solid #ddd;text-align:center;color:#e74c3c;">SI</td>
                            <td style="padding:8px;border:1px solid #ddd;text-align:center;color:#27ae60;">NO</td>
                        </tr>
                        <tr>
                            <td style="padding:8px;border:1px solid #ddd;">Version de PHP</td>
                            <td style="padding:8px;border:1px solid #ddd;text-align:center;color:#e74c3c;">SI (phpversion())</td>
                            <td style="padding:8px;border:1px solid #ddd;text-align:center;color:#27ae60;">NO</td>
                        </tr>
                        <tr style="background:#f8f9fa;">
                            <td style="padding:8px;border:1px solid #ddd;">Servidor web (Apache/Nginx)</td>
                            <td style="padding:8px;border:1px solid #ddd;text-align:center;color:#e74c3c;">SI (SERVER_SOFTWARE)</td>
                            <td style="padding:8px;border:1px solid #ddd;text-align:center;color:#27ae60;">NO</td>
                        </tr>
                        <tr>
                            <td style="padding:8px;border:1px solid #ddd;">Ruta absoluta del servidor</td>
                            <td style="padding:8px;border:1px solid #ddd;text-align:center;color:#e74c3c;">SI (__FILE__)</td>
                            <td style="padding:8px;border:1px solid #ddd;text-align:center;color:#27ae60;">NO</td>
                        </tr>
                        <tr style="background:#f8f9fa;">
                            <td style="padding:8px;border:1px solid #ddd;">Version de MySQL</td>
                            <td style="padding:8px;border:1px solid #ddd;text-align:center;color:#e74c3c;">SI (SELECT VERSION())</td>
                            <td style="padding:8px;border:1px solid #ddd;text-align:center;color:#27ae60;">NO</td>
                        </tr>
                        <tr>
                            <td style="padding:8px;border:1px solid #ddd;">Error registrado internamente</td>
                            <td style="padding:8px;border:1px solid #ddd;text-align:center;color:#e74c3c;">NO (se pierde)</td>
                            <td style="padding:8px;border:1px solid #ddd;text-align:center;color:#27ae60;">SI (error_log + logs_seguridad)</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>

        <p style="margin-top:20px;"><a href="perfil.php">Volver al perfil</a></p>
    </div>
</body>
</html>
