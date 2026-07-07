<?php
/**
 * error_demo.php - Demostracion de errores (VERSION VULNERABLE)
 * CASO PRACTICO 10 - FastMarket S.A.C.
 *
 * Este archivo contiene vulnerabilidades INTENCIONALES para fines educativos.
 * NUNCA usar este codigo en un entorno de produccion.
 *
 * Vulnerabilidades implementadas:
 *   Caso 6  -> Security Misconfiguration: errores PHP/MySQL expuestos al usuario
 *              con informacion tecnica completa (version, rutas, estructura SQL).
 *              Un atacante usa esta informacion para mapear la BD y el stack tecnologico.
 */

// VULNERABLE: display_errors esta habilitado por defecto en XAMPP/Laragon
// Si estuviera deshabilitado (display_errors = Off), el error se guardaria
// solo en el log del servidor y NO se mostraria al usuario.
// La configuracion insegura permite que PHP imprima errores fatales en pantalla.

require_once 'conexion.php';

$mensaje     = '';
$tipo_error  = '';
$detalle     = '';

// =============================================================
// VULNERABLE: se exponen multiples tipos de error SQL al usuario
// =============================================================

if (isset($_GET['error'])) {

    $tipo_error = $_GET['error'];

    try {

        switch ($tipo_error) {

            // ---------------------------------------------------
            // Error 1: Consultar una tabla que NO existe
            // ---------------------------------------------------
            // Esto provoca un PDOException con el mensaje completo:
            //   "SQLSTATE[42S02]: Base table or view not found: 1146
            //    Table 'fastmarket_db.tabla_inexistente' doesn't exist"
            //
            // La tabla 'tabla_inexistente' no existe en la BD.
            // El error revela:
            //   - Nombre de la base de datos (fastmarket_db)
            //   - Nombre de la tabla consultada
            //   - Codigo de error MySQL (42S02)
            // ---------------------------------------------------
            case 'tabla':
                $sql = "SELECT * FROM tabla_inexistente";
                $pdo->query($sql);
                break;

            // ---------------------------------------------------
            // Error 2: Syntax error por comilla simple sin cerrar
            // ---------------------------------------------------
            // Simula un SQL Injection mal formado que rompe la
            // sintaxis de la consulta. El error muestra:
            //   - La consulta SQL completa con la variable insertada
            //   - La posicion del error de sintaxis
            //   - Codigo de error MySQL (42000)
            //
            // Ejemplo de payload que el usuario puede probar:
            //   error_demo.php?error=syntax&buscar=admin'
            // ---------------------------------------------------
            case 'syntax':
                $buscar = $_GET['buscar'] ?? "admin'";
                $sql    = "SELECT * FROM usuarios WHERE usuario = '$buscar'";
                $pdo->query($sql);
                break;

            // ---------------------------------------------------
            // Error 3: Consulta con columna inexistente
            // ---------------------------------------------------
            // El error revela las columnas que SI existen en la tabla,
            // lo que permite al atacante mapear la estructura:
            //   "Unknown column 'password_hash' in 'field list'"
            // ---------------------------------------------------
            case 'columna':
                $sql = "SELECT password_hash FROM usuarios WHERE id = 1";
                $pdo->query($sql);
                break;

            // ---------------------------------------------------
            // Error 4: INSERT con tipos de dato incompatibles
            // ---------------------------------------------------
            // El error revela el tipo de dato esperado en la columna:
            //   "Incorrect integer value: 'texto' for column 'id'"
            // ---------------------------------------------------
            case 'tipo':
                $sql = "INSERT INTO usuarios (id, nombre) VALUES ('texto', 'test')";
                $pdo->query($sql);
                break;

            // ---------------------------------------------------
            // Error 5: Dividir por cero en SQL (genera warning)
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
        // VULNERABLE - Caso 6: Se expone TODO el error al usuario
        // =============================================================
        //
        // Lo que se muestra al atacante:
        //
        // 1. MENSAJE DE ERROR COMPLETO de PDO:
        //    Incluye: codigo SQLSTATE, mensaje de MySQL, numero de error.
        //    Ejemplo: "SQLSTATE[42S02]: Base table or view not found:
        //              1146 Table 'fastmarket_db.tabla_inexistente' doesn't exist"
        //
        // 2. CODIGO DE ERROR MySQL:
        //    Permite al atacante identificar el tipo exacto de problema
        //    y buscar exploits o tecnicas especificas.
        //
        // 3. CONSULTA SQL COMPLETA:
        //    En errores de sintaxis, se muestra la query con la variable
        //    insertada, revelando la estructura de la tabla y las columnas.
        //
        // En un entorno SEGURO, se deberia:
        //   - Mostrar solo: "Ocurrio un error. Intente mas tarde."
        //   - Guardar el error completo en un log interno (error_log())
        //   - Nunca mostrar errores de BD al usuario final
        //
        // VULNERABLE: expone informacion tecnica interna del servidor (Security Misconfiguration - Caso 6), que un atacante puede usar para mapear la BD o el stack tecnologico
        // =============================================================

        $mensaje   = $e->getMessage();
        $detalle   = $e->getCode();
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
        <p style="color:#e74c3c;margin-bottom:15px;">
            Esta pagina muestra intencionalmente errores SQL con toda la informacion tecnica.
            Un atacante usa esta informacion para mapear la base de datos y el stack tecnologico.
        </p>

        <!-- Botones para provocar cada tipo de error -->
        <h2>Provokear errores:</h2>
        <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:20px;">
            <a href="?error=tabla"
               style="padding:8px 12px;background:#e74c3c;color:#fff;border-radius:4px;text-decoration:none;font-size:0.9em;">
                Tabla inexistente
            </a>
            <a href="?error=syntax"
               style="padding:8px 12px;background:#e67e22;color:#fff;border-radius:4px;text-decoration:none;font-size:0.9em;">
                Error de sintaxis
            </a>
            <a href="?error=columna"
               style="padding:8px 12px;background:#9b59b6;color:#fff;border-radius:4px;text-decoration:none;font-size:0.9em;">
                Columna inexistente
            </a>
            <a href="?error=tipo"
               style="padding:8px 12px;background:#3498db;color:#fff;border-radius:4px;text-decoration:none;font-size:0.9em;">
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
                 VULNERABLE: se muestra el error COMPLETO de PDO/MySQL
                 ============================================================= -->
            <div class="error-box" style="margin-top:20px;">
                <h3 style="color:#e74c3c;">ERROR SQL --<?php echo htmlspecialchars($tipo_error); ?>---</h3>

                <!-- Error completo de PDO/MySQL -->
                <pre style="background:#2c3e50;color:#e74c3c;padding:15px;border-radius:5px;overflow-x:auto;font-size:13px;"><?php echo $mensaje; ?></pre>

                <!-- Codigo de error MySQL -->
                <?php if ($detalle): ?>
                    <p><strong>Codigo de error:</strong> <?php echo $detalle; ?></p>
                <?php endif; ?>

                <hr style="margin:15px 0;">

                <!-- =============================================================
                     VULNERABLE: informacion tecnica del servidor expuesta
                     =============================================================
                     Un atacante usa estos datos para:
                     - Conocer la version de PHP (buscar vulnerabilidades conocidas)
                     - Conocer el servidor web (Apache, Nginx, etc.)
                     - Conocer la ruta absoluta del proyecto en el servidor
                     - Conocer la estructura de la BD (nombre, tablas, columnas)
                     - Conocer el usuario de BD (usualmente root en dev)
                     ============================================================= -->

                <h4>Informacion expuesta del servidor:</h4>
                <table style="width:100%;border-collapse:collapse;font-size:0.9em;">
                    <tr style="background:#f8f9fa;">
                        <td style="padding:8px;border:1px solid #ddd;font-weight:bold;">PHP Version</td>
                        <td style="padding:8px;border:1px solid #ddd;"><code><?php echo phpversion(); ?></code></td>
                    </tr>
                    <tr>
                        <td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Servidor Web</td>
                        <td style="padding:8px;border:1px solid #ddd;"><code><?php echo $_SERVER['SERVER_SOFTWARE'] ?? 'N/A'; ?></code></td>
                    </tr>
                    <tr style="background:#f8f9fa;">
                        <td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Ruta absoluta del archivo</td>
                        <td style="padding:8px;border:1px solid #ddd;"><code><?php echo __FILE__; ?></code></td>
                    </tr>
                    <tr>
                        <td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Base de datos</td>
                        <td style="padding:8px;border:1px solid #ddd;"><code>fastmarket_db</code></td>
                    </tr>
                    <tr style="background:#f8f9fa;">
                        <td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Motor BD</td>
                        <td style="padding:8px;border:1px solid #ddd;"><code><?php echo $pdo->query('SELECT VERSION()')->fetchColumn(); ?></code></td>
                    </tr>
                    <tr>
                        <td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Usuario BD</td>
                        <td style="padding:8px;border:1px solid #ddd;"><code>root</code></td>
                    </tr>
                </table>
            </div>
        <?php endif; ?>

        <p style="margin-top:20px;"><a href="perfil.php">Volver al perfil</a></p>
    </div>
</body>
</html>
