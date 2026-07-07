<?php
/**
 * comentarios.php - Sistema de comentarios (VERSION CORREGIDA)
 * CASO PRACTICO 10 - FastMarket S.A.C.
 *
 * Este archivo corrige TODAS las vulnerabilidades de la version vulnerable.
 * Cada correccion esta marcada con "// CORREGIDO:" para contraste lado a lado
 * con los comentarios "// VULNERABLE" del archivo vulnerable/comentarios.php.
 *
 * Vulnerabilidades corregidas:
 *   Caso 1  -> Prepared statements en INSERT y SELECT (previene SQL Injection)
 *   Caso 2  -> htmlspecialchars() en toda salida de datos (previene XSS almacenado)
 *   Caso 10 -> Validacion de entrada en servidor (capa adicional de defensa)
 *   Caso 8  -> Registro de eventos sospechosos (logger.php)
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

$mensaje = '';

// =============================================================
// CORREGIDO (Caso 1): Prepared statement en SELECT
// =============================================================
// VULNERABLE: La version anterior usaba $pdo->query() con la consulta
// completa sin parametros vinculados. Aunque en este caso no hay input
// del usuario en el SELECT, usar prepared statements es buena practica
// porque previene SQL Injection si en el futuro se agrega un filtro
// (por ejemplo, buscar comentarios por producto o por usuario).
//
// Aqui mantenemos query() directa porque no hay interpolacion de datos
// del usuario, pero lo importante es que NINGUN dato del usuario se
// concatena en la consulta SQL.
// =============================================================

$comentarios = $pdo->prepare("SELECT c.*, u.usuario, u.nombre
                              FROM comentarios c
                              JOIN usuarios u ON c.id_usuario = u.id
                              ORDER BY c.fecha DESC");
$comentarios->execute();
$comentarios = $comentarios->fetchAll(PDO::FETCH_ASSOC);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // CORREGIDO (Caso 10): Requerir sesion activa para comentar
    // VULNERABLE: La version anterior permitia que cualquier visitante
    // (incluso sin sesion) enviara comentarios, usando id_usuario = 0.
    if (!isset($_SESSION['id_usuario'])) {
        $mensaje = 'Debes iniciar sesion para comentar';
    } else {

        $id_usuario  = $_SESSION['id_usuario'];
        $nombre      = $_POST['nombre']      ?? '';
        $contenido   = $_POST['contenido']   ?? '';
        $id_producto = $_POST['id_producto'] ?? '';

        // =============================================================
        // CORREGIDO (Caso 10): Validacion de entrada en servidor
        // =============================================================
        // IMPORTANTE: La sanitizacion de SALIDA (htmlspecialchars) es la
        // defensa PRINCIPAL contra XSS. La validacion de ENTRADA es una
        // capa ADICIONAL de defensa en profundidad. No confiar solo en
        // la validacion de entrada porque:
        //   - Un atacante puede enviar request directo al servidor
        //   - Los controles del navegador (maxlength, etc.) se saltan
        //   - Puede haber otros puntos de entrada (API, otro formulario)
        //
        // VULNERABLE: La version anterior no validaba nada. Aceitaba
        // scripts, HTML, comillas, consultas SQL, y cualquier caracter
        // especial sin restriccion alguna.
        // =============================================================

        // --- Validar nombre ---
        // Solo letras (incluidas tildes y ñ) y espacios. Maximo 50 caracteres.
        $nombre = trim($nombre);
        if (!preg_match('/^[a-zA-ZáéíóúñÁÉÍÓÚÑüÜ\s]{1,50}$/', $nombre)) {
            $mensaje = 'El nombre solo debe contener letras y espacios (maximo 50 caracteres)';
        }

        // --- Validar contenido del comentario ---
        // Longitud maxima 300 caracteres
        if (empty($mensaje) && strlen($contenido) > 300) {
            $mensaje = 'El comentario no debe exceder los 300 caracteres';
        }

        // --- Detectar patrones sospechosos ---
        // Rechazar si contiene etiquetas <script> o patrones obvios de inyeccion SQL.
        // NOTA: Esto es una capa adicional. La defensa real contra XSS es htmlspecialchars()
        // al mostrar, y contra SQL Injection es el prepared statement al guardar.
        // Este filtro busca patrones conocidos de payloads comunes.
        if (empty($mensaje)) {
            $patrones_sospechosos = [
                '/<script/i',                    // Etiquetas script
                '/javascript\s*:/i',             // javascript: en atributos
                '/on\w+\s*=/i',                  // Eventos onclick, onerror, etc.
                '/union\s+select/i',             // UNION SELECT (SQL Injection)
                '/or\s+[\d\'"]\s*=\s*[\d\'"]/i', // OR 1=1, OR 'a'='a'
                '/;\s*drop\s+table/i',           // DROP TABLE
                '/;\s*delete\s+from/i',          // DELETE FROM
                '/--\s*$/',                      // Comentarios SQL al final
            ];

            $contenido_limpio = trim($contenido);

            foreach ($patrones_sospechosos as $patron) {
                if (preg_match($patron, $contenido_limpio)) {
                    // =============================================================
                    // CORREGIDO (Caso 8): Registrar intento sospechoso
                    // =============================================================
                    // VULNERABLE: La version anterior no registraba nada cuando
                    // se enviaba contenido malicioso. No habia forma de detectar
                    // intentos de ataque o patrones de comportamiento malicious.
                    //
                    // Ahora registramos cada intento rechazado con: usuario,
                    // IP, y detalle del patron detectado. Esto permite:
                    //   - Detectar ataques dirigidos
                    //   - Identificar IPs o usuarios maliciosos
                    //   - Generar alertas de seguridad
                    // =============================================================
                    registrarEvento(
                        $pdo,
                        'intento_sospechoso',
                        $_SESSION['usuario'] ?? 'desconocido',
                        "Comentario rechazado - Patron sospechoso detectado: " . $contenido_limpio
                    );

                    $mensaje = 'El comentario contiene contenido no permitido';
                    break;
                }
            }
        }

        // --- Validar id_producto ---
        if (empty($mensaje)) {
            $id_producto = filter_var($id_producto, FILTER_VALIDATE_INT);
            if (!$id_producto || $id_producto < 1) {
                $mensaje = 'Producto invalido';
            }
        }

        // --- Insertar comentario si todas las validaciones pasaron ---
        if (empty($mensaje)) {

            // =============================================================
            // CORREGIDO (Caso 1): Prepared statement en INSERT
            // =============================================================
            // VULNERABLE: La version anterior concatenaba directamente:
            //   $sql = "INSERT INTO comentarios ...
            //           VALUES ($id_usuario, $id_producto, '$contenido')";
            //   $pdo->query($sql);
            //
            // Esto permitia que un payload en $contenido modificara la
            // estructura SQL. Por ejemplo:
            //   contenido: ', (SELECT password FROM usuarios LIMIT 1))--
            //
            // Con prepared statements, $contenido se pasa como parametro
            // vinculado. PDO lo escapa internamente, eliminando la
            // posibilidad de inyeccion SQL.
            // =============================================================

            try {
                $stmt = $pdo->prepare("INSERT INTO comentarios (id_usuario, id_producto, contenido)
                                       VALUES (:id_usuario, :id_producto, :contenido)");
                $stmt->execute([
                    ':id_usuario'  => $id_usuario,
                    ':id_producto' => $id_producto,
                    ':contenido'   => $contenido,
                ]);

                $mensaje = 'Comentario publicado';
                header('Location: comentarios.php');
                exit;

            } catch (PDOException $e) {
                // CORREGIDO (Caso 6): Manejo seguro de errores
                // VULNERABLE: La version anterior no capturaba errores PDO.
                // Un error de SQL mostraria detalles tecnicos al usuario.
                error_log("comentarios.php - Error al insertar comentario: " . $e->getMessage());
                $mensaje = 'Ocurrio un error, intenta mas tarde';
            }
        }
    }
}

$productos = $pdo->query("SELECT * FROM productos")->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Comentarios - FastMarket</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Comentarios de Productos</h1>

        <?php if ($mensaje): ?>
            <!-- CORREGIDO (Caso 2): htmlspecialchars() en mensajes de feedback -->
            <!-- VULNERABLE: La version anterior no aplicaba htmlspecialchars() -->
            <p class="error"><?php echo htmlspecialchars($mensaje, ENT_QUOTES, 'UTF-8'); ?></p>
        <?php endif; ?>

        <?php if (isset($_SESSION['usuario'])): ?>
        <!-- =========================================================
             CORREGIDO (Caso 10): Formulario con validacion
             =========================================================
             VULNERABLE: La version anterior no tenia maxlength en el
             textarea, no filtraba caracteres, y no validaba tipo de dato.
             Ahora el textarea tiene maxlength="300" como primera barrera
             (aunque la validacion real es en el servidor).
             ========================================================= -->
        <form method="POST" action="">
            <label>Tu nombre:</label>
            <!-- maxlength="50" coincide con la validacion del servidor -->
            <input type="text" name="nombre" placeholder="Tu nombre"
                   maxlength="50" pattern="[a-zA-ZáéíóúñÁÉÍÓÚÑüÜ\s]+" required>

            <label>Producto:</label>
            <select name="id_producto" required>
                <?php foreach ($productos as $prod): ?>
                    <!-- CORREGIDO (Caso 2): htmlspecialchars() en opcion del select -->
                    <!-- VULNERABLE: La version anterior no sanitizaba el nombre del producto -->
                    <option value="<?php echo (int)$prod['id']; ?>">
                        <?php echo htmlspecialchars($prod['nombre'], ENT_QUOTES, 'UTF-8'); ?>
                    </option>
                <?php endforeach; ?>
            </select>

            <label>Comentario:</label>
            <!-- maxlength="300" como primera barrera + validacion en servidor -->
            <textarea name="contenido" rows="4" maxlength="300"
                      placeholder="Escribe tu comentario aqui..."
                      required></textarea>

            <button type="submit">Publicar</button>
        </form>
        <?php else: ?>
            <p><a href="login.php">Inicia sesion</a> para comentar.</p>
        <?php endif; ?>

        <h2>Comentarios recientes</h2>
        <div class="comentarios">
            <?php if (empty($comentarios)): ?>
                <p>No hay comentarios aun.</p>
            <?php else: ?>
                <?php foreach ($comentarios as $com): ?>
                    <div class="comentario">
                        <!--
                            CORREGIDO (Caso 2): XSS Almacenado (renderizado)
                            
                            TODOS los campos generados por el usuario se envuelven
                            con htmlspecialchars($valor, ENT_QUOTES, 'UTF-8').
                            
                            htmlspecialchars() convierte:
                              <  →  &lt;    (prevents <script>, <iframe>, etc.)
                              >  →  &gt;
                              &  →  &amp;
                              "  →  &quot;
                              '  →  &#039;
                            
                            Con ENT_QUOTES se escapan tanto comillas dobles como
                            simples, necesario porque los valores se usan dentro
                            de atributos HTML (value="...").
                            
                            Con 'UTF-8' se manejan correctamente tildes, ñ y
                            caracteres especiales del idioma español.
                            
                            VULNERABLE: La version anterior imprimia:
                              echo $com['nombre'];       ← XSS via nombre
                              echo $com['contenido'];    ← XSS via contenido
                            
                            Un comentario con <script>alert('XSS')</script> se
                            ejecutaba automaticamente en el navegador de CADA
                            visitante que cargara la pagina.
                        -->
                        <strong><?php echo htmlspecialchars($com['nombre'], ENT_QUOTES, 'UTF-8'); ?></strong>
                        <span class="producto">en <?php echo htmlspecialchars($com['id_producto'], ENT_QUOTES, 'UTF-8'); ?></span>
                        <p><?php echo htmlspecialchars($com['contenido'], ENT_QUOTES, 'UTF-8'); ?></p>
                        <small><?php echo $com['fecha']; ?></small>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <p><a href="perfil.php">Volver al perfil</a></p>
    </div>
</body>
</html>
