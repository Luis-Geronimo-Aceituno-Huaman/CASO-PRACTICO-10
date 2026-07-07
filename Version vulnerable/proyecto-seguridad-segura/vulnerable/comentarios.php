<?php
/**
 * comentarios.php - Sistema de comentarios (VERSION VULNERABLE)
 * CASO PRACTICO 10 - FastMarket S.A.C.
 *
 * Este archivo contiene vulnerabilidades INTENCIONALES para fines educativos.
 * NUNCA usar este codigo en un entorno de produccion.
 *
 * Vulnerabilidades implementadas:
 *   Caso 1  -> SQL Injection en el INSERT (concatenacion directa)
 *   Caso 2  -> XSS almacenado (contenido sin sanitizar se guarda y se muestra)
 *   Caso 10 -> Sin validacion de entrada (acepta todo: scripts, HTML, comillas, etc.)
 */

session_start();
require_once 'conexion.php';

$mensaje = '';

// =============================================================
// VULNERABLE - Caso 2: XSS Almacenado (lectura)
// =============================================================
// Se obtienen todos los comentarios de la BD. El campo `contenido`
// puede contener cualquier cosa: texto plano, etiquetas HTML,
// scripts JavaScript, etc. Esto NO es un problema en si mismo
// (almacenar no es el problema), el problema es que al MOSTRAR
// el contenido se imprime tal cual con echo, sin htmlspecialchars().
// =============================================================

$comentarios = $pdo->query("SELECT c.*, u.usuario, u.nombre
                             FROM comentarios c
                             JOIN usuarios u ON c.id_usuario = u.id
                             ORDER BY c.fecha DESC")->fetchAll(PDO::FETCH_ASSOC);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // CASO 10: Sin sesion obligatoria - cualquier visitante puede comentar
    $id_usuario  = isset($_SESSION['id']) ? $_SESSION['id'] : 0;
    $nombre      = $_POST['nombre']      ?? '';
    $contenido   = $_POST['contenido']   ?? '';
    $id_producto = $_POST['id_producto'] ?? '1';

    // =============================================================
    // VULNERABLE - Caso 10: Sin validacion de entrada
    // =============================================================
    // El formulario NO tiene:
    //   - maxlength en el textarea
    //   - filtro de caracteres especiales
    //   - validacion de tipo de dato
    //   - sanitizacion con htmlspecialchars(), filter_var() o similar
    //
    // El usuario puede ingresar libremente:
    //   - Etiquetas HTML: <b>, <i>, <img>, <iframe>, etc.
    //   - Scripts: <script>alert('XSS')</script>
    //   - Comillas simples y dobles: ' "
    //   - Consultas SQL: ' OR 1=1 --
    //   - Cualquier caracter especial
    //
    // Esto permite tanto XSS como SQL Injection.
    // =============================================================

    // =============================================================
    // VULNERABLE - Caso 1: SQL Injection en INSERT
    // =============================================================
    // Las variables $id_usuario, $id_producto y $contenido se
    // insertan DENTRO de la cadena SQL sin ningun tipo de escape.
    // Un atacante podria manipular $contenido para inyectar SQL
    // adicional, por ejemplo:
    //
    //   contenido: ', (SELECT password FROM usuarios LIMIT 1))--
    //
    // Esto modificaria la consulta INSERT, potencialmente ejecutando
    // subconsultas o extrayendo datos.
    // =============================================================

    $sql = "INSERT INTO comentarios (id_usuario, id_producto, contenido)
            VALUES ($id_usuario, $id_producto, '$contenido')";
    $pdo->query($sql);

    $mensaje = 'Comentario publicado';
    header('Location: comentarios.php');
    exit;
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
            <p class="exito"><?php echo $mensaje; ?></p>
        <?php endif; ?>

        <!-- =========================================================
             VULNERABLE - Caso 10: Formulario sin validacion
             =========================================================
             El textarea NO tiene maxlength, NO tiene filtro de
             caracteres, NO acepta solo texto plano. Un atacante
             puede enviar cualquier cosa.
             ========================================================= -->

        <form method="POST" action="">
            <label>Tu nombre:</label>
            <input type="text" name="nombre" placeholder="Tu nombre" required>

            <label>Producto:</label>
            <select name="id_producto" required>
                <?php foreach ($productos as $prod): ?>
                    <option value="<?php echo $prod['id']; ?>">
                        <?php echo $prod['nombre']; ?>
                    </option>
                <?php endforeach; ?>
            </select>

            <label>Comentario:</label>
            <!-- Sin maxlength, sin filtro, sin validacion -->
            <textarea name="contenido" rows="4"
                      placeholder="Escribe tu comentario aqui..."
                      required></textarea>

            <button type="submit">Publicar</button>
        </form>

        <h2>Comentarios recientes</h2>
        <div class="comentarios">
            <?php if (empty($comentarios)): ?>
                <p>No hay comentarios aun.</p>
            <?php else: ?>
                <?php foreach ($comentarios as $com): ?>
                    <div class="comentario">
                        <strong><?php echo $com['nombre']; ?></strong>
                        <span class="producto">en <?php echo $com['id_producto']; ?></span>

                        <!--
                            VULNERABLE - Caso 2: XSS Almacenado (renderizado)
                            
                            Aqui se imprime el contenido del comentario DIRECTAMENTE
                            con echo, SIN usar htmlspecialchars().
                            
                            Si un usuario envio:  <script>alert('Hack')</script>
                            ese script se guardo tal cual en la BD y ahora se
                            imprime en el HTML. El navegador lo interpreta y EJECUTA
                            el JavaScript en el contexto de la pagina.
                            
                            Esto significa que un atacante puede:
                            - Robar cookies de sesion (session hijacking)
                            - Redirigir a sitios maliciosos
                            - Modificar el contenido de la pagina (defacement)
                            - Ejecutar acciones en nombre del usuario
                            
                            NOTA: htmlspecialchars($comentario, ENT_QUOTES, 'UTF-8')
                            habria convertido < en &lt; y > en &gt;, haciendo que
                            el navegador muestre el texto literal sin ejecutarlo.
                        -->
                        <p><?php echo $com['contenido']; ?></p>

                        <small><?php echo $com['fecha']; ?></small>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <p><a href="perfil.php">Volver al perfil</a></p>
    </div>
</body>
</html>
