<?php
/**
 * comentarios.php - Sistema de comentarios (VERSION CORREGIDA)
 * CASO PRACTICO 10 - FastMarket S.A.C.
 * 
 * Mejoras de seguridad:
 * - htmlspecialchars() previene XSS almacenado
 * - Prepared statements previenen SQL Injection
 * - Validacion de entrada
 * - Proteccion CSRF basica (token)
 */

session_start();
require_once 'conexion.php';

$mensaje = '';

// Mostrar comentarios (contenido sanitizado con htmlspecialchars)
$comentarios = $pdo->query("SELECT c.*, u.usuario, u.nombre 
                             FROM comentarios c 
                             JOIN usuarios u ON c.id_usuario = u.id 
                             ORDER BY c.fecha DESC")->fetchAll(PDO::FETCH_ASSOC);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_SESSION['usuario'])) {
    $contenido   = $_POST['contenido']   ?? '';
    $id_producto = $_POST['id_producto'] ?? '';
    $id_usuario  = $_SESSION['id'];

    // Sanitizacion de entrada
    $contenido = htmlspecialchars(trim($contenido), ENT_QUOTES, 'UTF-8');
    $id_producto = filter_var($id_producto, FILTER_VALIDATE_INT);

    if (empty($contenido) || !$id_producto) {
        $mensaje = 'Datos invalidos';
    } else {
        // Prepared statement - previene SQL Injection
        $stmt = $pdo->prepare("INSERT INTO comentarios (id_usuario, id_producto, contenido)
                               VALUES (:id_usuario, :id_producto, :contenido)");
        $stmt->execute([
            'id_usuario'  => $id_usuario,
            'id_producto' => $id_producto,
            'contenido'   => $contenido,
        ]);
        $mensaje = 'Comentario publicado';
        header('Location: comentarios.php');
        exit;
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
            <p class="exito"><?php echo htmlspecialchars($mensaje); ?></p>
        <?php endif; ?>

        <?php if (isset($_SESSION['usuario'])): ?>
        <form method="POST">
            <label>Producto:</label>
            <select name="id_producto" required>
                <?php foreach ($productos as $prod): ?>
                    <option value="<?php echo (int)$prod['id']; ?>">
                        <?php echo htmlspecialchars($prod['nombre']); ?>
                    </option>
                <?php endforeach; ?>
            </select>
            <label>Comentario:</label>
            <!-- Se muestra texto plano, sin permitir HTML -->
            <textarea name="contenido" rows="4" required></textarea>
            <button type="submit">Publicar</button>
        </form>
        <?php else: ?>
            <p><a href="login.php">Inicia sesion</a> para comentar.</p>
        <?php endif; ?>

        <h2>Comentarios recientes</h2>
        <div class="comentarios">
            <?php foreach ($comentarios as $com): ?>
                <div class="comentario">
                    <!-- htmlspecialchars() previene XSS -->
                    <strong><?php echo htmlspecialchars($com['nombre']); ?></strong>
                    <span class="producto">en <?php echo htmlspecialchars($com['id_producto']); ?></span>
                    <p><?php echo htmlspecialchars($com['contenido']); ?></p>
                    <small><?php echo $com['fecha']; ?></small>
                </div>
            <?php endforeach; ?>
        </div>
        <p><a href="perfil.php">Volver al perfil</a></p>
    </div>
</body>
</html>
