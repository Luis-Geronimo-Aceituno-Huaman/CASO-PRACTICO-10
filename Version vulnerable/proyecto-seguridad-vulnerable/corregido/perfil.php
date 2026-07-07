<?php
/**
 * perfil.php - Perfil de usuario (VERSION CORREGIDA)
 * CASO PRACTICO 10 - FastMarket S.A.C.
 * 
 * Mejoras de seguridad:
 * - Verificacion de sesion obligatoria
 * - Control de acceso: solo ver propio perfil (o admin ve cualquier uno)
 * - Prepared statements
 * - htmlspecialchars() en salida
 */

session_start();
require_once 'conexion.php';

// Verificar sesion activa
if (!isset($_SESSION['usuario'])) {
    header('Location: login.php');
    exit;
}

// Obtener el ID del usuario logueado
$id_sesion = $_SESSION['id'];
$rol       = $_SESSION['rol'];

// Un cliente solo ve su propio perfil; admin puede ver cualquier perfil
if ($rol === 'admin' && isset($_GET['id'])) {
    $id = filter_var($_GET['id'], FILTER_VALIDATE_INT);
} else {
    $id = $id_sesion;
}

// Prepared statement
$stmt = $pdo->prepare("SELECT * FROM usuarios WHERE id = :id");
$stmt->execute(['id' => $id]);
$usuario = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$usuario) {
    die("Usuario no encontrado");
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
        <h1>Mi Perfil</h1>
        <div class="perfil">
            <p><strong>Nombre:</strong> <?php echo htmlspecialchars($usuario['nombre']); ?></p>
            <p><strong>Email:</strong> <?php echo htmlspecialchars($usuario['email']); ?></p>
            <p><strong>Usuario:</strong> <?php echo htmlspecialchars($usuario['usuario']); ?></p>
            <p><strong>Rol:</strong> <?php echo htmlspecialchars($usuario['rol']); ?></p>
            <p><strong>Registro:</strong> <?php echo $usuario['fecha_registro']; ?></p>
        </div>
        <nav>
            <a href="comentarios.php">Comentarios</a> |
            <a href="upload.php">Subir imagen</a> |
            <a href="login.php">Cerrar sesion</a>
        </nav>
    </div>
</body>
</html>
