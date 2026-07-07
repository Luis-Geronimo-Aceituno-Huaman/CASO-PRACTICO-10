<?php
/**
 * registro.php - Registro de usuarios (VERSION VULNERABLE)
 * CASO PRACTICO 10 - FastMarket S.A.C.
 * 
 * Vulnerabilidades intencionales:
 * - SQL Injection por concatenacion
 * - Contraseñas en texto plano (Caso 9)
 * - Sin validacion de entrada (Caso 10)
 * - Sin sanitizacion de datos
 */

require_once 'conexion.php';

$mensaje = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $nombre   = $_POST['nombre']   ?? '';
    $email    = $_POST['email']    ?? '';
    $usuario  = $_POST['usuario']  ?? '';
    $password = $_POST['password'] ?? '';

    // CASO 10: Sin validacion de caracteres especiales, HTML, scripts
    // CASO 9: Password en texto plano - NO se usa password_hash()
    $sql = "INSERT INTO usuarios (nombre, email, usuario, password, rol)
            VALUES ('$nombre', '$email', '$usuario', '$password', 'cliente')";
    
    if ($pdo->query($sql)) {
        $mensaje = 'Registro exitoso';
    } else {
        $mensaje = 'Error al registrar';
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registro - FastMarket</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Registro de Usuario</h1>
        <?php if ($mensaje): ?>
            <p class="error"><?php echo $mensaje; ?></p>
        <?php endif; ?>
        <form method="POST">
            <label>Nombre:</label>
            <input type="text" name="nombre" required>
            <label>Email:</label>
            <input type="email" name="email" required>
            <label>Usuario:</label>
            <input type="text" name="usuario" required>
            <label>Contrasena:</label>
            <input type="password" name="password" required>
            <button type="submit">Registrarse</button>
        </form>
        <p><a href="login.php">Volver al login</a></p>
    </div>
</body>
</html>
