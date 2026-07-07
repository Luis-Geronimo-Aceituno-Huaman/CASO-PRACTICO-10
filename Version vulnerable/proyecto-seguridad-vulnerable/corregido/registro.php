<?php
/**
 * registro.php - Registro de usuarios (VERSION CORREGIDA)
 * CASO PRACTICO 10 - FastMarket S.A.C.
 * 
 * Mejoras de seguridad:
 * - Prepared statements (previene SQL Injection)
 * - password_hash() para contraseñas (Caso 9)
 * - Validacion y sanitizacion de entrada (Caso 10)
 * - Sanitizacion con htmlspecialchars()
 */

require_once 'conexion.php';

$mensaje = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $nombre   = $_POST['nombre']   ?? '';
    $email    = $_POST['email']    ?? '';
    $usuario  = $_POST['usuario']  ?? '';
    $password = $_POST['password'] ?? '';

    // Validaciones de entrada
    $nombre   = filter_var(trim($nombre), FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    $email    = filter_var(trim($email), FILTER_VALIDATE_EMAIL);
    $usuario  = filter_var(trim($usuario), FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    
    if (strlen($password) < 8) {
        $mensaje = 'La contrasena debe tener al menos 8 caracteres';
    } elseif (!$email) {
        $mensaje = 'El correo electronico no es valido';
    } elseif (empty($nombre) || empty($usuario)) {
        $mensaje = 'Todos los campos son obligatorios';
    } else {
        // Hash de contraseña con password_hash()
        $password_hash = password_hash($password, PASSWORD_DEFAULT);

        // Prepared statement - previene SQL Injection
        $stmt = $pdo->prepare("INSERT INTO usuarios (nombre, email, usuario, password, rol)
                               VALUES (:nombre, :email, :usuario, :password, 'cliente')");
        
        if ($stmt->execute([
            'nombre'   => $nombre,
            'email'    => $email,
            'usuario'  => $usuario,
            'password' => $password_hash,
        ])) {
            $mensaje = 'Registro exitoso';
        } else {
            $mensaje = 'Error al registrar';
        }
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
            <p class="error"><?php echo htmlspecialchars($mensaje); ?></p>
        <?php endif; ?>
        <form method="POST">
            <label>Nombre:</label>
            <input type="text" name="nombre" required>
            <label>Email:</label>
            <input type="email" name="email" required>
            <label>Usuario:</label>
            <input type="text" name="usuario" required>
            <label>Contrasena (minimo 8 caracteres):</label>
            <input type="password" name="password" minlength="8" required>
            <button type="submit">Registrarse</button>
        </form>
        <p><a href="login.php">Volver al login</a></p>
    </div>
</body>
</html>
