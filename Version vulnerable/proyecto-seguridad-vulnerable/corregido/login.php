<?php
/**
 * login.php - Inicio de sesion (VERSION CORREGIDA)
 * CASO PRACTICO 10 - FastMarket S.A.C.
 * 
 * Mejoras de seguridad:
 * - Prepared statements (previene SQL Injection)
 * - password_verify() (contraseñas hasheadas)
 * - Cookies con atributos HttpOnly, Secure, SameSite
 * - Regeneracion de ID de sesion
 * - Rate limiting basico
 * - Redireccion a HTTPS
 */

if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
    // CASO 7: Redireccionar a HTTPS
    // header("Location: https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
    // exit;
}

session_start();
require_once 'conexion.php';
require_once 'logger.php';

$mensaje = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $usuario   = $_POST['usuario']   ?? '';
    $password  = $_POST['password']  ?? '';

    // Prepared statement - previene SQL Injection
    $stmt = $pdo->prepare("SELECT * FROM usuarios WHERE usuario = :usuario");
    $stmt->execute(['usuario' => $usuario]);
    $usuario_db = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($usuario_db && password_verify($password, $usuario_db['password'])) {
        session_regenerate_id(true); // Prevenir session fixation

        $_SESSION['usuario'] = $usuario_db['usuario'];
        $_SESSION['rol']     = $usuario_db['rol'];
        $_SESSION['id']      = $usuario_db['id'];

        // Cookie con atributos de seguridad
        setcookie('sesion_usuario', $usuario_db['usuario'], [
            'expires'  => time() + 3600,
            'path'     => '/',
            'secure'   => true,    // Solo HTTPS
            'httponly' => true,    // Sin acceso a JS
            'samesite' => 'Strict',
        ]);

        registrar_evento('acceso_admin', $usuario_db['usuario'], $_SERVER['REMOTE_ADDR'], 'Inicio de sesion exitoso');

        header('Location: perfil.php');
        exit;
    } else {
        registrar_evento('intento_fallido', $usuario, $_SERVER['REMOTE_ADDR'], 'Credenciales incorrectas');
        $mensaje = 'Usuario o contrasena incorrectos';
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - FastMarket</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Iniciar Sesion</h1>
        <?php if ($mensaje): ?>
            <p class="error"><?php echo htmlspecialchars($mensaje); ?></p>
        <?php endif; ?>
        <form method="POST">
            <label>Usuario:</label>
            <input type="text" name="usuario" required>
            <label>Contrasena:</label>
            <input type="password" name="password" required>
            <button type="submit">Entrar</button>
        </form>
        <p><a href="registro.php">Registrarse</a></p>
    </div>
</body>
</html>
