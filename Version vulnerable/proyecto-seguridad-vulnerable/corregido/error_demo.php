<?php
/**
 * error_demo.php - Demostracion de errores (VERSION CORREGIDA)
 * CASO PRACTICO 10 - FastMarket S.A.C.
 * 
 * Mejoras de seguridad:
 * - Mensajes de error genericos sin info tecnica
 * - Errores registrados en log interno, no mostrados al usuario
 * - Sin exponer: version PHP, rutas, credenciales de BD
 */

require_once 'conexion.php';

$mensaje = '';

if (isset($_GET['buscar'])) {
    $buscar = $_GET['buscar'];
    
    // Prepared statement - previene SQL Injection
    try {
        $stmt = $pdo->prepare("SELECT * FROM usuarios WHERE usuario = :usuario");
        $stmt->execute(['usuario' => $buscar]);
        $resultado = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        // Mensaje generico - NO se expone info tecnica
        error_log("Error en busqueda de usuario: " . $e->getMessage());
        $mensaje = "Ocurrio un error al procesar la busqueda.";
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Busqueda - FastMarket</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Busqueda de Usuarios</h1>
        <form method="GET">
            <label>Buscar usuario:</label>
            <input type="text" name="buscar" placeholder="Nombre de usuario">
            <button type="submit">Buscar</button>
        </form>

        <?php if ($mensaje): ?>
            <div class="error-box">
                <p class="error"><?php echo htmlspecialchars($mensaje); ?></p>
            </div>
        <?php endif; ?>

        <?php if (isset($resultado) && $resultado): ?>
            <h2>Resultados:</h2>
            <?php foreach ($resultado as $fila): ?>
                <div class="usuario">
                    <p><strong>Usuario:</strong> <?php echo htmlspecialchars($fila['usuario']); ?></p>
                    <p><strong>Nombre:</strong> <?php echo htmlspecialchars($fila['nombre']); ?></p>
                </div>
            <?php endforeach; ?>
        <?php endif; ?>

        <p><a href="perfil.php">Volver al perfil</a></p>
    </div>
</body>
</html>
