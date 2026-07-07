<?php
/**
 * upload.php - Carga de archivos (VERSION CORREGIDA)
 * CASO PRACTICO 10 - FastMarket S.A.C.
 * 
 * Mejoras de seguridad:
 * - Validacion de extension (solo imagenes permitidas)
 * - Validacion de MIME type real
 * - Limite de tamaño (2MB)
 * - Renombrar archivo con nombre aleatorio
 * - Verificar que es una imagen real
 */

session_start();
$mensaje = '';

// Extensiones permitidas
$extensiones_permitidas = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
$tamano_maximo = 2 * 1024 * 1024; // 2MB

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['archivo'])) {
    $archivo = $_FILES['archivo'];
    
    // Obtener extension
    $nombre_original = $archivo['name'];
    $extension = strtolower(pathinfo($nombre_original, PATHINFO_EXTENSION));
    
    // Validar extension
    if (!in_array($extension, $extensiones_permitidas)) {
        $mensaje = "Extension no permitida. Solo: " . implode(', ', $extensiones_permitidas);
    }
    // Validar tamaño
    elseif ($archivo['size'] > $tamano_maximo) {
        $mensaje = "El archivo excede el limite de 2MB";
    }
    // Validar que es una imagen real
    elseif (!@getimagesize($archivo['tmp_name'])) {
        $mensaje = "El archivo no es una imagen valida";
    }
    // Validar MIME type real
    else {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime_real = finfo_file($finfo, $archivo['tmp_name']);
        finfo_close($finfo);
        
        $mimes_permitidos = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        
        if (!in_array($mime_real, $mimes_permitidos)) {
            $mensaje = "Tipo de archivo no permitido";
        } else {
            // Generar nombre aleatorio para evitar path traversal
            $nuevo_nombre = bin2hex(random_bytes(16)) . '.' . $extension;
            $destino = 'uploads/' . $nuevo_nombre;
            
            if (move_uploaded_file($archivo['tmp_name'], $destino)) {
                $mensaje = "Imagen subida correctamente";
            } else {
                $mensaje = "Error al subir archivo";
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Subir Imagen - FastMarket</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Subir Imagen de Producto</h1>
        <?php if ($mensaje): ?>
            <p class="exito"><?php echo htmlspecialchars($mensaje); ?></p>
        <?php endif; ?>
        <form method="POST" enctype="multipart/form-data">
            <label>Seleccionar imagen (JPG, PNG, GIF, WebP - max 2MB):</label>
            <input type="file" name="archivo" accept="image/jpeg,image/png,image/gif,image/webp" required>
            <button type="submit">Subir</button>
        </form>
        <p><a href="perfil.php">Volver al perfil</a></p>
    </div>
</body>
</html>
