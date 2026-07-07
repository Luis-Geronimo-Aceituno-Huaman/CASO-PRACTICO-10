<?php
/**
 * upload.php - Carga de archivos (VERSION VULNERABLE)
 * CASO PRACTICO 10 - FastMarket S.A.C.
 *
 * Este archivo contiene vulnerabilidades INTENCIONALES para fines educativos.
 * NUNCA usar este codigo en un entorno de produccion.
 *
 * Vulnerabilidades implementadas:
 *   Caso 5  -> Carga de archivos sin validacion (extension, MIME, tamano)
 *              Permite subir archivos PHP arbitrarios y ejecutarlos en el servidor (RCE)
 *   Caso 6  -> Expone la ruta completa del archivo subido en pantalla
 */

$mensaje    = '';
$ruta_guard = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['archivo'])) {

    $archivo = $_FILES['archivo'];

    // =============================================================
    // VULNERABLE - Caso 5: Sin validacion de extension ni MIME
    // =============================================================
    // El script acepta CUALQUIER archivo sin verificar:
    //
    //   - Extension: No se verifica si es .jpg, .png, .gif, etc.
    //     Si el archivo se llama "malware.php", se guarda tal cual.
    //
    //   - MIME type: No se usa finfo_file(), getimagesize() ni
    //     ningun metodo para verificar que el archivo sea realmente
    //     una imagen. Un atacante puede subir un script PHP con
    //     extension .jpg o cualquier otro nombre.
    //
    //   - Tamano: No hay limite. Un atacante puede subir un archivo
    //     de gigabytes y agotar el disco del servidor.
    //
    //   - Nombre original: Se usa $archivo['name'] tal cual.
    //     Si el nombre es "../../config.php", podria sobreescribir
    //     archivos criticos (path traversal).
    //     Si el nombre es "malware.php", queda accesible via URL.
    //
    // CONSECUENCIA: Esto permite Remote Code Execution (RCE).
    // Un atacante sube un archivo PHP que contiene codigo
    // malicioso, y luego accede a el desde el navegador.
    // El servidor lo interpreta como PHP y ejecuta el codigo.
    //
    // VULNERABLE: sin validacion de extension/MIME, permite subir y ejecutar archivos PHP arbitrarios (RCE via upload)
    // =============================================================

    $destino = 'uploads/' . $archivo['name'];

    if (move_uploaded_file($archivo['tmp_name'], $destino)) {

        // =============================================================
        // VULNERABLE - Caso 6: Exposicion de informacion
        // =============================================================
        // Se muestra al usuario la ruta COMPLETA del archivo en el
        // servidor. Esto revela:
        //   - La estructura de directorios del servidor
        //   - La ruta del proyecto (C:\xampp\htdocs\...)
        //   - Confirma que el archivo se guardo correctamente
        //
        // Un atacante usa esta informacion para acceder directamente
        // al archivo subido via URL y ejecutarlo.
        // =============================================================

        $ruta_guard = realpath($destino);
        $mensaje    = "Archivo subido correctamente.";

    } else {
        $mensaje = "Error al subir archivo.";
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
            <p class="exito"><?php echo $mensaje; ?></p>
        <?php endif; ?>

        <!--
            VULNERABLE: el input NO tiene atributo accept que restrinja
            las extensiones. Aunque el atributo accept existiera, un
            atacante lo ignora facilmente (solo es una sugerencia del
            navegador, no una validacion del servidor).
        -->
        <form method="POST" enctype="multipart/form-data">
            <label>Seleccionar archivo (imagen del producto):</label>
            <input type="file" name="archivo" required>
            <button type="submit">Subir</button>
        </form>

        <?php if ($ruta_guard): ?>
            <!-- VULNERABLE: se expone la ruta completa del archivo en el servidor -->
            <div style="background:#f8f9fa;padding:15px;border-radius:5px;margin-top:15px;border-left:4px solid #3498db;">
                <p><strong>Ruta del archivo guardado:</strong></p>
                <code style="display:block;background:#2c3e50;color:#ecf0f1;padding:10px;border-radius:3px;margin-top:5px;word-break:break-all;">
                    <?php echo $ruta_guard; ?>
                </code>
                <p style="margin-top:10px;font-size:0.9em;color:#555;">
                    <strong>URL de acceso:</strong>
                    <?php
                        // Mostrar la URL relativa para que el atacante sepa a donde ir
                        $url_acceso = 'uploads/' . htmlspecialchars($archivo['name']);
                        echo $url_acceso;
                    ?>
                </p>
            </div>
        <?php endif; ?>

        <p><a href="perfil.php">Volver al perfil</a></p>
    </div>
</body>
</html>
