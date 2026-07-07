<?php
/**
 * upload.php - Carga de archivos (VERSION CORREGIDA)
 * CASO PRACTICO 10 - FastMarket S.A.C.
 *
 * Este archivo corrige TODAS las vulnerabilidades de la version vulnerable.
 * Cada correccion esta marcada con "// CORREGIDO:" para contraste lado a lado
 * con los comentarios "// VULNERABLE" del archivo vulnerable/upload.php.
 *
 * Vulnerabilidades corregidas:
 *   Caso 5  -> Validacion de extension (whitelist), MIME (finfo), tamano, nombre
 *   Caso 6  -> No exponer rutas del servidor ni confirmar guardado exitoso
 *   Caso 8  -> Registro de eventos (cargas exitosas y rechazadas)
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
// CORREGIDO (Caso 5): Configuracion de validacion de archivos
// =============================================================
// VULNERABLE: La version anterior no tenia NINGUNA restriccion:
//   - Extension: aceptaba cualquier archivo (.php, .exe, .sh, etc.)
//   - MIME: no verificaba el tipo real del archivo
//   - Tamano: sin limite, podia llenar el disco
//   - Nombre: usaba el nombre original (path traversal possible)
//
// Ahora configuramos todas las validaciones ANTES del procesamiento.
// =============================================================

// 1. Lista blanca de extensiones permitidas (solo imagenes)
//    VULNERABLE: no existia lista blanca, se aceptaba cualquier extension
$extensiones_permitidas = ['jpg', 'jpeg', 'png', 'webp'];

// 2. Tipos MIME permitidos (verificados con finfo_file)
//    VULNERABLE: no se verificaba el MIME real, se confiaba en $_FILES['type']
$mimes_permitidos = ['image/jpeg', 'image/png', 'image/webp'];

// 3. Tamano maximo: 2MB (en bytes)
//    VULNERABLE: no habia limite de tamano
$tamano_maximo_bytes = 2 * 1024 * 1024; // 2MB

// 4. Directorio de destino (con .htaccess que bloquea ejecucion de PHP)
//    VULNERABLE: guardaba en 'uploads/' sin proteccion contra ejecucion
$directorio_uploads = __DIR__ . '/uploads';

// Crear directorio si no existe
if (!is_dir($directorio_uploads)) {
    mkdir($directorio_uploads, 0755, true);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['archivo'])) {

    $archivo = $_FILES['archivo'];
    $nombre_original = $archivo['name'];

    // =============================================================
    // CORREGIDO (Caso 5): Validar que no haya errores de PHP
    // =============================================================
    // PHP puede rechazar archivos por:
    //   - UPLOAD_ERR_INI_SIZE: excede upload_max_filesize en php.ini
    //   - UPLOAD_ERR_FORM_SIZE: excede MAX_FILE_SIZE en el form
    //   - UPLOAD_ERR_PARTIAL: archivo incompleto
    //   - UPLOAD_ERR_NO_FILE: no se selecciono archivo
    // Si alguno de estos errores ocurre, no intentamos procesar.
    // =============================================================

    if ($archivo['error'] !== UPLOAD_ERR_OK) {
        $mensaje = 'Error al subir el archivo. Verifica que no exceda el limite permitido.';
        registrarEvento($pdo, 'intento_sospechoso', $_SESSION['usuario'] ?? null,
            "Error en carga de archivo - Codigo de error PHP: " . $archivo['error']);
    } else {

        // =============================================================
        // CORREGIDO (Caso 5): Validar extension con lista blanca
        // =============================================================
        // VULNERABLE: La version anterior no verificaba la extension.
        // Un atacante podia subir "shell.php" o "imagen.jpg.php" y el
        // servidor lo guardaba y ejecutaba como PHP.
        //
        // Ahora usamos pathinfo() para extraer la extension y la
        // comparamos contra la lista blanca. Solo aceptamos .jpg,
        // .jpeg, .png y .webp.
        //
        // IMPORTANTE: Para defender contra dobles extensiones como
        // "imagen.jpg.php", usamos pathinfo() con PATHINFO_EXTENSION
        // que extrae SOLO la ultima extension. Entonces "imagen.jpg.php"
        // devolveria "php" (no permitido), y "imagen.php.jpg" devolveria
        // "jpg" (permitido, pero la validacion MIME lo rechazaria porque
        // no es una imagen real).
        // =============================================================

        $extension = strtolower(pathinfo($nombre_original, PATHINFO_EXTENSION));

        if (!in_array($extension, $extensiones_permitidas)) {
            $mensaje = 'Extension no permitida. Solo se permiten: ' . implode(', ', $extensiones_permitidas);
            registrarEvento($pdo, 'intento_sospechoso', $_SESSION['usuario'] ?? null,
                "Carga rechazada - Extension no permitida: '$extension' (archivo: $nombre_original)");
        } else {

            // =============================================================
            // CORREGIDO (Caso 5): Validar tamano maximo
            // =============================================================
            // VULNERABLE: No habia limite. Un atacante podia subir archivos
            // de gigabytes para agotar el disco o causar denegacion de servicio.
            //
            // Verificamos tanto en el script (esta validacion) como a nivel
            // de configuracion PHP (upload_max_filesize y post_max_size en
            // php.ini). La configuracion de PHP es la barrera principal;
            // esta validacion es una capa adicional.
            // =============================================================

            if ($archivo['size'] > $tamano_maximo_bytes) {
                $mensaje = 'El archivo excede el limite de 2MB permitido.';
                registrarEvento($pdo, 'intento_sospechoso', $_SESSION['usuario'] ?? null,
                    "Carga rechazada - Tamano excedido: " . round($archivo['size'] / 1024 / 1024, 2) . "MB (archivo: $nombre_original)");
            } else {

                // =============================================================
                // CORREGIDO (Caso 5): Validar que es una imagen real (getimagesize)
                // =============================================================
                // getimagesize() intenta leer la cabecera de imagen del archivo.
                // Si no es una imagen valida, retorna false. Esto atrapa archivos
                // que tienen extension .jpg pero NO son imagenes (por ejemplo,
                // un script PHP renombrado a "malware.jpg").
                //
                // El operador @ suprime warnings de PHP si el archivo no es
                // una imagen (por ejemplo, si es un archivo de texto plano).
                // =============================================================

                $info_imagen = @getimagesize($archivo['tmp_name']);

                if ($info_imagen === false) {
                    $mensaje = 'El archivo no es una imagen valida.';
                    registrarEvento($pdo, 'intento_sospechoso', $_SESSION['usuario'] ?? null,
                        "Carga rechazada - No es imagen real (archivo: $nombre_original)");
                } else {

                    // =============================================================
                    // CORREGIDO (Caso 5): Validar MIME type real con finfo_file
                    // =============================================================
                    // finfo_file() analiza el contenido del archivo para determinar
                    // su tipo MIME real, ignorando la extension y el Content-Type
                    // del request HTTP (que puede ser falseado por el cliente).
                    //
                    // VULNERABLE: La version anterior no verificaba el MIME.
                    // Un atacante podia subir un archivo PHP con Content-Type
                    // "image/jpeg" y el servidor lo aceptaria.
                    //
                    // NOTA: finfo_file() no es infalible (algunos formatos
                    // pueden ser ambiguos), por eso lo combinamos con getimagesize()
                    // como doble verificacion.
                    // =============================================================

                    $finfo = finfo_open(FILEINFO_MIME_TYPE);
                    $mime_real = finfo_file($finfo, $archivo['tmp_name']);
                    finfo_close($finfo);

                    if (!in_array($mime_real, $mimes_permitidos)) {
                        $mensaje = 'Tipo de archivo no permitido.';
                        registrarEvento($pdo, 'intento_sospechoso', $_SESSION['usuario'] ?? null,
                            "Carga rechazada - MIME no permitido: '$mime_real' (archivo: $nombre_original)");
                    } else {

                        // =============================================================
                        // CORREGIDO (Caso 5): Renombrar archivo con nombre aleatorio
                        // =============================================================
                        // VULNERABLE: La version anterior usaba el nombre original:
                        //   $destino = 'uploads/' . $archivo['name'];
                        //
                        // Esto permitia:
                        //   - Path traversal: "../../config.php" sobreescribe archivos
                        //   - Sobrescritura: si dos archivos se llaman igual, uno pierde
                        //   - Nombre predecible: el atacante sabe el nombre del archivo
                        //
                        // Ahora generamos un nombre aleatorio con bin2hex(random_bytes(8))
                        // que produce 16 caracteres hexadecimales aleatorios (ej: "a3f8b2c1e9d04f67").
                        // La extension se obtiene de la validacion anterior (ya verificada).
                        //
                        // Esto elimina: path traversal, sobrescritura, y nombre predecible.
                        // =============================================================

                        $nuevo_nombre = bin2hex(random_bytes(8)) . '.' . $extension;
                        $destino = $directorio_uploads . '/' . $nuevo_nombre;

                        try {
                            if (move_uploaded_file($archivo['tmp_name'], $destino)) {

                                // =============================================================
                                // CORREGIDO (Caso 8): Registrar carga exitosa
                                // =============================================================
                                // VULNERABLE: La version anterior no registraba nada.
                                // No habia forma de saber quien subio que archivo y cuando.
                                //
                                // Ahora registramos cada carga exitosa con: usuario, nombre
                                // original, nombre generado, y tamano.
                                // =============================================================

                                registrarEvento($pdo, 'modificacion_producto', $_SESSION['usuario'] ?? null,
                                    "Imagen subida: '$nombre_original' → '$nuevo_nombre' (" .
                                    round($archivo['size'] / 1024, 1) . "KB)");

                                // =============================================================
                                // CORREGIDO (Caso 6): No exponer ruta del servidor
                                // =============================================================
                                // VULNERABLE: La version anterior mostraba:
                                //   realpath($destino)  ← ruta completa del servidor
                                //   URL de acceso       ← URL directa al archivo
                                //
                                // Esto revelaba la estructura del servidor y confirmaba
                                // que el archivo estaba accesible via URL.
                                //
                                // Ahora mostramos solo un mensaje generico. El usuario
                                // no necesita saber la ruta exacta donde se guardo.
                                // =============================================================

                                $mensaje = 'Imagen subida correctamente.';

                            } else {
                                $mensaje = 'Error al guardar el archivo.';
                                error_log("upload.php - move_uploaded_file fallo para: $nombre_original");
                            }
                        } catch (Exception $e) {
                            $mensaje = 'Ocurrio un error, intenta mas tarde.';
                            error_log("upload.php - Excepcion al guardar archivo: " . $e->getMessage());
                        }
                    }
                }
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
            <!-- CORREGIDO (Caso 2 + Caso 6): htmlspecialchars() y mensaje generico -->
            <!-- VULNERABLE: La version anterior no sanitizaba el mensaje y exponia rutas -->
            <p class="error"><?php echo htmlspecialchars($mensaje, ENT_QUOTES, 'UTF-8'); ?></p>
        <?php endif; ?>

        <!--
            CORREGIDO (Caso 5): Formulario con restricciones en el cliente
            ============================================================
            VULNERABLE: La version anterior no tenia el atributo accept,
            lo que permitia seleccionar cualquier tipo de archivo.
            Ahora el navegador sugiere solo imagenes, aunque un atacante
            puede ignorar esto (la validacion real es en el servidor).
        -->
        <form method="POST" enctype="multipart/form-data">
            <label>Seleccionar imagen (JPG, PNG o WebP - maximo 2MB):</label>
            <input type="file" name="archivo"
                   accept="image/jpeg,image/png,image/webp"
                   required>
            <button type="submit">Subir</button>
        </form>

        <!--
            CORREGIDO (Caso 6): No se muestra la ruta del servidor
            VULNERABLE: La version anterior mostraba:
              - realpath($destino)  → C:\xampp\htdocs\proyecto\uploads\archivo.jpg
              - URL de acceso       → uploads/archivo.jpg
            Esto ayudaba al atacante a localizar y acceder al archivo.
        -->

        <p><a href="perfil.php">Volver al perfil</a></p>
    </div>
</body>
</html>
