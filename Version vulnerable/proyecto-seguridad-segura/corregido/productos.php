<?php
/**
 * productos.php - Gestion de productos (VERSION CORREGIDA)
 * CASO PRACTICO 10 - FastMarket S.A.C.
 *
 * CORREGIDO (Caso 8 - Logging y monitoreo):
 * Modulo de administracion de productos que registra toda modificacion
 * en logs_seguridad con tipo_evento = 'modificacion_producto'.
 *
 * Vulnerabilidades corregidas:
 *   Caso 1  -> Prepared statements en INSERT, UPDATE, DELETE, SELECT
 *   Caso 2  -> htmlspecialchars() en toda salida
 *   Caso 3  -> Verificacion de sesion y rol admin
 *   Caso 6  -> Mensajes genericos sin info tecnica
 *   Caso 8  -> Registro de eventos para cada modificacion
 *   Caso 10 -> Validacion de entrada en servidor
 */

// CORREGIDO (Caso 6): Incluir configuracion global de errores ANTES de todo
require_once 'config.php';

session_start();
require_once 'conexion.php';
require_once 'logger.php';

// =============================================================
// CORREGIDO (Caso 3): Verificar sesion y rol de admin
// =============================================================
// Solo los administradores pueden gestionar productos.
// VULNERABLE: La version anterior no tenia control de acceso.
// =============================================================

if (!isset($_SESSION['id_usuario']) || $_SESSION['rol'] !== 'admin') {
    http_response_code(403);
    ?>
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Acceso denegado - FastMarket</title>
        <link rel="stylesheet" href="style.css">
    </head>
    <body>
        <div class="container">
            <h1>Acceso denegado</h1>
            <p class="error">No tienes permiso para ver este recurso.</p>
            <nav><a href="perfil.php">Volver al perfil</a></nav>
        </div>
    </body>
    </html>
    <?php
    exit;
}

$mensaje = '';
$tipo_mensaje = 'exito'; // 'exito' o 'error'

// =============================================================
// CORREGIDO (Caso 1 + Caso 10): Procesar acciones CRUD
// =============================================================
// Cada accion (crear, editar, eliminar) esta envuelta en try/catch
// y registra el evento en logs_seguridad.
// =============================================================

$accion = $_GET['accion'] ?? 'listar';
$id_producto = filter_var($_GET['id'] ?? '', FILTER_VALIDATE_INT);

// --- ACCION: ELIMINAR ---
if ($accion === 'eliminar' && $id_producto) {
    try {
        // Obtener nombre del producto antes de eliminar (para el log)
        $stmt = $pdo->prepare("SELECT nombre FROM productos WHERE id = :id");
        $stmt->execute([':id' => $id_producto]);
        $producto = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($producto) {
            $stmt = $pdo->prepare("DELETE FROM productos WHERE id = :id");
            $stmt->execute([':id' => $id_producto]);

            // =============================================================
            // CORREGIDO (Caso 8): Registrar eliminacion de producto
            // =============================================================
            // VULNERABLE: La version anterior no registraba eliminaciones.
            // No habia forma de saber quien elimino que producto y cuando.
            // =============================================================
            registrarEvento($pdo, 'modificacion_producto', $_SESSION['usuario'],
                "Producto eliminado: '" . $producto['nombre'] . "' (ID: $id_producto)");

            $mensaje = 'Producto eliminado correctamente';
        } else {
            $mensaje = 'Producto no encontrado';
            $tipo_mensaje = 'error';
        }
    } catch (PDOException $e) {
        error_log("productos.php - Error al eliminar producto: " . $e->getMessage());
        $mensaje = 'Ocurrio un error al eliminar el producto';
        $tipo_mensaje = 'error';
    }
    $accion = 'listar';
}

// --- ACCION: CREAR o EDITAR (formulario) ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $nombre_post   = trim($_POST['nombre'] ?? '');
    $descripcion   = trim($_POST['descripcion'] ?? '');
    $precio        = $_POST['precio'] ?? '';
    $stock         = $_POST['stock'] ?? '';
    $id_editar     = filter_var($_POST['id_producto'] ?? '', FILTER_VALIDATE_INT);

    // =============================================================
    // CORREGIDO (Caso 10): Validacion de entrada
    // =============================================================
    // VULNERABLE: La version anterior no validaba nada.
    // Ahora validamos: nombre requerido, precio >= 0, stock >= 0.
    // =============================================================

    if (empty($nombre_post)) {
        $mensaje = 'El nombre del producto es obligatorio';
        $tipo_mensaje = 'error';
    } elseif (!is_numeric($precio) || $precio < 0) {
        $mensaje = 'El precio debe ser un numero positivo';
        $tipo_mensaje = 'error';
    } elseif (!is_numeric($stock) || $stock < 0) {
        $mensaje = 'El stock debe ser un numero positivo';
        $tipo_mensaje = 'error';
    } else {

        try {
            if ($id_editar) {
                // --- EDITAR PRODUCTO EXISTENTE ---
                // CORREGIDO (Caso 1): Prepared statement en UPDATE
                $stmt = $pdo->prepare(
                    "UPDATE productos
                     SET nombre = :nombre, descripcion = :descripcion,
                         precio = :precio, stock = :stock
                     WHERE id = :id"
                );
                $stmt->execute([
                    ':nombre'      => $nombre_post,
                    ':descripcion' => $descripcion,
                    ':precio'      => $precio,
                    ':stock'       => $stock,
                    ':id'          => $id_editar,
                ]);

                // =============================================================
                // CORREGIDO (Caso 8): Registrar modificacion de producto
                // =============================================================
                // VULNERABLE: La version anterior no registraba ediciones.
                // Ahora se registra cada cambio con: campo modificado, valores.
                // =============================================================
                registrarEvento($pdo, 'modificacion_producto', $_SESSION['usuario'],
                    "Producto editado: '$nombre_post' (ID: $id_editar, precio: $precio, stock: $stock)");

                $mensaje = 'Producto actualizado correctamente';

            } else {
                // --- CREAR PRODUCTO NUEVO ---
                // CORREGIDO (Caso 1): Prepared statement en INSERT
                $stmt = $pdo->prepare(
                    "INSERT INTO productos (nombre, descripcion, precio, stock)
                     VALUES (:nombre, :descripcion, :precio, :stock)"
                );
                $stmt->execute([
                    ':nombre'      => $nombre_post,
                    ':descripcion' => $descripcion,
                    ':precio'      => $precio,
                    ':stock'       => $stock,
                ]);

                $nuevo_id = $pdo->lastInsertId();

                // =============================================================
                // CORREGIDO (Caso 8): Registro de creacion de producto
                // =============================================================
                registrarEvento($pdo, 'modificacion_producto', $_SESSION['usuario'],
                    "Producto creado: '$nombre_post' (ID: $nuevo_id, precio: $precio, stock: $stock)");

                $mensaje = 'Producto creado correctamente';
            }
        } catch (PDOException $e) {
            error_log("productos.php - Error al guardar producto: " . $e->getMessage());
            $mensaje = 'Ocurrio un error al guardar el producto';
            $tipo_mensaje = 'error';
        }
    }
    $accion = 'listar';
}

// --- ACCION: LISTAR (por defecto) ---
$productos = [];
if ($accion === 'listar') {
    try {
        $stmt = $pdo->query("SELECT * FROM productos ORDER BY id DESC");
        $productos = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        error_log("productos.php - Error al listar productos: " . $e->getMessage());
        $mensaje = 'Error al cargar productos';
        $tipo_mensaje = 'error';
    }
}

// --- ACCION: FORMULARIO (crear o editar) ---
$producto_editar = null;
if ($accion === 'formulario' && $id_producto) {
    try {
        $stmt = $pdo->prepare("SELECT * FROM productos WHERE id = :id");
        $stmt->execute([':id' => $id_producto]);
        $producto_editar = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$producto_editar) {
            $accion = 'listar';
            $mensaje = 'Producto no encontrado';
            $tipo_mensaje = 'error';
        }
    } catch (PDOException $e) {
        error_log("productos.php - Error al obtener producto: " . $e->getMessage());
        $accion = 'listar';
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gestion de Productos - FastMarket</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Gestion de Productos</h1>

        <?php if ($mensaje): ?>
            <p class="<?php echo $tipo_mensaje === 'error' ? 'error' : 'exito'; ?>">
                <?php echo htmlspecialchars($mensaje, ENT_QUOTES, 'UTF-8'); ?>
            </p>
        <?php endif; ?>

        <?php if ($accion === 'formulario'): ?>
            <!-- Formulario de crear/editar -->
            <h2><?php echo $producto_editar ? 'Editar Producto' : 'Nuevo Producto'; ?></h2>
            <form method="POST" action="productos.php?accion=listar">
                <?php if ($producto_editar): ?>
                    <input type="hidden" name="id_producto" value="<?php echo (int)$producto_editar['id']; ?>">
                <?php endif; ?>

                <label>Nombre:</label>
                <input type="text" name="nombre" maxlength="150" required
                       value="<?php echo htmlspecialchars($producto_editar['nombre'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">

                <label>Descripcion:</label>
                <textarea name="descripcion" rows="3"><?php echo htmlspecialchars($producto_editar['descripcion'] ?? '', ENT_QUOTES, 'UTF-8'); ?></textarea>

                <label>Precio:</label>
                <input type="number" name="precio" step="0.01" min="0" required
                       value="<?php echo htmlspecialchars($producto_editar['precio'] ?? '0.00', ENT_QUOTES, 'UTF-8'); ?>">

                <label>Stock:</label>
                <input type="number" name="stock" min="0" required
                       value="<?php echo htmlspecialchars($producto_editar['stock'] ?? '0', ENT_QUOTES, 'UTF-8'); ?>">

                <button type="submit"><?php echo $producto_editar ? 'Actualizar' : 'Crear'; ?></button>
                <a href="productos.php" style="margin-left:10px;">Cancelar</a>
            </form>

        <?php else: ?>
            <!-- Lista de productos -->
            <p><a href="productos.php?accion=formulario" style="display:inline-block;padding:8px 16px;background:#27ae60;color:#fff;border-radius:4px;text-decoration:none;">+ Nuevo Producto</a></p>

            <?php if (empty($productos)): ?>
                <p>No hay productos registrados.</p>
            <?php else: ?>
                <table style="width:100%;border-collapse:collapse;">
                    <thead>
                        <tr style="background:#2c3e50;color:#fff;">
                            <th style="padding:10px;text-align:left;">ID</th>
                            <th style="padding:10px;text-align:left;">Nombre</th>
                            <th style="padding:10px;text-align:left;">Precio</th>
                            <th style="padding:10px;text-align:left;">Stock</th>
                            <th style="padding:10px;text-align:left;">Acciones</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($productos as $prod): ?>
                            <tr style="border-bottom:1px solid #eee;">
                                <td style="padding:8px;"><?php echo (int)$prod['id']; ?></td>
                                <td style="padding:8px;"><?php echo htmlspecialchars($prod['nombre'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td style="padding:8px;">S/. <?php echo number_format($prod['precio'], 2); ?></td>
                                <td style="padding:8px;"><?php echo (int)$prod['stock']; ?></td>
                                <td style="padding:8px;">
                                    <a href="productos.php?accion=formulario&id=<?php echo (int)$prod['id']; ?>"
                                       style="color:#3498db;">Editar</a>
                                    <a href="productos.php?accion=eliminar&id=<?php echo (int)$prod['id']; ?>"
                                       style="color:#e74c3c;margin-left:10px;"
                                       onclick="return confirm('Eliminar este producto?');">Eliminar</a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        <?php endif; ?>

        <nav style="margin-top:20px;">
            <a href="perfil.php">Volver al perfil</a> |
            <a href="panel_logs.php">Ver logs de seguridad</a>
        </nav>
    </div>
</body>
</html>
