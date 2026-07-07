<?php
/**
 * logger.php - Sistema de registro de eventos (VERSION CORREGIDA)
 * CASO PRACTICO 10 - FastMarket S.A.C.
 *
 * CORREGIDO (Caso 8 - Logging y monitoreo):
 * Todas las acciones de seguridad se registran en la tabla logs_seguridad.
 * Esto permite detectar patrones de ataque, intentos de intrusion y
 * actividad sospechosa. La tabla tiene campos: id, tipo_evento, usuario,
 * ip, detalle, fecha.
 *
 * Esta funcion se reutiliza en login.php, registro.php, comentarios.php,
 * upload.php, perfil.php y cualquier modulo que requiera auditoria.
 */

/**
 * Registra un evento de seguridad en la tabla logs_seguridad.
 *
 * @param PDO    $pdo         Conexion PDO activa
 * @param string $tipo_evento Tipo del evento: 'intento_fallido', 'acceso_admin',
 *                            'cambio_password', 'modificacion_producto',
 *                            'subida_archivo', 'eliminacion_producto', etc.
 * @param string $usuario     Nombre de usuario involucrado (puede ser NULL)
 * @param string $detalle     Descripcion legible del evento
 */
function registrarEvento(PDO $pdo, string $tipo_evento, ?string $usuario, string $detalle): void
{
    try {
        $stmt = $pdo->prepare(
            "INSERT INTO logs_seguridad (tipo_evento, usuario, ip, detalle)
             VALUES (:tipo_evento, :usuario, :ip, :detalle)"
        );

        $stmt->execute([
            ':tipo_evento' => $tipo_evento,
            ':usuario'     => $usuario,
            ':ip'          => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
            ':detalle'     => $detalle,
        ]);
    } catch (PDOException $e) {
        // CORREGIDO (Caso 6): Nunca mostrar errores de BD al usuario.
        // Se registran en el log del servidor para revision del administrador.
        error_log("logger.php - Error al registrar evento: " . $e->getMessage());
    }
}
