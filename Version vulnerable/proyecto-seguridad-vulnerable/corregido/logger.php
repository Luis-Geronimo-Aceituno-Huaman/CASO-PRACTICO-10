<?php
/**
 * logger.php - Sistema de registro de eventos (VERSION CORREGIDA)
 * CASO PRACTICO 10 - FastMarket S.A.C.
 * 
 * Implementa:
 * - Registro de intentos fallidos de login
 * - Registro de cambios de contraseña
 * - Registro de accesos de administradores
 * - Registro de modificaciones de productos
 * - Tabla: logs_seguridad
 */

require_once __DIR__ . '/conexion.php';

/**
 * Registra un evento de seguridad en la tabla logs_seguridad
 *
 * @param string $tipo_evento  Tipo: intento_fallido, cambio_password, acceso_admin, modificacion_producto
 * @param string $usuario      Nombre de usuario (o NULL)
 * @param string $ip           Direccion IP del cliente
 * @param string $detalle      Descripcion del evento
 */
function registrar_evento(string $tipo_evento, ?string $usuario, string $ip, string $detalle): void
{
    global $pdo;

    $stmt = $pdo->prepare("INSERT INTO logs_seguridad (tipo_evento, usuario, ip, detalle)
                           VALUES (:tipo, :usuario, :ip, :detalle)");

    $stmt->execute([
        'tipo'    => $tipo_evento,
        'usuario' => $usuario,
        'ip'      => $ip,
        'detalle' => $detalle,
    ]);
}

/**
 * Obtiene los ultimos N eventos de seguridad
 */
function obtener_eventos(int $limite = 100): array
{
    global $pdo;

    $stmt = $pdo->prepare("SELECT * FROM logs_seguridad ORDER BY fecha DESC LIMIT :limite");
    $stmt->bindValue(':limite', $limite, PDO::PARAM_INT);
    $stmt->execute();

    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}
