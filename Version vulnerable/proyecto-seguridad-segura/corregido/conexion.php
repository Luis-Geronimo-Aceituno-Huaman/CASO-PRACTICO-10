<?php
/**
 * conexion.php - Conexion a BD (VERSION CORREGIDA)
 * CASO PRACTICO 10 - FastMarket S.A.C.
 * 
 * Mejoras de seguridad:
 * - Conexion PDO con modo seguro
 * - Charset UTF-8 configurado explicitamente
 * - Manejo de errores generico sin exponer detalles
 */

$host     = getenv('DB_HOST') ?: 'localhost';
$dbname   = getenv('DB_NAME') ?: 'fastmarket_db';
$username = getenv('DB_USER') ?: 'root';
$password = getenv('DB_PASS') ?: '';

try {
    $pdo = new PDO(
        "mysql:host=$host;dbname=$dbname;charset=utf8mb4",
        $username,
        $password,
        [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]
    );
} catch (PDOException $e) {
    error_log("Error de conexion a BD: " . $e->getMessage());
    die("Error interno del servidor. Intente mas tarde.");
}
