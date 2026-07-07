<?php
/**
 * conexion.php - Conexion a BD (VERSION VULNERABLE)
 * CASO PRACTICO 10 - FastMarket S.A.C.
 * 
 * Vulnerabilidades intencionales:
 * - Credenciales de BD hardcodeadas
 * - Sin manejo de errores apropiado
 * - Sin configuracion de charset explicita (relacionado con inyeccion)
 */

// En Docker, el host es el nombre del servicio 'db'
// Fuera de Docker, es 'localhost'
$host     = getenv('DB_HOST') ?: 'localhost';
$dbname   = getenv('DB_NAME') ?: 'fastmarket_db';
$username = getenv('DB_USER') ?: 'root';
$password = getenv('DB_PASS') ?: '';

try {
    $pdo = new PDO(
        "mysql:host=$host;dbname=$dbname",
        $username,
        $password
    );
    // PDO por defecto no lanza excepciones, configurar para que si
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    // CASO 6: Exponer informacion tecnica del servidor
    die("Error de conexion: " . $e->getMessage());
}
