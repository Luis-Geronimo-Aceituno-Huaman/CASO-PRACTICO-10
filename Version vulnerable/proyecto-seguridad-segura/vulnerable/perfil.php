<?php
/**
 * perfil.php - Perfil de usuario (VERSION VULNERABLE)
 * CASO PRACTICO 10 - FastMarket S.A.C.
 *
 * Este archivo contiene vulnerabilidades INTENCIONALES para fines educativos.
 * NUNCA usar este codigo en un entorno de produccion.
 *
 * Vulnerabilidades implementadas:
 *   Caso 3  -> Broken Access Control / IDOR
 *              (cualquier usuario accede a perfiles ajenos cambiando ?id= en la URL)
 *   Caso 1  -> SQL Injection adicional en la consulta SELECT por concatenacion
 */

session_start();
require_once 'conexion.php';

// =============================================================
// VULNERABLE - Caso 3: Broken Access Control (IDOR)
// =============================================================
// El script recibe el id del usuario a consultar via parametro GET
// y lo usa DIRECTAMENTE para la consulta SQL.
//
// NO se verifica:
//   1. Que exista una sesion activa (cualquiera puede acceder)
//   2. Que $_SESSION['id_usuario'] coincida con el ?id= solicitado
//   3. Que el usuario autenticado tenga permiso para ver ese perfil
//
// Esto es un ataque IDOR (Insecure Direct Object Reference):
// el atacante simplemente cambia el numero en la URL para acceder
// a datos de otros usuarios. No necesita hacks complejos, solo
// modificar el parametro ?id= en la barra de direccion del navegador.
//
// Ejemplo de ataque:
//   1. El usuario "juan" (id=2) se loguea y accede a perfil.php?id=2
//   2. Ve sus datos correctamente.
//   3. Cambia la URL a perfil.php?id=1 (el admin).
//   4. Accede a los datos del admin (nombre, email, etc.)
//   5. Tambien puede probar ?id=3 para ver a otro cliente.
//
// VULNERABLE: no valida que el id solicitado pertenezca al usuario autenticado (IDOR / Broken Access Control)
// =============================================================

$id = $_GET['id'] ?? 1;

// =============================================================
// VULNERABLE - Caso 1: SQL Injection en SELECT
// =============================================================
// La variable $id se obtiene directamente de $_GET sin validar
// que sea numerica ni escaparla. Un atacante podria inyectar SQL
// en el parametro, por ejemplo:
//   perfil.php?id=1 OR 1=1
//   perfil.php?id=1 UNION SELECT 1,2,3,4,5,6,7,8--
//
// Como PDO esta en modo ERRMODE_EXCEPTION (configurado en
// conexion.php), una inyeccion con error de sintaxis mostrara
// el error nativo de PDO con toda la info tecnica (Caso 6).
// =============================================================

$sql = "SELECT * FROM usuarios WHERE id = $id";
$usuario = $pdo->query($sql)->fetch(PDO::FETCH_ASSOC);

if (!$usuario) {
    die("Usuario no encontrado");
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Perfil - FastMarket</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Perfil de Usuario</h1>

        <div class="perfil">
            <!--
                VULNERABLE: se muestran los datos del usuario obtenidos
                con el id del GET, sin verificar que el usuario actual
                tenga derecho a ver esta informacion.
            -->
            <p><strong>Nombre:</strong>     <?php echo $usuario['nombre']; ?></p>
            <p><strong>Email:</strong>       <?php echo $usuario['email']; ?></p>
            <p><strong>Usuario:</strong>     <?php echo $usuario['usuario']; ?></p>
            <p><strong>Rol:</strong>         <?php echo $usuario['rol']; ?></p>
            <p><strong>Fecha registro:</strong> <?php echo $usuario['fecha_registro']; ?></p>
        </div>

        <!-- Info de la sesion actual (para evidenciar que otro usuario ve datos ajenos) -->
        <?php if (isset($_SESSION['id_usuario'])): ?>
            <div style="background:#f8f9fa;padding:10px;border-radius:5px;margin-bottom:15px;font-size:0.9em;">
                <strong>Sesion activa:</strong>
                <?php echo $_SESSION['usuario']; ?>
                (ID: <?php echo $_SESSION['id_usuario']; ?>, Rol: <?php echo $_SESSION['rol']; ?>)
                &mdash; Viendo perfil con <strong>id=<?php echo (int)$id; ?></strong>
            </div>
        <?php else: ?>
            <div style="background:#fdecea;padding:10px;border-radius:5px;margin-bottom:15px;font-size:0.9em;">
                <strong>Sin sesion activa</strong> &mdash; Accediendo al perfil con id=<?php echo (int)$id; ?>
            </div>
        <?php endif; ?>

        <nav>
            <a href="comentarios.php">Comentarios</a> |
            <a href="upload.php">Subir imagen</a> |
            <a href="error_demo.php">Demo Errores</a> |
            <a href="login.php">Cerrar sesion</a>
        </nav>
    </div>
</body>
</html>
