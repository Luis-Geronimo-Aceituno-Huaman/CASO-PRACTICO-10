<?php
/**
 * login.php - Inicio de sesion (VERSION VULNERABLE)
 * CASO PRACTICO 10 - FastMarket S.A.C.
 * 
 * Este archivo contiene vulnerabilidades INTENCIONALES para fines educativos.
 * NUNCA usar este codigo en un entorno de produccion.
 * 
 * Vulnerabilidades implementadas:
 *   Caso 1  -> SQL Injection (concatenacion directa en la consulta)
 *   Caso 4  -> Cookies de sesion sin atributos de seguridad
 *   Caso 6  -> Configuracion insegura (errores PHP expuestos al usuario)
 *   Caso 7  -> Sin HTTPS (credenciales enviadas en texto plano por HTTP)
 *   Caso 9  -> Autenticacion debil (password en texto plano sin hash)
 */

// CASO 7: No se fuerza HTTPS. El formulario se envia por HTTP puro,
// lo que permite que un atacante intercepte usuario y password con
// cualquier herramienta de sniffing (Wireshark, tcpdump, etc.).
// No existe ninguna redireccion a HTTPS ni header Strict-Transport-Security.

session_start();
require_once 'conexion.php';

$mensaje = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $usuario  = $_POST['usuario']  ?? '';
    $password = $_POST['password'] ?? '';

    // =============================================================
    // VULNERABLE - Caso 1: SQL Injection
    // =============================================================
    // El valor ingresado por el usuario se inserta DENTRO de la cadena
    // SQL sin ningun tipo de escape, prepared statement o validacion.
    // Esto permite que un atacante cierre la cadena de texto con una
    // comilla simple (') y agregue codigo SQL arbitrario.
    //
    // Ejemplo de payload malicioso en el campo "usuario":
    //   admin' OR '1'='1
    //
    // La consulta resultante seria:
    //   SELECT * FROM usuarios WHERE usuario='admin' OR '1'='1' AND password='cualquier'
    //
    // Como '1'='1' siempre es TRUE, la condicion WHERE devuelva TRUE
    // para TODAS las filas, y el primer registro (el admin) se retorna
    // como resultado valido, permitiendo el acceso sin conocer el password.
    //
    // PDO por defecto NO lanza excepcion en errores SQL cuando esta en
    // modo silencioso (ERRMODE_SILENT), simplemente retorna false.
    // Aqui configuramos ERRMODE_EXCEPTION en conexion.php, por lo que
    // un error de sintaxis SQL GENERARA una excepcion que PHP mostrara
    // en pantalla con toda la informacion tecnica (Caso 6).
    // =============================================================

    $sql = "SELECT * FROM usuarios WHERE usuario='$usuario' AND password='$password'";
    $resultado = $pdo->query($sql);
    $usuario_db = $resultado->fetch(PDO::FETCH_ASSOC);

    if ($usuario_db) {

        // =============================================================
        // VULNERABLE - Caso 9: Autenticacion debil
        // =============================================================
        // El password se comparo directamente contra el campo `password`
        // de la base de datos. En la tabla `usuarios`, el password esta
        // guardado en TEXTO PLANO (ej: "admin123", "juan2024").
        // No se usa password_hash() ni password_verify().
        // Si un atacante obtiene acceso a la BD (SQL Injection, backup
        // filtrado, etc.), obtiene todas las contrasenas sin esfuerzo.
        // =============================================================

        // Iniciar sesion
        $_SESSION['id_usuario'] = $usuario_db['id'];
        $_SESSION['usuario']    = $usuario_db['usuario'];
        $_SESSION['rol']        = $usuario_db['rol'];

        // =============================================================
        // VULNERABLE - Caso 4: Cookies sin atributos de seguridad
        // =============================================================
        // La cookie de sesion se configura SIN los atributos:
        //   - HttpOnly: No esta. JavaScript puede leer la cookie
        //     (facilita ataques XSS para robar sesiones).
        //   - Secure: No esta. La cookie se envia por HTTP y HTTPS,
        //     permitiendo que se transmita en texto plano.
        //   - SameSite: No esta. No hay proteccion contra CSRF.
        //
        // Para evidenciar esto, abrir las DevTools del navegador (F12)
        // -> pestana Application -> Cookies, y verificar que la cookie
        // "sesion_usuario" NO tiene las banderas HttpOnly, Secure ni SameSite.
        // =============================================================

        setcookie('sesion_usuario', $usuario_db['usuario'], time() + 3600, '/');

        header('Location: perfil.php');
        exit;

    } else {

        // =============================================================
        // VULNERABLE - Caso 6: Mensaje de error generico
        // =============================================================
        // En este caso el mensaje es generico ("incorrectos"), lo cual
        // esta bien para el login. PERO si ocurre un error SQL (por
        // ejemplo, un SQL Injection con sintaxis incorrecta), NO se
        // captura la excepcion y PHP mostrara el error nativo de PDO
        // con: numero de error, mensaje completo, archivo, linea, y
        // la consulta SQL completa. Esto revela informacion tecnica
        // valiosa al atacante (estructura de tablas, nombres de
        // columnas, motor de base de datos, rutas del servidor).
        //
        // Para ver esta exposicion, intentar un payload que rompa la
        // sintaxis SQL, por ejemplo en usuario:  ' AND 1=CONVERT(int,
        // (SELECT TOP 1 table_name FROM information_schema.tables))--
        // =============================================================

        $mensaje = 'Usuario o contrasena incorrectos';
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - FastMarket</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Iniciar Sesion</h1>

        <?php if ($mensaje): ?>
            <p class="error"><?php echo $mensaje; ?></p>
        <?php endif; ?>

        <!-- CASO 7: El form apunta a HTTP, no HTTPS.
             No hay action="https://...", se usa el protocolo actual (HTTP). -->
        <form method="POST" action="">
            <label>Usuario:</label>
            <input type="text" name="usuario" placeholder="Ingresa tu usuario" required>

            <label>Contrasena:</label>
            <input type="password" name="password" placeholder="Ingresa tu contrasena" required>

            <button type="submit">Entrar</button>
        </form>

        <p><a href="registro.php">Registrarse</a></p>
    </div>
</body>
</html>
