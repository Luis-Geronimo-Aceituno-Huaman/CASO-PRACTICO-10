<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error - FastMarket</title>
    <link rel="stylesheet" href="style.css">
    <style>
        .error-container {
            text-align: center;
            padding: 60px 20px;
        }
        .error-container h1 {
            color: #e74c3c;
            font-size: 3em;
            margin-bottom: 10px;
        }
        .error-container p {
            font-size: 1.2em;
            color: #555;
            margin-bottom: 30px;
        }
        .error-container .code {
            font-size: 4em;
            font-weight: bold;
            color: #ccc;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="error-container">
            <!--
                CORREGIDO (Caso 6): Pagina de error generica
                ============================================================
                VULNERABLE: En la version anterior, cuando ocurría un error
                PHP o SQL, se mostraba al usuario:
                  - El mensaje completo de error de PHP/MySQL
                  - La ruta del archivo en el servidor
                  - La linea del error
                  - La consulta SQL completa
                  - Version de PHP y MySQL
                  - Stack trace completo

                Esta informacion permitia al atacante:
                  1. Mapear la estructura de la BD
                  2. Identificar vulnerabilidades conocidas del stack
                  3. Conocer rutas del servidor para path traversal
                  4. Obtener credenciales si aparecen en errores de conexion

                Ahora el usuario solo ve:
                  - Un codigo de error generico (500)
                  - Un mensaje amigable
                  - Un boton para volver al inicio

                El detalle tecnico real queda registrado en:
                  - error_log() → archivo de log del servidor
                  - logs_seguridad → tabla de auditoria
                ============================================================
            -->

            <div class="code">500</div>
            <h1>Ha ocurrido un error</h1>
            <p>Por favor intenta mas tarde o contacta a soporte.</p>

            <a href="perfil.php"
               style="display:inline-block;padding:12px 24px;background:#3498db;color:#fff;border-radius:5px;text-decoration:none;font-weight:bold;">
                Volver al inicio
            </a>
        </div>
    </div>
</body>
</html>
