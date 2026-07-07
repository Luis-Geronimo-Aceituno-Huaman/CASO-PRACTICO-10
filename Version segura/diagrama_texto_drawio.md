# Versión en texto (para recrear manualmente en draw.io)

## Estructura de subgraphs (capas)

### 1. Cliente (Navegador)
- **Nodo:** Usuario ingresa credenciales / datos
- **Flecha a →** Formulario HTML (validación básica en cliente)

### 2. Servidor de Aplicación (Apache/PHP)

#### 2.1 Capa TLS/SSL
- HTTPS Obligatorio (config.php)
- Header HSTS (Strict-Transport-Security)

#### 2.2 Capa de Validación y Sanitización
- filter_var() → VALIDATE_EMAIL, VALIDATE_INT
- preg_match() → nombre: solo letras, max 50
- strlen() → contenido: max 300 chars
- Detección de patrones sospechosos (<script>, UNION SELECT, etc.)
- htmlspecialchars() → ENT_QUOTES, UTF-8 (SANITIZACIÓN DE SALIDA)

#### 2.3 Capa de Autenticación
- session_set_cookie_params() → httponly: true, secure: true, samesite: Strict
- session_start() → session_regenerate_id(true)
- password_hash() → PASSWORD_DEFAULT (bcrypt)
- password_verify() → comparación segura

#### 2.4 Capa de Autorización
- ¿Sesión activa? ($_SESSION['id_usuario'])
  - No → HTTP 403 - Mensaje genérico
  - Sí → ¿ID solicitado = ID de sesión?
    - Sí → ✅ Acceso concedido
    - No → ¿Rol = admin?
      - Sí → Registrar acceso admin en logs_seguridad → ✅ Acceso concedido
      - No → Registrar intento sospechoso → ❌ HTTP 403

#### 2.5 Lógica de Negocio
- login.php
- comentarios.php
- perfil.php
- productos.php

#### 2.6 Carga de Archivos (rama independiente)
- Validar extension (whitelist: jpg, jpeg, png, webp)
- Validar MIME real (finfo_file())
- Validar imagen real (getimagesize())
- Validar tamaño (max 2MB)
- Renombrar archivo (bin2hex(random_bytes(8)))
- → move_uploaded_file() a /uploads/ (.htaccess bloquea PHP)
- → registrarEvento(modificacion_producto)

#### 2.7 Acceso a Datos
- PDO Connection (ATTR_EMULATE_PREPARES = false)
- prepare()
- execute([:param => valor])
- → Query parametrizada → Base de Datos

### 3. Seguridad Transversal

#### 3.1 Manejo de Errores Centralizado
- set_error_handler() / set_exception_handler() / register_shutdown_function()
- → error_log() → Archivo del servidor (detalle técnico)
- → logs_seguridad (tipo_evento = 'error_sistema')
- → error_generico.php (HTTP 500 - Mensaje genérico)
- **Conecta con:** Todas las capas del servidor (intercepta excepciones)

#### 3.2 Logging / Auditoría
- registrarEvento()
- → Tabla logs_seguridad (intento_fallido, cambio_password, acceso_admin, modificacion_producto, intento_sospechoso)
- **Recibe eventos de:** Autenticación, Autorización, Carga de Archivos

### 4. Base de Datos MySQL
- tabla: usuarios (id, nombre, email, usuario, password, rol, fecha_registro)
- tabla: productos (id, nombre, descripcion, precio, stock, imagen)
- tabla: comentarios (id, id_usuario, id_producto, contenido, fecha)
- tabla: logs_seguridad (id, tipo_evento, usuario, ip, detalle, fecha)

---

## Flechas principales (flujo de datos)

1. Cliente → HTTPS → Capa TLS/SSL
2. Capa TLS → Capa de Validación
3. Capa de Validación → Capa de Autenticación
4. Capa de Autenticación → Capa de Autorización
5. Capa de Autorización → Lógica de Negocio
6. Lógica de Negocio → Carga de Archivos (rama) OR Acceso a Datos
7. Acceso a Datos → Base de Datos

## Flechas secundarias (seguridad transversal)

8. Manejo de Errores ←→ Todas las capas (líneas punteadas)
9. Logging ← Autenticación (evento: intento_fallido / acceso_admin)
10. Logging ← Autorización (evento: intento_sospechoso / acceso_admin)
11. Logging ← Carga de Archivos (evento: modificacion_producto / intento_sospechoso)
12. Logging → Base de Datos (INSERT INTO logs_seguridad)
13. Carga de Archivos → /uploads/ (carpeta protegida)

---

## Colores sugeridos para draw.io

| Capa | Color de fondo | Color de borde |
|------|---------------|----------------|
| Cliente | #E3F2FD (azul claro) | #1565C0 |
| TLS/SSL | #F3E5F5 (púrpura claro) | #7B1FA2 |
| Validación | #F3E5F5 | #7B1FA2 |
| Autenticación | #F3E5F5 | #7B1FA2 |
| Autorización | #F3E5F5 | #7B1FA2 |
| Lógica de Negocio | #F3E5F5 | #7B1FA2 |
| Carga de Archivos | #F3E5F5 | #7B1FA2 |
| PDO | #F3E5F5 | #7B1FA2 |
| Manejo de Errores | #FCE4EC (rojo claro) | #C62828 |
| Logging | #FFF8E1 (ámbar claro) | #F57F17 |
| Base de Datos | #E8F5E9 (verde claro) | #2E7D32 |
