-- ============================================================
-- CASO PRACTICO 10 - FastMarket S.A.C.
-- Base de datos: fastmarket_db
-- Curso: Desarrollo de Sistemas Web (FISI - UNMSM)
-- Proposito: Fines educativos sobre seguridad OWASP Top 10
-- ============================================================

CREATE DATABASE IF NOT EXISTS fastmarket_db
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;

USE fastmarket_db;

-- ------------------------------------------------------------
-- Tabla: usuarios
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS usuarios (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  nombre        VARCHAR(100)  NOT NULL,
  email         VARCHAR(150)  NOT NULL UNIQUE,
  usuario       VARCHAR(50)   NOT NULL UNIQUE,
  password      VARCHAR(255)  NOT NULL,
  rol           ENUM('cliente', 'admin') NOT NULL DEFAULT 'cliente',
  fecha_registro DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Tabla: productos
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS productos (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  nombre      VARCHAR(150) NOT NULL,
  descripcion TEXT,
  precio      DECIMAL(10,2) NOT NULL DEFAULT 0.00,
  stock       INT           NOT NULL DEFAULT 0,
  imagen      VARCHAR(255)  DEFAULT NULL
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Tabla: comentarios
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS comentarios (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  id_usuario  INT NOT NULL,
  id_producto INT NOT NULL,
  contenido   TEXT NOT NULL,
  fecha       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (id_usuario)  REFERENCES usuarios(id) ON DELETE CASCADE,
  FOREIGN KEY (id_producto) REFERENCES productos(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Tabla: logs_seguridad
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS logs_seguridad (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  tipo_evento  ENUM('intento_fallido', 'cambio_password', 'acceso_admin', 'modificacion_producto') NOT NULL,
  usuario      VARCHAR(50)  DEFAULT NULL,
  ip           VARCHAR(45)  DEFAULT NULL,
  detalle      TEXT,
  fecha        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ============================================================
-- DATOS DE PRUEBA
-- ============================================================

-- Usuarios
-- NOTA version vulnerable: passwords en TEXTO PLANO (Caso 9)
-- NOTA version corregida: se asume que se migrarian con password_hash()

-- Admin: admin / admin123
INSERT INTO usuarios (nombre, email, usuario, password, rol)
VALUES ('Carlos Admin', 'admin@fastmarket.com', 'admin', 'admin123', 'admin');

-- Cliente 1: juan / juan2024
INSERT INTO usuarios (nombre, email, usuario, password, rol)
VALUES ('Juan Perez', 'juan@correo.com', 'juan', 'juan2024', 'cliente');

-- Cliente 2: maria / maria2024
INSERT INTO usuarios (nombre, email, usuario, password, rol)
VALUES ('Maria Lopez', 'maria@correo.com', 'maria', 'maria2024', 'cliente');

-- Productos
INSERT INTO productos (nombre, descripcion, precio, stock, imagen) VALUES
('Arroz Extra', 'Arroz de 5kg grado extra', 12.50, 200, NULL),
('Aceite Vegetal', 'Aceite vegetal de 1L', 8.90, 150, NULL),
('Leche Entera', 'Leche entera de 1L', 4.20, 300, NULL);

-- Comentarios de ejemplo
INSERT INTO comentarios (id_usuario, id_producto, contenido) VALUES
(2, 1, 'Muy buen arroz, lo recomiendo.'),
(3, 2, 'Buen precio para el aceite.'),
(2, 3, 'La leche llego en buen estado.');
