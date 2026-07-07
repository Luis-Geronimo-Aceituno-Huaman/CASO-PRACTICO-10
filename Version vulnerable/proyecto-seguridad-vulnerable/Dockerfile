FROM php:8.2-apache

# Instalar extensiones PHP para MySQL
RUN docker-php-ext-install pdo_mysql mysqli

# Habilitar mod_rewrite (opcional)
RUN a2enmod rewrite

# Copiar php.ini con display_errors ON (para demostrar vulnerabilidades)
RUN echo "display_errors = On" >> /usr/local/etc/php/php.ini \
    && echo "error_reporting = E_ALL" >> /usr/local/etc/php/php.ini \
    && echo "log_errors = On" >> /usr/local/etc/php/php.ini

EXPOSE 80
