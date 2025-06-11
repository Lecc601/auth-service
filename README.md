# Auth Service

## Descripción

`auth-service` es un microservicio dedicado a la autenticación y autorización de usuarios para el sistema Biblioteca Virtual. Implementado con Spring Boot, gestiona el registro, login, roles, permisos y emisión de tokens JWT para asegurar el acceso a los demás servicios.

---

## Tecnologías

- Java 17+
- Spring Boot
- Spring Security
- JWT (JSON Web Tokens)
- PostgreSQL (para almacenamiento de usuarios y roles)
- Redis (para manejo de sesiones y cache)
- Maven
- Docker (opcional)

---

## Funcionalidades principales

- Registro y autenticación de usuarios.
- Gestión de roles y permisos.
- Emisión y validación de tokens JWT.
- Protección de endpoints mediante Spring Security.
- Soporte para sesiones en Redis.
- Endpoints REST para operaciones de usuarios y roles.

---

## Cómo ejecutar el proyecto

### Requisitos previos

- Java 21+
- Maven
- PostgreSQL y Redis configurados (o contenedores Docker)

### Pasos

1. Clonar el repositorio:

```bash
git clone https://github.com/tu_usuario/auth-service.git
cd auth-service
