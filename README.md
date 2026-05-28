# 🌱 MOOC Ambiental — Backend

> API REST para [MoocAmbiental](https://mooc-ambiental.vercel.app), una plataforma de cursos online sobre medio ambiente y sostenibilidad. Construida con Node.js, Express y MySQL, con autenticación basada en JWT y contraseñas hasheadas con bcrypt.

![Node](https://img.shields.io/badge/Node.js-18.x-339933?logo=nodedotjs&logoColor=white)
![Express](https://img.shields.io/badge/Express-5-000000?logo=express&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL-4479A1?logo=mysql&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-000000?logo=jsonwebtokens&logoColor=white)

🔗 **Repo del frontend:** [mooc-ambiental-frontend](https://github.com/JuanaGonzalez21/mooc-ambiental-frontend)  
🌐 **Sitio en vivo:** [mooc-ambiental.vercel.app](https://mooc-ambiental.vercel.app)

---

## 🛠️ Tecnologías

- **Node.js 18+** — Entorno de ejecución
- **Express 5** — Framework web minimalista
- **MySQL** (mysql2/promise) — Base de datos relacional
- **JWT** (jsonwebtoken) — Autenticación con tokens
- **bcrypt** — Hasheo seguro de contraseñas
- **CORS** — Configuración de peticiones cross-origin
- **dotenv** — Manejo de variables de entorno

## ✨ Características

- 🔐 Registro y login de usuarios con contraseñas hasheadas
- 🎫 Autenticación con tokens JWT
- 👥 Sistema de roles (Estudiante, Instructor, Administrador)
- 📚 Gestión de cursos
- 🌐 API REST consumible desde el frontend Next.js
- 🛡️ Manejo seguro de credenciales mediante variables de entorno

## 🚀 Instalación local

### Prerrequisitos

- Node.js 18.x o superior
- npm
- Una base de datos MySQL accesible

### Pasos

1. **Clonar el repositorio**

```bash
   git clone https://github.com/JuanaGonzalez21/mooc-ambiental-backend.git
   cd mooc-ambiental-backend
```

2. **Instalar dependencias**

```bash
   npm install
```

3. **Configurar variables de entorno**

   Copia la plantilla y rellénala con tus valores:

```bash
   cp .env.example .env
```

4. **Levantar el servidor en modo desarrollo**

```bash
   npm run dev
```

   El servidor quedará disponible en `http://localhost:3001`.

## 🔑 Variables de entorno

| Variable | Descripción |
|----------|-------------|
| `DB_HOST` | Host de la base de datos MySQL |
| `DB_PORT` | Puerto de la base de datos (por defecto `3306`) |
| `DB_USER` | Usuario de la base de datos |
| `DB_PASSWORD` | Contraseña de la base de datos |
| `DB_NAME` | Nombre de la base de datos |
| `JWT_SECRET` | Cadena larga y aleatoria para firmar tokens |
| `PORT` | Puerto del servidor (por defecto `3001`) |
| `NODE_ENV` | `development` o `production` |
| `FRONTEND_URL` | URL del frontend (para CORS) |

> ⚠️ Nunca subas el archivo `.env` al repositorio. El `.gitignore` ya lo cubre.

## 📡 Endpoints de la API

### Autenticación

| Método | Ruta | Descripción | Requiere Auth |
|--------|------|-------------|---------------|
| `POST` | `/api/auth/register` | Registra un nuevo usuario | ❌ |
| `POST` | `/api/auth/login` | Inicia sesión y devuelve un JWT | ❌ |

#### Ejemplo: Registro

**Request** `POST /api/auth/register`

```json
{
  "name": "Juana González",
  "email": "juana@example.com",
  "password": "miContraseñaSegura",
  "role": "STUDENT"
}
```

**Validaciones:**
- `name`, `email` y `password` son obligatorios
- La contraseña debe tener al menos 6 caracteres
- `role` es opcional (`STUDENT` por defecto)

<!-- Cuando agregues más endpoints (cursos, login, etc.), documéntalos aquí siguiendo el mismo formato -->

## 📁 Estructura del proyecto
