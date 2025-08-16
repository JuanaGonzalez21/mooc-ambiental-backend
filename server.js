require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3001;

// Configuración CORS corregida para desarrollo
app.use(cors({
  origin: function (origin, callback) {
    // Permitir solicitudes sin origin (como Postman) o desde localhost
    if (!origin || origin.includes('localhost') || origin.includes('127.0.0.1')) {
      return callback(null, true);
    }
    
    // Lista de orígenes permitidos
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:3001',
      'https://localhost:3000',
      'https://localhost:3001',
      process.env.FRONTEND_URL
    ].filter(Boolean);
    
    // Verificar si el origen está en la lista o permitir todos para desarrollo
    if (allowedOrigins.includes(origin) || process.env.NODE_ENV === 'development') {
      return callback(null, true);
    }
    
    // Permitir todos los orígenes temporalmente
    return callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Origin',
    'X-Requested-With',
    'Content-Type',
    'Accept',
    'Authorization',
    'Cache-Control',
    'X-HTTP-Method-Override'
  ],
  optionsSuccessStatus: 200
}));

app.use(express.json());

// Configuración de BD usando variables de entorno
const dbConfig = {
  host: process.env.DB_HOST || 'b34elnhyzjwh5mxllzff-mysql.services.clever-cloud.com',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'uzoqf3a0oexcwpvc',
  password: process.env.DB_PASSWORD || 'ppeNdtt4seRoNiMu3BiR',
  database: process.env.DB_NAME || 'b34elnhyzjwh5mxllzff'
};

const JWT_SECRET = process.env.JWT_SECRET || 'tu_clave_secreta_muy_segura_2024';

async function getConnection() {
  return await mysql.createConnection(dbConfig);
}

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role = 'STUDENT' } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Nombre, email y contraseña son requeridos'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        error: 'La contraseña debe tener al menos 6 caracteres'
      });
    }

    const connection = await getConnection();

    const [existingUser] = await connection.execute(
      'SELECT user_id FROM users WHERE email = ?',
      [email]
    );

    if (existingUser.length > 0) {
      await connection.end();
      return res.status(400).json({
        success: false,
        error: 'El email ya está registrado'
      });
    }

    const [roleResult] = await connection.execute(
      'SELECT role_id FROM roles WHERE role_name = ?',
      [role]
    );

    let roleId = 1;
    if (roleResult.length > 0) {
      roleId = roleResult[0].role_id;
    } else {
      await connection.execute(
        "INSERT IGNORE INTO roles (role_name, description) VALUES ('STUDENT', 'Estudiante'), ('INSTRUCTOR', 'Instructor')"
      );
      roleId = role === 'INSTRUCTOR' ? 2 : 1;
    }

    const nameParts = name.trim().split(' ');
    const firstName = nameParts[0] || name;
    const lastName = nameParts.slice(1).join(' ') || '';

    const [result] = await connection.execute(
      'INSERT INTO users (email, first_name, last_name, password_hash, role_id, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())',
      [email, firstName, lastName, password, roleId, true]
    );

    await connection.end();

    const token = jwt.sign(
      { 
        userId: result.insertId, 
        email: email,
        roleId: roleId 
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      success: true,
      message: 'Usuario registrado exitosamente',
      user: {
        id: result.insertId,
        email: email,
        firstName: firstName,
        lastName: lastName,
        roleId: roleId
      },
      token: token
    });

  } catch (error) {
    console.error('Error en registro:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Error interno del servidor' 
    });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Email y contraseña son requeridos' 
      });
    }

    const connection = await getConnection();
    
    const [users] = await connection.execute(`
      SELECT u.user_id, u.email, u.first_name, u.last_name, u.password_hash, 
             u.role_id, u.is_active, r.role_name
      FROM users u 
      LEFT JOIN roles r ON u.role_id = r.role_id 
      WHERE u.email = ?
    `, [email]);

    await connection.end();

    if (users.length === 0) {
      return res.status(401).json({ 
        success: false, 
        error: 'Credenciales incorrectas' 
      });
    }

    const user = users[0];

    if (!user.is_active) {
      return res.status(401).json({ 
        success: false, 
        error: 'Cuenta desactivada. Contacta al administrador' 
      });
    }

    if (password !== user.password_hash) {
      return res.status(401).json({ 
        success: false, 
        error: 'Credenciales incorrectas' 
      });
    }

    const token = jwt.sign(
      { 
        userId: user.user_id, 
        email: user.email,
        roleId: user.role_id 
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      message: 'Login exitoso',
      user: {
        id: user.user_id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        roleId: user.role_id,
        roleName: user.role_name || 'STUDENT'
      },
      token
    });

  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Error interno del servidor' 
    });
  }
});

app.post('/api/auth/verify', async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(401).json({ success: false, error: 'Token requerido' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    
    const connection = await getConnection();
    const [users] = await connection.execute(`
      SELECT u.user_id, u.email, u.first_name, u.last_name, u.role_id, 
             u.is_active, r.role_name
      FROM users u 
      LEFT JOIN roles r ON u.role_id = r.role_id 
      WHERE u.user_id = ?
    `, [decoded.userId]);
    await connection.end();

    if (users.length === 0 || !users[0].is_active) {
      return res.status(401).json({ success: false, error: 'Token inválido' });
    }

    res.json({
      success: true,
      user: {
        id: users[0].user_id,
        email: users[0].email,
        firstName: users[0].first_name,
        lastName: users[0].last_name,
        roleId: users[0].role_id,
        roleName: users[0].role_name || 'STUDENT'
      }
    });

  } catch (error) {
    console.error('Error verificando token:', error);
    res.status(401).json({ success: false, error: 'Token inválido' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.json({
    success: true,
    message: 'Logout exitoso'
  });
});

app.get('/api/test', (req, res) => {
  res.json({ message: 'Servidor funcionando correctamente' });
});

// API para obtener categorías
app.get('/api/categories', async (req, res) => {
  try {
    const connection = await getConnection();
    const [categories] = await connection.execute(`
      SELECT category_id, name, description, icon, color, created_at, updated_at
      FROM categories 
      ORDER BY name
    `);
    await connection.end();
    
    res.json({
      success: true,
      categories: categories
    });
  } catch (error) {
    console.error('Error obteniendo categorías:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// API para obtener cursos
app.get('/api/courses', async (req, res) => {
  try {
    const connection = await getConnection();
    const [courses] = await connection.execute(`
      SELECT 
        c.course_id,
        c.title,
        c.description,
        c.category_id,
        c.instructor_id,
        c.duration_hours,
        c.level,
        c.is_published,
        c.created_at,
        c.updated_at,
        c.name_course,
        cat.name as category_name,
        CONCAT(u.first_name, ' ', u.last_name) as instructor_name
      FROM courses c
      LEFT JOIN categories cat ON c.category_id = cat.category_id
      LEFT JOIN users u ON c.instructor_id = u.user_id
      WHERE c.is_published = 1
      ORDER BY c.created_at DESC
    `);
    await connection.end();
    
    res.json({
      success: true,
      courses: courses
    });
  } catch (error) {
    console.error('Error obteniendo cursos:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// API para obtener curso por ID
app.get('/api/courses/:courseId', async (req, res) => {
  try {
    const { courseId } = req.params;
    const connection = await getConnection();
    
    const [courses] = await connection.execute(`
      SELECT 
        c.course_id,
        c.title,
        c.description,
        c.category_id,
        c.instructor_id,
        c.duration_hours,
        c.level,
        c.is_published,
        c.created_at,
        c.updated_at,
        c.name_course,
        cat.name as category_name,
        cat.icon as category_icon,
        cat.color as category_color,
        CONCAT(u.first_name, ' ', u.last_name) as instructor_name,
        u.email as instructor_email
      FROM courses c
      LEFT JOIN categories cat ON c.category_id = cat.category_id
      LEFT JOIN users u ON c.instructor_id = u.user_id
      WHERE c.course_id = ? AND c.is_published = 1
    `, [courseId]);
    
    await connection.end();
    
    if (courses.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Curso no encontrado'
      });
    }
    
    res.json({
      success: true,
      course: courses[0]
    });
  } catch (error) {
    console.error('Error obteniendo curso:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// API para obtener curso por name_course
app.get('/api/courses/by-name/:courseName', async (req, res) => {
  try {
    const { courseName } = req.params;
    const connection = await getConnection();
    
    const [courses] = await connection.execute(`
      SELECT 
        c.course_id,
        c.title,
        c.description,
        c.category_id,
        c.instructor_id,
        c.duration_hours,
        c.level,
        c.is_published,
        c.created_at,
        c.updated_at,
        c.name_course,
        cat.name as category_name,
        cat.icon as category_icon,
        cat.color as category_color,
        CONCAT(u.first_name, ' ', u.last_name) as instructor_name,
        u.email as instructor_email
      FROM courses c
      LEFT JOIN categories cat ON c.category_id = cat.category_id
      LEFT JOIN users u ON c.instructor_id = u.user_id
      WHERE c.name_course = ? AND c.is_published = 1
    `, [courseName]);
    
    await connection.end();
    
    if (courses.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Curso no encontrado'
      });
    }
    
    res.json({
      success: true,
      course: courses[0]
    });
  } catch (error) {
    console.error('Error obteniendo curso por nombre:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/tables', async (req, res) => {
  try {
    const connection = await getConnection();
    const [tables] = await connection.execute('SHOW TABLES');
    await connection.end();
    
    const tableNames = tables.map(table => Object.values(table)[0]);
    res.json({ success: true, tables: tableNames });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/table/:tableName', async (req, res) => {
  try {
    const { tableName } = req.params;
    const connection = await getConnection();
    
    const [columns] = await connection.execute(`DESCRIBE ${tableName}`);
    const [data] = await connection.execute(`SELECT * FROM ${tableName} LIMIT 10`);
    const [count] = await connection.execute(`SELECT COUNT(*) as total FROM ${tableName}`);
    
    await connection.end();
    
    res.json({
      success: true,
      tableName,
      columns,
      data,
      total: count[0].total
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/table/:tableName', async (req, res) => {
  try {
    const { tableName } = req.params;
    const data = req.body;
    
    const connection = await getConnection();
    
    const columns = Object.keys(data).join(', ');
    const values = Object.values(data);
    const placeholders = values.map(() => '?').join(', ');
    
    const query = `INSERT INTO ${tableName} (${columns}) VALUES (${placeholders})`;
    const [result] = await connection.execute(query, values);
    
    await connection.end();
    
    res.json({
      success: true,
      message: 'Registro creado exitosamente',
      insertId: result.insertId
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Endpoint para obtener el progreso del usuario
app.get('/api/user/:userId/progress', async (req, res) => {
  try {
    const { userId } = req.params;
    
    const connection = await getConnection();
    
    // Obtener progreso detallado del usuario
    const [progressData] = await connection.execute(`
      SELECT 
        p.progress_id,
        p.user_id,
        p.lesson_id,
        p.completed_at,
        p.time_spent,
        p.is_completed,
        c.title as course_title,
        c.course_id,
        c.duration_hours as course_duration
      FROM progress p
      LEFT JOIN courses c ON p.lesson_id = c.course_id
      WHERE p.user_id = ?
      ORDER BY p.completed_at DESC
    `, [userId]);
    
    // Calcular estadísticas generales
    const [stats] = await connection.execute(`
      SELECT 
        COUNT(*) as total_lessons,
        COUNT(CASE WHEN is_completed = 1 THEN 1 END) as completed_lessons,
        SUM(time_spent) as total_time_spent,
        COUNT(DISTINCT lesson_id) as unique_courses
      FROM progress 
      WHERE user_id = ?
    `, [userId]);
    
    // Obtener cursos únicos con progreso
    const [courseProgress] = await connection.execute(`
      SELECT 
        c.course_id,
        c.title,
        c.duration_hours,
        COUNT(p.progress_id) as lessons_taken,
        COUNT(CASE WHEN p.is_completed = 1 THEN 1 END) as lessons_completed,
        SUM(p.time_spent) as time_spent,
        MAX(p.completed_at) as last_accessed
      FROM courses c
      LEFT JOIN progress p ON c.course_id = p.lesson_id AND p.user_id = ?
      WHERE p.user_id IS NOT NULL
      GROUP BY c.course_id, c.title, c.duration_hours
      ORDER BY last_accessed DESC
    `, [userId]);
    
    await connection.end();
    
    // Calcular progreso porcentual por curso
    const coursesWithProgress = courseProgress.map(course => {
      const progressPercentage = course.duration_hours > 0 
        ? Math.round((course.time_spent / (course.duration_hours * 60)) * 100) // Convertir horas a minutos
        : 0;
      
      return {
        ...course,
        progress_percentage: Math.min(progressPercentage, 100), // No más del 100%
        status: course.lessons_completed > 0 ? 'in-progress' : 'not-started'
      };
    });
    
    res.json({
      success: true,
      data: {
        user_id: userId,
        progress_details: progressData,
        statistics: stats[0] || {
          total_lessons: 0,
          completed_lessons: 0,
          total_time_spent: 0,
          unique_courses: 0
        },
        courses: coursesWithProgress
      }
    });
    
  } catch (error) {
    console.error('Error obteniendo progreso del usuario:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Error interno del servidor',
      details: error.message 
    });
  }
});

const server = app.listen(PORT, async () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
  
  try {
    const connection = await getConnection();
    console.log('Conexión a MySQL exitosa');
    
    await connection.execute(`
      INSERT IGNORE INTO roles (role_name, description) VALUES 
      ('STUDENT', 'Estudiante del MOOC'),
      ('INSTRUCTOR', 'Instructor del MOOC')
    `);
    
    await connection.end();
    console.log('Servidor listo para recibir peticiones');
  } catch (error) {
    console.error('Error conectando a MySQL:', error.message);
  }
});

process.on('SIGINT', () => {
  console.log('Cerrando servidor...');
  server.close(() => {
    console.log('Servidor cerrado correctamente');
    process.exit(0);
  });
});

process.on('SIGTERM', () => {
  console.log('Cerrando servidor...');
  server.close(() => {
    console.log('Servidor cerrado correctamente');
    process.exit(0);
  });
});