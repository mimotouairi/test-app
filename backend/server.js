const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
require('dotenv').config();

const app = express();
const port = 3000;

// Middleware
app.use(cors());
app.use(express.json());

// اتصال PostgreSQL
const pool = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'postgres',
    password: process.env.DB_PASSWORD || '2002',
    port: process.env.DB_PORT || 5432,
});

// اختبار الاتصال بقاعدة البيانات
pool.connect((err, client, release) => {
    if (err) {
        console.error('❌ PostgreSQL connection error:', err.message);
    } else {
        console.log('✅ Connected to PostgreSQL successfully');
        release();
    }
});

// إنشاء جدول users إذا لم يكن موجوداً
const createTable = async () => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('✅ Users table created/verified successfully');
        
        // إضافة مستخدم تجريبي (اختياري)
        const result = await pool.query('SELECT COUNT(*) FROM users');
        if (parseInt(result.rows[0].count) === 0) {
            await pool.query(
                'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)',
                ['admin', 'admin@example.com', 'admin123']
            );
            console.log('✅ Test user added: admin@example.com / admin123');
        }
    } catch (err) {
        console.error('❌ Error creating table:', err.message);
    }
};

createTable();

// ============================================
// API Routes
// ============================================

// الصفحة الرئيسية
app.get('/', (req, res) => {
    res.json({ 
        message: '🚀 API Server is running!',
        database: process.env.DB_NAME,
        time: new Date().toISOString(),
        endpoints: {
            test: 'GET /api/test',
            users: 'GET /api/users',
            createUser: 'POST /api/users'
        }
    });
});

// Endpoint للاختبار
app.get('/api/test', (req, res) => {
    res.json({ 
        message: '✅ Test endpoint is working!',
        timestamp: new Date().toISOString()
    });
});

// جلب جميع المستخدمين
app.get('/api/users', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, email, created_at FROM users ORDER BY id DESC');
        res.json({
            success: true,
            count: result.rows.length,
            users: result.rows
        });
    } catch (err) {
        console.error('Error fetching users:', err.message);
        res.status(500).json({ 
            success: false, 
            error: err.message 
        });
    }
});

// إضافة مستخدم جديد
app.post('/api/users', async (req, res) => {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
        return res.status(400).json({ 
            success: false,
            error: 'Username, email and password are required' 
        });
    }
    
    try {
        const result = await pool.query(
            'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email, created_at',
            [username, email, password]
        );
        res.status(201).json({
            success: true,
            message: 'User created successfully',
            user: result.rows[0]
        });
    } catch (err) {
        console.error('Error creating user:', err.message);
        if (err.code === '23505') {
            res.status(400).json({ 
                success: false,
                error: 'Username or email already exists' 
            });
        } else {
            res.status(500).json({ 
                success: false, 
                error: err.message 
            });
        }
    }
});

// جلب مستخدم محدد
app.get('/api/users/:id', async (req, res) => {
    const { id } = req.params;
    
    try {
        const result = await pool.query(
            'SELECT id, username, email, created_at FROM users WHERE id = $1',
            [id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ 
                success: false,
                error: 'User not found' 
            });
        }
        
        res.json({
            success: true,
            user: result.rows[0]
        });
    } catch (err) {
        console.error('Error fetching user:', err.message);
        res.status(500).json({ 
            success: false, 
            error: err.message 
        });
    }
});

// حذف مستخدم
app.delete('/api/users/:id', async (req, res) => {
    const { id } = req.params;
    
    try {
        const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING id', [id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ 
                success: false,
                error: 'User not found' 
            });
        }
        
        res.json({
            success: true,
            message: 'User deleted successfully'
        });
    } catch (err) {
        console.error('Error deleting user:', err.message);
        res.status(500).json({ 
            success: false, 
            error: err.message 
        });
    }
});

// تشغيل السيرفر
app.listen(port, () => {
    console.log(`\n🚀 Server running on http://localhost:${port}`);
    console.log(`📝 Test endpoints:`);
    console.log(`   - http://localhost:${port}/`);
    console.log(`   - http://localhost:${port}/api/test`);
    console.log(`   - http://localhost:${port}/api/users`);
    console.log(`💾 Database: ${process.env.DB_NAME}\n`);
});