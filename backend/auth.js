const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

// مفتاح JWT (في الإنتاج خزنه في .env)
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';
const JWT_EXPIRES_IN = '7d';

// ============================================
// دوال مساعدة
// ============================================

// تشفير كلمة السر
const hashPassword = async (password) => {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(password, salt);
};

// مقارنة كلمة السر
const comparePassword = async (password, hash) => {
    return await bcrypt.compare(password, hash);
};

// إنشاء JWT Token
const generateToken = (userId, username) => {
    return jwt.sign(
        { id: userId, username: username },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
    );
};

// التحقق من JWT Token
const verifyToken = (token) => {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return null;
    }
};

// ============================================
// API Routes
// ============================================

// تسجيل مستخدم جديد (Register)
const register = async (req, res, pool) => {
    // التحقق من صحة البيانات
    await body('username').isLength({ min: 3 }).run(req);
    await body('email').isEmail().run(req);
    await body('password').isLength({ min: 6 }).run(req);
    
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    
    const { username, email, password, full_name } = req.body;
    
    try {
        // التحقق من وجود المستخدم
        const existingUser = await pool.query(
            'SELECT id FROM users WHERE email = $1 OR username = $2',
            [email, username]
        );
        
        if (existingUser.rows.length > 0) {
            return res.status(400).json({ 
                error: 'User already exists with this email or username' 
            });
        }
        
        // تشفير كلمة السر
        const hashedPassword = await hashPassword(password);
        
        // إضافة المستخدم
        const result = await pool.query(
            `INSERT INTO users (username, email, password_hash, is_verified) 
             VALUES ($1, $2, $3, $4) RETURNING id, username, email, created_at`,
            [username, email, hashedPassword, true] // true للتجربة، في الحقيقة احتاج تفعيل
        );
        
        const user = result.rows[0];
        
        // إضافة الملف الشخصي
        await pool.query(
            'INSERT INTO profiles (user_id, full_name) VALUES ($1, $2)',
            [user.id, full_name || username]
        );
        
        // إنشاء token
        const token = generateToken(user.id, user.username);
        
        // حفظ الجلسة
        await pool.query(
            `INSERT INTO sessions (user_id, token, device_info, ip_address, expires_at) 
             VALUES ($1, $2, $3, $4, NOW() + INTERVAL \'7 days\')`,
            [user.id, token, req.headers['user-agent'], req.ip]
        );
        
        res.status(201).json({
            message: 'User created successfully',
            user: {
                id: user.id,
                username: user.username,
                email: user.email
            },
            token
        });
        
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

// تسجيل الدخول (Login)
const login = async (req, res, pool) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }
    
    try {
        // البحث عن المستخدم
        const result = await pool.query(
            `SELECT id, username, email, password_hash, is_active, is_verified 
             FROM users WHERE email = $1`,
            [email]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const user = result.rows[0];
        
        // التحقق من كلمة السر
        const isValidPassword = await comparePassword(password, user.password_hash);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // التحقق من نشاط الحساب
        if (!user.is_active) {
            return res.status(401).json({ error: 'Account is disabled' });
        }
        
        // تحديث آخر تسجيل دخول
        await pool.query(
            'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
            [user.id]
        );
        
        // إنشاء token
        const token = generateToken(user.id, user.username);
        
        // حفظ الجلسة
        await pool.query(
            `INSERT INTO sessions (user_id, token, device_info, ip_address, expires_at) 
             VALUES ($1, $2, $3, $4, NOW() + INTERVAL \'7 days\')`,
            [user.id, token, req.headers['user-agent'], req.ip]
        );
        
        res.json({
            message: 'Login successful',
            user: {
                id: user.id,
                username: user.username,
                email: user.email
            },
            token
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

// التحقق من صحة Token (Verify)
const verify = async (req, res, pool) => {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        // التحقق من صحة token
        const decoded = verifyToken(token);
        if (!decoded) {
            return res.status(401).json({ error: 'Invalid token' });
        }
        
        // التحقق من وجود الجلسة
        const session = await pool.query(
            'SELECT * FROM sessions WHERE token = $1 AND expires_at > NOW()',
            [token]
        );
        
        if (session.rows.length === 0) {
            return res.status(401).json({ error: 'Session expired' });
        }
        
        // جلب بيانات المستخدم
        const user = await pool.query(
            `SELECT u.id, u.username, u.email, u.created_at, 
                    p.full_name, p.bio, p.avatar_url, p.phone
             FROM users u 
             LEFT JOIN profiles p ON u.id = p.user_id 
             WHERE u.id = $1`,
            [decoded.id]
        );
        
        res.json({
            valid: true,
            user: user.rows[0]
        });
        
    } catch (error) {
        console.error('Verify error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

// تسجيل الخروج (Logout)
const logout = async (req, res, pool) => {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (token) {
        await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
    }
    
    res.json({ message: 'Logged out successfully' });
};

// جلب بيانات المستخدم (Get Profile)
const getProfile = async (req, res, pool) => {
    const userId = req.userId; // من middleware التحقق
    
    try {
        const result = await pool.query(
            `SELECT u.id, u.username, u.email, u.created_at, u.last_login,
                    p.full_name, p.bio, p.avatar_url, p.phone, p.address, 
                    p.city, p.country, p.birth_date, p.website
             FROM users u 
             LEFT JOIN profiles p ON u.id = p.user_id 
             WHERE u.id = $1`,
            [userId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json(result.rows[0]);
        
    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

// تحديث الملف الشخصي (Update Profile)
const updateProfile = async (req, res, pool) => {
    const userId = req.userId;
    const { full_name, bio, phone, address, city, country, birth_date, website } = req.body;
    
    try {
        const result = await pool.query(
            `UPDATE profiles 
             SET full_name = COALESCE($1, full_name),
                 bio = COALESCE($2, bio),
                 phone = COALESCE($3, phone),
                 address = COALESCE($4, address),
                 city = COALESCE($5, city),
                 country = COALESCE($6, country),
                 birth_date = COALESCE($7, birth_date),
                 website = COALESCE($8, website),
                 updated_at = CURRENT_TIMESTAMP
             WHERE user_id = $9
             RETURNING *`,
            [full_name, bio, phone, address, city, country, birth_date, website, userId]
        );
        
        res.json({ 
            message: 'Profile updated successfully',
            profile: result.rows[0]
        });
        
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

module.exports = {
    register,
    login,
    verify,
    logout,
    getProfile,
    updateProfile,
    verifyToken
};