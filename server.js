const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_financial_key_2024';

// Database Connection Configuration
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: { rejectUnauthorized: false }
});

// Connect to Database and Create Tables
db.connect((err) => {
    if (err) {
        console.error('❌ Database connection failed:', err.message);
        return;
    }
    console.log('✅ Successfully connected to MySQL database!');

    // 1. إنشاء جدول المستخدمين أولاً
    const createUsersTable = `
        CREATE TABLE IF NOT EXISTS Users (
            Id INT AUTO_INCREMENT PRIMARY KEY,
            Username VARCHAR(50) UNIQUE NOT NULL,
            PasswordHash VARCHAR(255) NOT NULL,
            Role VARCHAR(20) DEFAULT 'user'
        )
    `;

    // 2. إنشاء جدول العمليات (تمت إضافة UserId كـ Foreign Key)
    const createTransactionsTable = `
        CREATE TABLE IF NOT EXISTS Transactions (
            Id INT AUTO_INCREMENT PRIMARY KEY,
            UserId INT NOT NULL,
            Description VARCHAR(255) NOT NULL,
            Amount DECIMAL(10, 2) NOT NULL,
            TransactionDate DATE NOT NULL,
            Category VARCHAR(100) NOT NULL,
            Type VARCHAR(50) NOT NULL,
            FOREIGN KEY (UserId) REFERENCES Users(Id) ON DELETE CASCADE
        )
    `;

    // تنفيذ إنشاء الجداول بالترتيب الصحيح
    db.query(createUsersTable, (err) => {
        if (err) console.error('❌ Error creating Users table:', err.message);
        else {
            console.log('✅ Users table is ready!');

            db.query(createTransactionsTable, (err) => {
                if (err) console.error('❌ Error creating Transactions table:', err.message);
                else console.log('✅ Transactions table is ready!');
            });
        }
    });
});

// ==========================================
// 🛡️ Middleware: للتحقق من هوية المستخدم (حارس الباك إند)
// ==========================================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // استخراج التوكن

    if (!token) return res.status(401).json({ error: 'غير مصرح لك، يرجى تسجيل الدخول' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'انتهت صلاحية الجلسة' });
        req.user = user; // { id, username, role } سنستخدم req.user.id لاحقاً
        next();
    });
};

// ==========================================
// 🔐 نظام الحسابات (Authentication)
// ==========================================

// 🆕 مسار إنشاء حساب جديد (Register)
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'مطلوب إدخال اسم المستخدم وكلمة المرور' });
    }

    try {
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        const query = 'INSERT INTO Users (Username, PasswordHash) VALUES (?, ?)';
        db.query(query, [username, passwordHash], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'اسم المستخدم مسجل مسبقاً' });
                return res.status(500).json({ error: 'Database error' });
            }
            res.status(201).json({ message: 'تم إنشاء الحساب بنجاح!' });
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});
// مسار تسجيل الدخول (Login)
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;

    const query = 'SELECT * FROM Users WHERE Username = ?';
    db.query(query, [username], async (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        
        if (results.length === 0) return res.status(404).json({ error: 'لا يوجد حساب مسجل بهذا الاسم' });

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.PasswordHash);
        
        if (!isMatch) return res.status(401).json({ error: 'كلمة المرور غير صحيحة' });

        // 1. التوكن المؤقت (لواجهة الموقع - 24 ساعة)
        const token = jwt.sign(
            { id: user.Id, username: user.Username, role: user.Role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        // 2. التوكن الدائم (للاختصارات - 10 سنوات)
        const mobileToken = jwt.sign(
            { id: user.Id, username: user.Username, role: user.Role },
            JWT_SECRET,
            { expiresIn: '3650d' }
        );

        // إرسال الاثنين معاً
        res.json({ message: 'تم الدخول بنجاح', token, mobileToken, user: { username: user.Username, id: user.Id } });
    });
});

// ==========================================
// 📱 مسار إصدار رمز الآيفون طويل الأمد (Personal Access Token)
// ==========================================
app.get('/api/auth/mobile-token', authenticateToken, (req, res) => {
    // نأخذ بيانات المستخدم من التوكن العادي (الصالح حالياً)
    const user = req.user;

    // نصدر توكن جديد ينتهي بعد 10 سنوات (3650d) مخصص فقط للآيفون
    const mobileToken = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: '3650d' }
    );

    res.json({ mobileToken });
});
// ==========================================
// 💰 مسارات العمليات المالية (محمية بالـ authenticateToken)
// ==========================================

// جلب عمليات المستخدم الذي سجل دخوله فقط
app.get('/api/transactions', authenticateToken, (req, res) => {
    const userId = req.user.id; // أخذنا رقم المستخدم من التوكن
    const query = 'SELECT * FROM Transactions WHERE UserId = ? ORDER BY TransactionDate DESC, Id DESC';

    db.query(query, [userId], (err, results) => {
        if (err) return res.status(500).json({ error: 'Failed to fetch transactions' });
        res.json(results);
    });
});

// إضافة عملية مالية جديدة وربطها بالمستخدم
app.post('/api/transactions', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const { Description, Amount, TransactionDate, Category, Type } = req.body;

    const query = 'INSERT INTO Transactions (UserId, Description, Amount, TransactionDate, Category, Type) VALUES (?, ?, ?, ?, ?, ?)';
    const values = [userId, Description, Amount, TransactionDate, Category, Type];

    db.query(query, values, (err, result) => {
        if (err) return res.status(500).json({ error: 'Failed to save transaction' });
        res.status(201).json({ Id: result.insertId, UserId: userId, Description, Amount, TransactionDate, Category, Type });
    });
});

// تحديث عملية مالية (بشرط أن تكون تابعة للمستخدم نفسه)
app.put('/api/transactions/:id', authenticateToken, (req, res) => {
    const transactionId = req.params.id;
    const userId = req.user.id;
    const { Description, Amount, TransactionDate, Category, Type } = req.body;

    const query = 'UPDATE Transactions SET Description=?, Amount=?, TransactionDate=?, Category=?, Type=? WHERE Id=? AND UserId=?';
    const values = [Description, Amount, TransactionDate, Category, Type, transactionId, userId];

    db.query(query, values, (err, result) => {
        if (err) return res.status(500).json({ error: 'Failed to update transaction' });
        res.json({ message: 'Transaction updated successfully' });
    });
});

// حذف عملية مالية (بشرط أن تكون تابعة للمستخدم نفسه)
app.delete('/api/transactions/:id', authenticateToken, (req, res) => {
    const transactionId = req.params.id;
    const userId = req.user.id;

    const query = 'DELETE FROM Transactions WHERE Id=? AND UserId=?';

    db.query(query, [transactionId, userId], (err, result) => {
        if (err) return res.status(500).json({ error: 'Failed to delete transaction' });
        res.json({ message: 'Transaction deleted successfully' });
    });
});

// ==========================================
// 🚀 استلام الرسائل الخام من الآيفون (محمية ومربوطة بالمستخدم)
// ==========================================
// 👇 أضفنا authenticateToken هنا لحماية المسار
app.post('/api/raw-sms', authenticateToken, (req, res) => {

    // 👇 لم نعد بحاجة لاستقبال userId من الهاتف، السيرفر سيعرفه فوراً من التوكن!
    const { message: rawText } = req.body;
    const userId = req.user.id; // استخراج رقم المستخدم بأمان من التوكن

    const ignoreKeywords = ["رمز مؤقت", "رمز التفعيل", "تم تفعيل", "إضافة مستفيد", "كود"];
    if (!rawText || rawText.trim().length < 10 || ignoreKeywords.some(key => rawText.includes(key))) {
        return res.json({ status: "ignored" });
    }

    let amount = 0;
    const amountMatch = rawText.match(/(?:مبلغ:SAR|بـSAR|المبلغ:SAR|مبلغ|بـ|SAR)\s*([\d,.]+)/i);
    if (amountMatch) amount = parseFloat(amountMatch[1].replace(/,/g, ''));

    const isIncome = rawText.includes("واردة") || rawText.includes("إيداع");
    const type = isIncome ? "income" : "expense";
    let description = "Bank Transaction";

    const nameMatches = rawText.match(/(?:لـ|من:|الى:|من)\s*([^\d\n\r;*]{3,})/gi);
    if (nameMatches) {
        const rawName = nameMatches[nameMatches.length - 1];
        description = rawName.replace(/(?:لـ|من:|الى:|من)/i, '').trim();
    }
    if (description.toLowerCase().includes("بطاقة")) description = "Point of Sale / Card";

    const category = isIncome ? "Salary/Transfer" : "General/Spending";

    // 👇 إدخال العملية مع رقم المستخدم المستخرج من التوكن
    const query = 'INSERT INTO Transactions (UserId, Description, Amount, TransactionDate, Category, Type) VALUES (?, ?, ?, NOW(), ?, ?)';
    db.query(query, [userId, description, amount, category, type], (err, result) => {
        if (err) return res.status(500).json({ error: 'Database save failed' });
        res.json({ success: true, id: result.insertId });
    });
});


// ==========================================
// 🤖 المستشار المالي الذكي (AI Advisor)
// ==========================================
const { GoogleGenerativeAI } = require('@google/generative-ai');

app.get('/api/advisor', authenticateToken, (req, res) => {
    const userId = req.user.id;
    
    // نجلب عمليات الشهر الحالي فقط للتحليل
    const query = 'SELECT * FROM Transactions WHERE UserId = ? AND MONTH(TransactionDate) = MONTH(CURRENT_DATE()) AND YEAR(TransactionDate) = YEAR(CURRENT_DATE())';

    db.query(query, [userId], async (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        if (results.length === 0) {
            return res.json({ advice: 'أهلاً بك! قم بإضافة بعض العمليات المالية هذا الشهر لأتمكن من تحليل بياناتك وتقديم نصائح مخصصة لك. 📈' });
        }

        let income = 0;
        let expense = 0;
        let categories = {};

        // تحليل وتجميع البيانات
        results.forEach(t => {
            const amt = Number(t.Amount);
            if (t.Type === 'income') income += amt;
            else if (t.Type === 'expense') {
                expense += amt;
                categories[t.Category] = (categories[t.Category] || 0) + amt;
            }
        });

        // 🧠 إعداد الـ Prompt الاحترافي للذكاء الاصطناعي
        const prompt = `أنت مستشار مالي خبير. بناءً على بيانات المستخدم لهذا الشهر:
        - إجمالي الدخل: ${income} ريال.
        - إجمالي المصروفات: ${expense} ريال.
        - تفاصيل المصروفات حسب التصنيف: ${JSON.stringify(categories)}.
        
        اكتب نصيحة مالية واحدة ذكية ومباشرة باللغة العربية (سطرين كحد أقصى). 
        كن مشجعاً، وإذا كان الصرف أعلى من الدخل حذره بلطف. لا تستخدم أي مقدمات مثل "بناءً على البيانات".`;

try {
            const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
            const model = genAI.getGenerativeModel({ model: "gemini-2.0-flash" });
            
            const result = await model.generateContent(prompt);
            const advice = result.response.text();
            
            res.json({ advice: advice.trim() });
        } catch (error) {
            console.error('AI Error:', error);
            // 👇 التعديل هنا: جعلنا السيرفر يرسل الخطأ التقني الفعلي للتطبيق
            res.status(500).json({ error: `خطأ من جوجل: ${error.message}` }); 
        }
    });
});


// Dynamic Port
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`🚀 Server is now running on port: ${PORT}`);
});