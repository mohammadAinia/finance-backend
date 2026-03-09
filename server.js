const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto'); // 👈 استيراد مكتبة التشفير الخاصة بـ Node.js
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_financial_key_2024';

// ==========================================
// 🔐 محرك تشفير البيانات (AES-256-CBC)
// ==========================================
// يجب أن يكون المفتاح 32 حرفاً بالضبط (يمكنك تغييره في ملف .env لاحقاً)
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '12345678901234567890123456789012'; 
const IV_LENGTH = 16; 

function encrypt(text) {
    if (!text) return text;
    let iv = crypto.randomBytes(IV_LENGTH);
    let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text.toString());
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    if (!text) return text;
    try {
        let textParts = text.split(':');
        let iv = Buffer.from(textParts.shift(), 'hex');
        let encryptedText = Buffer.from(textParts.join(':'), 'hex');
        let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    } catch (error) {
        // إذا فشل فك التشفير (مثلاً البيانات القديمة غير مشفرة)، نعيدها كما هي لتجنب انهيار التطبيق
        return text; 
    }
}

// Database Connection Configuration
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: { rejectUnauthorized: false }
});

db.connect((err) => {
    if (err) {
        console.error('❌ Database connection failed:', err.message);
        return;
    }
    console.log('✅ Successfully connected to MySQL database!');

    const createUsersTable = `
        CREATE TABLE IF NOT EXISTS Users (
            Id INT AUTO_INCREMENT PRIMARY KEY,
            Username VARCHAR(50) UNIQUE NOT NULL,
            PasswordHash VARCHAR(255) NOT NULL,
            Role VARCHAR(20) DEFAULT 'user'
        )
    `;

    // 💡 تم تحويل Description و Notes إلى TEXT لتستوعب النصوص المشفرة الطويلة
    const createTransactionsTable = `
        CREATE TABLE IF NOT EXISTS Transactions (
            Id INT AUTO_INCREMENT PRIMARY KEY,
            UserId INT NOT NULL,
            Amount DECIMAL(10, 2) NOT NULL,
            Type ENUM('income', 'expense') NOT NULL,
            Category VARCHAR(100) NOT NULL,
            SubCategory VARCHAR(100) DEFAULT 'عام',
            Description TEXT NOT NULL, 
            Notes TEXT DEFAULT NULL,
            TransactionDate DATETIME NOT NULL,
            PaymentMethod VARCHAR(50) DEFAULT 'Cash',
            IsRecurring BOOLEAN DEFAULT FALSE,
            Source VARCHAR(50) DEFAULT 'Manual',
            CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (UserId) REFERENCES Users(Id) ON DELETE CASCADE
        )
    `;

    const createBudgetsTable = `
        CREATE TABLE IF NOT EXISTS Budgets (
            Id INT AUTO_INCREMENT PRIMARY KEY,
            UserId INT NOT NULL,
            Category VARCHAR(100) NOT NULL,
            AmountLimit DECIMAL(10, 2) NOT NULL,
            FOREIGN KEY (UserId) REFERENCES Users(Id) ON DELETE CASCADE,
            UNIQUE(UserId, Category)
        )
    `;

    db.query(createUsersTable, (err) => {
        if (err) console.error('❌ Error creating Users table:', err.message);
        else {
            console.log('✅ Users table is ready!');
            db.query(createTransactionsTable, (err) => {
                if (err) console.error('❌ Error creating Transactions table:', err.message);
                else {
                    console.log('✅ Transactions table is ready!');
                    db.query(createBudgetsTable, (err) => {
                        if (err) console.error('❌ Error creating Budgets table:', err.message);
                        else console.log('✅ Budgets table is ready!');
                    });
                }
            });
        }
    });
});

// Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'غير مصرح لك، يرجى تسجيل الدخول' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'انتهت صلاحية الجلسة' });
        req.user = user;
        next();
    });
};

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'مطلوب إدخال اسم المستخدم وكلمة المرور' });

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

app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    const query = 'SELECT * FROM Users WHERE Username = ?';
    
    db.query(query, [username], async (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (results.length === 0) return res.status(404).json({ error: 'لا يوجد حساب مسجل بهذا الاسم' });

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.PasswordHash);
        if (!isMatch) return res.status(401).json({ error: 'كلمة المرور غير صحيحة' });

        const token = jwt.sign({ id: user.Id, username: user.Username, role: user.Role }, JWT_SECRET, { expiresIn: '24h' });
        const mobileToken = jwt.sign({ id: user.Id, username: user.Username, role: user.Role }, JWT_SECRET, { expiresIn: '3650d' });

        res.json({ message: 'تم الدخول بنجاح', token, mobileToken, user: { username: user.Username, id: user.Id } });
    });
});

app.get('/api/auth/mobile-token', authenticateToken, (req, res) => {
    const user = req.user;
    const mobileToken = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '3650d' });
    res.json({ mobileToken });
});

// Transactions Routes
app.get('/api/transactions', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const query = 'SELECT * FROM Transactions WHERE UserId = ? ORDER BY TransactionDate DESC, Id DESC';

    db.query(query, [userId], (err, results) => {
        if (err) return res.status(500).json({ error: 'Failed to fetch transactions' });
        
        // 🔓 فك التشفير قبل إرسالها لتطبيق الجوال
        const decryptedResults = results.map(row => {
            row.Description = decrypt(row.Description);
            row.Notes = row.Notes ? decrypt(row.Notes) : null;
            return row;
        });

        res.json(decryptedResults);
    });
});

app.post('/api/transactions', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const { Amount, Type, Category, SubCategory, Description, Notes, TransactionDate, PaymentMethod, IsRecurring, Source } = req.body;

    // 🔒 تشفير البيانات الحساسة قبل الحفظ
    const encryptedDesc = encrypt(Description);
    const encryptedNotes = Notes ? encrypt(Notes) : null;

    const query = `
        INSERT INTO Transactions 
        (UserId, Amount, Type, Category, SubCategory, Description, Notes, TransactionDate, PaymentMethod, IsRecurring, Source) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const values = [
        userId, Amount, Type, Category, 
        SubCategory || 'عام', 
        encryptedDesc, // 👈 الوصف المشفر
        encryptedNotes, // 👈 الملاحظات المشفرة
        TransactionDate, 
        PaymentMethod || 'Cash', 
        IsRecurring ? 1 : 0, 
        Source || 'Manual'
    ];

    db.query(query, values, (err, result) => {
        if (err) return res.status(500).json({ error: 'Failed to save transaction' });
        res.status(201).json({ success: true, Id: result.insertId });
    });
});

app.put('/api/transactions/:id', authenticateToken, (req, res) => {
    const transactionId = req.params.id;
    const userId = req.user.id;
    const { Amount, Type, Category, SubCategory, Description, Notes, TransactionDate, PaymentMethod, IsRecurring } = req.body;

    // 🔒 تشفير البيانات الحساسة قبل التحديث
    const encryptedDesc = encrypt(Description);
    const encryptedNotes = Notes ? encrypt(Notes) : null;

    const query = `
        UPDATE Transactions 
        SET Amount=?, Type=?, Category=?, SubCategory=?, Description=?, Notes=?, TransactionDate=?, PaymentMethod=?, IsRecurring=? 
        WHERE Id=? AND UserId=?
    `;
    const values = [
        Amount, Type, Category, SubCategory || 'عام', encryptedDesc, encryptedNotes, TransactionDate, PaymentMethod || 'Cash', IsRecurring ? 1 : 0, transactionId, userId
    ];

    db.query(query, values, (err, result) => {
        if (err) return res.status(500).json({ error: 'Failed to update transaction' });
        res.json({ success: true, message: 'Transaction updated successfully' });
    });
});

app.delete('/api/transactions/:id', authenticateToken, (req, res) => {
    const transactionId = req.params.id;
    const userId = req.user.id;

    const query = 'DELETE FROM Transactions WHERE Id=? AND UserId=?';
    db.query(query, [transactionId, userId], (err, result) => {
        if (err) return res.status(500).json({ error: 'Failed to delete transaction' });
        res.json({ success: true, message: 'Transaction deleted successfully' });
    });
});

// SMS Route
app.post('/api/raw-sms', authenticateToken, async (req, res) => {
    const { message: rawText } = req.body;
    const userId = req.user.id;

    const ignoreKeywords = ["رمز مؤقت", "رمز التفعيل", "تم تفعيل", "إضافة مستفيد", "كود", "OTP", "رمز"];
    if (!rawText || rawText.trim().length < 10 || ignoreKeywords.some(key => rawText.includes(key))) {
        return res.json({ status: "ignored" });
    }

    let amount = 0;
    const amountMatch = rawText.match(/(?:مبلغ|بـ|SAR)\s*:?\s*([\d,.]+)/i) || rawText.match(/([\d,.]+)\s*(?:ريال|SAR)/i);
    if (amountMatch) {
        amount = parseFloat(amountMatch[1].replace(/,/g, ''));
    }

    const isIncome = rawText.includes("واردة") || rawText.includes("إيداع") || rawText.includes("استرجاع");
    const type = isIncome ? "income" : "expense";

    let description = "عملية بنكية";
    if (rawText.includes("من ")) {
        const fromMatch = rawText.match(/من\s+([A-Za-z\u0600-\u06FF0-9\s*_-]+)(?:\n|\r|في|حساب|مبلغ|؜)/i);
        if (fromMatch && fromMatch[1].trim().length > 2) description = fromMatch[1].trim();
    } else if (rawText.includes("لـ ") || rawText.includes("الى:")) {
        const toMatch = rawText.match(/(?:لـ|الى:)\s*([A-Za-z\u0600-\u06FF0-9\s*_-]+)(?:\n|\r|في|حساب|؜)/i);
        if (toMatch && toMatch[1].trim().length > 2) description = toMatch[1].trim();
    }
    description = description.replace(/حساب.*/g, '').trim();

    let paymentMethod = 'Bank Transfer';
    const textLower = rawText.toLowerCase();
    if (textLower.includes("applepay") || textLower.includes("ابل باي")) {
        paymentMethod = 'Apple Pay';
    } else if (textLower.includes("بطاقة") || textLower.includes("مدى") || textLower.includes("نقاط بيع") || textLower.includes("شراء")) {
        paymentMethod = 'Card';
    }

    let category = isIncome ? "حوالات واردة" : "مصروفات عامة";
    let subCategory = "عام";
    let isRecurring = false;
    let needsAI = true;

    const descLower = description.toLowerCase() + " " + textLower;

    if (descLower.includes("أطلس المستقبل") || descLower.includes("راتب")) {
        category = "الراتب والدخل"; subCategory = "راتب العمل"; needsAI = false;
    } else if (descLower.includes("openai") || descLower.includes("netflix") || descLower.includes("stc")) {
        category = "فواتير واشتراكات"; subCategory = "اشتراكات رقمية"; isRecurring = true; needsAI = false;
    } else if (descLower.includes("fuel") || descLower.includes("محطة")) {
        category = "السيارة والمواصلات"; subCategory = "بنزين"; needsAI = false;
    } else if (descLower.includes("بقالة") || descLower.includes("supermarket")) {
        category = "المنزل والمقاضي"; subCategory = "سوبر ماركت"; needsAI = false;
    }

    if (needsAI && !isIncome) {
        try {
            const { GoogleGenAI } = require('@google/genai');
            const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
            
            const prompt = `أنت خبير مالي في السعودية. هذه رسالة بنكية: "${rawText}". 
            استخرج اسم المتجر وصنفه. أمثلة: "Abdulsama" هو عبدالصمد القرشي.
            أريد الرد فقط بصيغة JSON خالية من أي نصوص أخرى، بهذا الشكل:
            {"CleanName": "اسم المحل الواضح", "Category": "التصنيف", "SubCategory": "التصنيف الفرعي"}`;

            const response = await ai.models.generateContent({
                model: "gemini-3-flash-preview",
                contents: prompt,
            });

            let aiText = response.text.replace(/```json/g, '').replace(/```/g, '').trim();
            const aiData = JSON.parse(aiText);
            
            if (aiData.CleanName) description = aiData.CleanName;
            if (aiData.Category) category = aiData.Category;
            if (aiData.SubCategory) subCategory = aiData.SubCategory;

        } catch (error) {
            console.error("AI Error:", error.message);
        }
    }

    // 🔒 تشفير الوصف النهائي قبل حفظه
    const encryptedDesc = encrypt(description);

    const query = `
        INSERT INTO Transactions 
        (UserId, Amount, Type, Category, SubCategory, Description, TransactionDate, PaymentMethod, IsRecurring, Source) 
        VALUES (?, ?, ?, ?, ?, ?, NOW(), ?, ?, 'SMS')
    `;
    
    db.query(query, [userId, amount, type, category, subCategory, encryptedDesc, paymentMethod, isRecurring ? 1 : 0], (err, result) => {
        if (err) return res.status(500).json({ error: 'Database save failed', details: err.message });
        res.json({ success: true, id: result.insertId });
    });
});

// Budgets Routes
app.get('/api/budgets', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const query = 'SELECT * FROM Budgets WHERE UserId = ?';
    db.query(query, [userId], (err, results) => {
        if (err) return res.status(500).json({ error: 'Failed to fetch budgets' });
        res.json(results);
    });
});

app.post('/api/budgets', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const { Category, AmountLimit } = req.body;

    if (!Category || !AmountLimit) return res.status(400).json({ error: 'الرجاء تحديد القسم وقيمة الميزانية' });

    const query = `
        INSERT INTO Budgets (UserId, Category, AmountLimit) 
        VALUES (?, ?, ?) 
        ON DUPLICATE KEY UPDATE AmountLimit = ?
    `;
    db.query(query, [userId, Category, AmountLimit, AmountLimit], (err, result) => {
        if (err) return res.status(500).json({ error: 'Failed to save budget' });
        res.json({ success: true, message: 'تم حفظ الميزانية بنجاح' });
    });
});

app.delete('/api/budgets/:category', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const category = req.params.category;
    const query = 'DELETE FROM Budgets WHERE UserId = ? AND Category = ?';
    db.query(query, [userId, category], (err, result) => {
        if (err) return res.status(500).json({ error: 'Failed to delete budget' });
        res.json({ success: true, message: 'تم حذف الميزانية' });
    });
});

// AI Advisor Route
const { GoogleGenAI } = require('@google/genai');

app.get('/api/advisor', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const query = 'SELECT * FROM Transactions WHERE UserId = ? AND MONTH(TransactionDate) = MONTH(CURRENT_DATE()) AND YEAR(TransactionDate) = YEAR(CURRENT_DATE())';

    db.query(query, [userId], async (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (results.length === 0) {
            return res.json({ advice: 'أهلاً بك! قم بإضافة بعض العمليات المالية هذا الشهر لأتمكن من تحليل بياناتك وتقديم نصائح مخصصة لك. 📈' });
        }

        let income = 0; let expense = 0; let categories = {};
        results.forEach(t => {
            const amt = Number(t.Amount);
            if (t.Type === 'income') income += amt;
            else if (t.Type === 'expense') {
                expense += amt;
                categories[t.Category] = (categories[t.Category] || 0) + amt;
            }
        });

        const prompt = `أنت مستشار مالي خبير. بناءً على بيانات المستخدم لهذا الشهر:
        - إجمالي الدخل: ${income} ريال.
        - إجمالي المصروفات: ${expense} ريال.
        - تفاصيل المصروفات حسب التصنيف: ${JSON.stringify(categories)}.
        اكتب نصيحة مالية واحدة ذكية ومباشرة باللغة العربية (سطرين كحد أقصى). 
        كن مشجعاً، وإذا كان الصرف أعلى من الدخل حذره بلطف. لا تستخدم أي مقدمات مثل "بناءً على البيانات".`;

        try {
            const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
            const response = await ai.models.generateContent({
                model: "gemini-3-flash-preview",
                contents: prompt,
            });
            res.json({ advice: response.text.trim() });
        } catch (error) {
            console.error('AI Error:', error);
            res.status(500).json({ error: `خطأ من جوجل: ${error.message}` });
        }
    });
});

// Dynamic Port
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`🚀 Server is now running on port: ${PORT}`);
});