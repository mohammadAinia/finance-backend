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

// دالة استخراج التاريخ
function extractTransactionDate(text) {
    const cleanText = text.replace(/[\u061C\u200E\u200F]/g, '').replace(/\n|\r/g, ' ');
    const match1 = cleanText.match(/(\d{1,2})\/(\d{1,2})\/(\d{2})\s+(\d{2}:\d{2})/);
    if (match1) {
        const day = match1[1].padStart(2, '0');
        const month = match1[2].padStart(2, '0');
        const year = "20" + match1[3]; 
        const time = match1[4] + ':00';
        return `${year}-${month}-${day} ${time}`; 
    }
    const match2 = cleanText.match(/(\d{2})-(\d{1,2})-(\d{1,2})\s+(\d{2}:\d{2})/);
    if (match2) {
        const year = "20" + match2[1];
        const month = match2[2].padStart(2, '0');
        const day = match2[3].padStart(2, '0');
        const time = match2[4] + ':00';
        return `${year}-${month}-${day} ${time}`;
    }
    return null;
}

app.post('/api/raw-sms', authenticateToken, async (req, res) => {
    const { message: rawText } = req.body;
    const userId = req.user.id;

    console.log('\n=======================================');
    console.log('📩 [New SMS Received] for User ID:', userId);
    console.log('📄 Text:', rawText);

    const ignoreKeywords = ["رمز مؤقت", "رمز التفعيل", "تم تفعيل", "إضافة مستفيد", "كود", "OTP", "رمز"];
    if (!rawText || rawText.trim().length < 10 || ignoreKeywords.some(key => rawText.includes(key))) {
        console.log('🚫 [Ignored]: SMS is not a financial transaction or too short.');
        return res.json({ status: "ignored" });
    }

    let amount = 0;
    const amountMatch = rawText.match(/(?:مبلغ|بـ|SAR)\s*:?\s*([\d,.]+)/i) || rawText.match(/([\d,.]+)\s*(?:ريال|SAR)/i);
    if (amountMatch) amount = parseFloat(amountMatch[1].replace(/,/g, ''));

    const textLower = rawText.toLowerCase();
    const isIncome = rawText.includes("واردة") || rawText.includes("إيداع") || rawText.includes("استرجاع");
    const type = isIncome ? "income" : "expense";

    let paymentMethod = 'Bank Transfer';
    if (textLower.includes("applepay") || textLower.includes("ابل باي")) paymentMethod = 'Apple Pay';
    else if (textLower.includes("بطاقة") || textLower.includes("مدى") || textLower.includes("شراء")) paymentMethod = 'Card';

    console.log(`💰 [Initial Data]: Amount: ${amount} | Type: ${type} | Payment Method: ${paymentMethod}`);

    // Default settings
    let description = "عملية بنكية";
    let category = isIncome ? "حوالات واردة" : "مصروفات عامة";
    let subCategory = "عام";
    let isRecurring = false;
    let needsAI = true;

    // =========================================
    // 💡 Local Dictionary (To protect against Google API rate limits)
    // =========================================
    const merchantsDictionary = [
        { keys: ["panda", "بنده"], name: "بنده", cat: "المنزل والمقاضي", sub: "سوبر ماركت" },
        { keys: ["mcdonald", "mcd", "ماك"], name: "ماكدونالدز", cat: "المطاعم والكافيهات", sub: "وجبات سريعة" },
        { keys: ["albaik", "البيك"], name: "البيك", cat: "المطاعم والكافيهات", sub: "وجبات سريعة" },
        { keys: ["stc", "الاتصالات"], name: "STC", cat: "فواتير واشتراكات", sub: "اتصالات وإنترنت", recurring: true },
        { keys: ["netflix", "نتفلكس"], name: "Netflix", cat: "فواتير واشتراكات", sub: "ترفيه", recurring: true },
        { keys: ["fuel", "محطة", "sasco", "aldrees", "nelt fuel"], name: "محطة وقود", cat: "السيارة والمواصلات", sub: "بنزين" },
        { keys: ["pharmacy", "nahdi", "صيدلية", "النهدي"], name: "صيدلية", cat: "الصحة والجمال", sub: "أدوية وعلاج" },
        { keys: ["أطلس المستقبل", "راتب"], name: "راتب العمل", cat: "الراتب والدخل", sub: "راتب العمل" },
        { keys: ["openai", "chatgpt"], name: "OpenAI", cat: "فواتير واشتراكات", sub: "اشتراكات رقمية", recurring: true }
    ];

    // Quick filter: If found locally, do not call Google AI!
    for (let merchant of merchantsDictionary) {
        if (merchant.keys.some(key => textLower.includes(key))) {
            description = merchant.name;
            category = merchant.cat;
            subCategory = merchant.sub;
            isRecurring = merchant.recurring || false;
            needsAI = false; 
            console.log(`📖 [Local Dictionary]: Merchant found (${description}) - No AI needed.`);
            break;
        }
    }

    // Extract sender name for incoming transfers (without AI)
    if (isIncome && needsAI) {
        const fromMatch = rawText.match(/من\s+([A-Za-z\u0600-\u06FF0-9\s*_-]+)(?:\n|\r|في|حساب|مبلغ|؜)/i);
        if (fromMatch && fromMatch[1].trim().length > 2) {
            description = fromMatch[1].trim();
            needsAI = false;
            console.log(`💵 [Incoming Transfer]: Sender extracted (${description}).`);
        }
    }

    // =========================================
    // 🤖 Use AI only for unknown transactions
    // =========================================
    if (needsAI && !isIncome) {
        console.log('🤖 [AI Processing]: Merchant not in dictionary, sending request to Gemini...');
        try {
            const { GoogleGenAI } = require('@google/genai');
            const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
            
            const allowedCategories = ["المطاعم والكافيهات", "المنزل والمقاضي", "التسوق", "الصحة والجمال", "السيارة والمواصلات", "فواتير واشتراكات", "مصروفات عامة"];
            
            const prompt = `أنت خبير مالي في السعودية. هذه رسالة بنكية: "${rawText}". 
            استخرج اسم المتجر وصنفه (اختر التصنيف من هنا فقط: ${JSON.stringify(allowedCategories)}).
            أمثلة: "Abdulsama" هو عبدالصمد القرشي. "TAJ ALHAL" هو تاج الحلا.
            أريد الرد فقط بصيغة JSON:
            {"CleanName": "اسم المحل الواضح", "Category": "التصنيف", "SubCategory": "التصنيف الفرعي"}`;

            const response = await ai.models.generateContent({
                model: "gemini-3-flash", // I changed this to the stable version to avoid 503 errors
                contents: prompt,
            });

            let aiText = response.text.replace(/```json/g, '').replace(/```/g, '').trim();
            const aiData = JSON.parse(aiText);

            console.log('✅ [AI - Success]:', aiData);

            if (aiData.CleanName) description = aiData.CleanName;
            if (aiData.Category) category = aiData.Category;
            if (aiData.SubCategory) subCategory = aiData.SubCategory;

        } catch (error) {
            console.error("❌ [AI - Error]:", error.message);
            // Fallback plan if AI fails due to high demand
            const fallbackMatch = rawText.match(/لـ\s*([A-Za-z\s]+)(?:\n|\r|؜)/i);
            if (fallbackMatch) description = fallbackMatch[1].trim();
            console.log(`⚠️ [Fallback]: Used simple text extraction (${description}).`);
        }
    }

    // Extract date
    let transactionDate = extractTransactionDate(rawText);
    if (!transactionDate) {
        transactionDate = new Date().toISOString().slice(0, 19).replace('T', ' ');
        console.log(`⏳ [Date]: No date found in SMS, using current server time (${transactionDate}).`);
    } else {
        console.log(`📅 [Date]: Date successfully extracted (${transactionDate}).`);
    }

    // Encrypt and save
    const encryptedDesc = encrypt(description);
    console.log(`🔒 [Encryption]: Description encrypted for database protection.`);

    const query = `
        INSERT INTO Transactions 
        (UserId, Amount, Type, Category, SubCategory, Description, TransactionDate, PaymentMethod, IsRecurring, Source) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'SMS')
    `;

    db.query(query, [userId, amount, type, category, subCategory, encryptedDesc, transactionDate, paymentMethod, isRecurring ? 1 : 0], (err, result) => {
        if (err) {
            console.error('❌ [Database - Error]: Failed to save transaction.', err.message);
            return res.status(500).json({ error: 'Database save failed', details: err.message });
        }
        console.log(`🎉 [Database - Success]: Transaction saved with ID: ${result.insertId}`);
        console.log('=======================================\n');
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