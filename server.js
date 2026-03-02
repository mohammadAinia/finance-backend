const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());

// Database Connection Configuration
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: {
        rejectUnauthorized: false
    }
});

// Connect to Database and Create Table if not exists
db.connect((err) => {
    if (err) {
        console.error('❌ Database connection failed:', err.message);
        return;
    }
    console.log('✅ Successfully connected to MySQL database!');

    // SQL query to create the table automatically
    const createTableQuery = `
        CREATE TABLE IF NOT EXISTS Transactions (
            Id INT AUTO_INCREMENT PRIMARY KEY,
            Description VARCHAR(255) NOT NULL,
            Amount DECIMAL(10, 2) NOT NULL,
            TransactionDate DATE NOT NULL,
            Category VARCHAR(100) NOT NULL,
            Type VARCHAR(50) NOT NULL
        )
    `;

    db.query(createTableQuery, (err, result) => {
        if (err) {
            console.error('❌ Error creating table:', err.message);
        } else {
            console.log('✅ Transactions table is ready!');
        }
    });
});

// Root Route
app.get('/', (req, res) => {
    res.send('Welcome to the Financial Management App Backend!');
});

// Get all transactions
app.get('/api/transactions', (req, res) => {
    const query = 'SELECT * FROM Transactions ORDER BY Id DESC';
    db.query(query, (err, results) => {
        if (err) {
            console.error('❌ Error fetching transactions:', err.message);
            res.status(500).json({ error: 'Failed to fetch transactions' });
            return;
        }
        res.json(results);
    });
});

// Create a new transaction
app.post('/api/transactions', (req, res) => {
    const { Description, Amount, TransactionDate, Category, Type } = req.body;

    const query = 'INSERT INTO Transactions (Description, Amount, TransactionDate, Category, Type) VALUES (?, ?, ?, ?, ?)';
    const values = [Description, Amount, TransactionDate, Category, Type];

    db.query(query, values, (err, result) => {
        if (err) {
            console.error('❌ Error saving transaction:', err.message);
            res.status(500).json({ error: 'Failed to save transaction' });
            return;
        }

        res.status(201).json({
            Id: result.insertId,
            Description,
            Amount,
            TransactionDate,
            Category,
            Type
        });
    });
});

// Update an existing transaction
app.put('/api/transactions/:id', (req, res) => {
    const transactionId = req.params.id;
    const { Description, Amount, TransactionDate, Category, Type } = req.body;

    const query = 'UPDATE Transactions SET Description=?, Amount=?, TransactionDate=?, Category=?, Type=? WHERE Id=?';
    const values = [Description, Amount, TransactionDate, Category, Type, transactionId];

    db.query(query, values, (err, result) => {
        if (err) {
            console.error('❌ Error updating transaction:', err.message);
            res.status(500).json({ error: 'Failed to update transaction' });
            return;
        }
        res.json({ message: 'Transaction updated successfully' });
    });
});

// Delete a transaction
app.delete('/api/transactions/:id', (req, res) => {
    const transactionId = req.params.id;

    const query = 'DELETE FROM Transactions WHERE Id=?';

    db.query(query, [transactionId], (err, result) => {
        if (err) {
            console.error('❌ Error deleting transaction:', err.message);
            res.status(500).json({ error: 'Failed to delete transaction' });
            return;
        }
        res.json({ message: 'Transaction deleted successfully' });
    });
});
// 🚀 استلام ومعالجة الرسائل الخام من الآيفون (يدعم الراجحي والإنماء)
app.post('/api/raw-sms', (req, res) => {
    const rawText = req.body.message;

    // 1. فلتر تجاهل الرسائل الإدارية والرموز (OTP)
    const ignoreKeywords = ["رمز مؤقت", "رمز التفعيل", "تم تفعيل", "إضافة مستفيد", "كود"];
    if (!rawText || rawText.trim().length < 10 || ignoreKeywords.some(key => rawText.includes(key))) {
        console.log("⚠️ Ignored system/OTP message");
        return res.json({ status: "ignored" });
    }

    console.log("📩 Processing new SMS:", rawText);

    // 2. استخراج المبلغ بمرونة (يدعم: ريال، SAR، بـ، مبلغ، مبلغ:)
    let amount = 0;
    // النمط الجديد يبحث عن أي رقم يأتي بعد الكلمات المفتاحية المالية
    const amountMatch = rawText.match(/(?:مبلغ:SAR|بـSAR|المبلغ:SAR|مبلغ|بـ|SAR)\s*([\d,.]+)/i);
    if (amountMatch) {
        amount = parseFloat(amountMatch[1].replace(/,/g, ''));
    }

    // 3. تحديد نوع العملية (Type)
    const isIncome = rawText.includes("واردة") || rawText.includes("إيداع") || rawText.includes("شركة أطلس المستقبل");
    const type = isIncome ? "income" : "expense";

    // 4. استخراج الوصف (Description) بذكاء متقدم
    let description = "Bank Transaction";

    // نبحث عن الأسماء التي تأتي بعد "من" أو "لـ" أو "الى" بشرط ألا تكون أرقاماً فقط
    // هذا النمط يتجاهل أرقام الحسابات التي تبدأ بـ * أو تحتوي على أرقام فقط
    const nameMatches = rawText.match(/(?:لـ|من:|الى:|من)\s*([^\d\n\r;*]{3,})/gi);

    if (nameMatches) {
        // نأخذ آخر نتيجة غالباً لأنها تحتوي على اسم الطرف الآخر (تاجر أو شخص)
        const rawName = nameMatches[nameMatches.length - 1];
        description = rawName.replace(/(?:لـ|من:|الى:|من)/i, '').trim();
    }

    // تنظيف إضافي لرسائل المشتريات (مثل OPENAI أو Supermarket)
    if (description.toLowerCase().includes("بطاقة")) {
        description = "Point of Sale / Card";
    }

    // 5. حفظ البيانات في قاعدة البيانات
    const query = 'INSERT INTO Transactions (Description, Amount, TransactionDate, Category, Type) VALUES (?, ?, NOW(), ?, ?)';
    const category = isIncome ? "Salary/Transfer" : "General/Spending";

    db.query(query, [description, amount, category, type], (err, result) => {
        if (err) {
            console.error('❌ Error saving to DB:', err.message);
            return res.status(500).json({ error: 'Database save failed' });
        }
        console.log(`✅ Recorded: ${type} | ${amount} SAR | ${description}`);
        res.json({ success: true, id: result.insertId });
    });
});
// Dynamic Port for Cloud Deployment
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server is now running on port: ${PORT}`);
});