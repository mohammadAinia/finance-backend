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
// 🚀 استلام ومعالجة الرسائل الخام من الآيفون
app.post('/api/raw-sms', (req, res) => {
    const rawText = req.body.message;

    // 1. تجاهل رسائل الرموز المؤقتة (OTP) لضمان نظافة البيانات
    if (rawText.includes("رمز مؤقت")) {
        console.log("⚠️ Ignored OTP message");
        return res.json({ status: "ignored", reason: "OTP message" });
    }

    console.log("📩 Processing new SMS:", rawText);

    // 2. استخراج المبلغ (Amount) بدقة
    // يبحث عن الرقم بعد "بـSAR" أو "مبلغ:SAR" أو "المبلغ:SAR"
    let amount = 0;
    const amountMatch = rawText.match(/(?:بـSAR|مبلغ:SAR|المبلغ:SAR)\s*([\d,.]+)/);
    if (amountMatch) {
        amount = parseFloat(amountMatch[1].replace(/,/g, ''));
    }

    // 3. تحديد نوع العملية (Type)
    // إذا كانت الرسالة تحتوي على "واردة" فهي دخل (income)، غير ذلك فهي مصروف (expense)
    const isIncome = rawText.includes("واردة") || rawText.includes("إيداع") || rawText.includes("من: شركة أطلس المستقبل");
    const type = isIncome ? "income" : "expense";

    // 4. استخراج الوصف (Description) بناءً على نوع الرسالة
    let description = "Bank Transaction";

    // جلب الاسم بعد "لـ" (للمشتريات) أو "من:" (للحوالات الواردة) أو "الى:" (للصادرة)
    const descMatch = rawText.match(/(?:لـ|من:|الى:)\s*(.*?)(?:\s\d|\n|$|؜|;)/);
    if (descMatch) {
        description = descMatch[1].trim();
    }

    // 5. حفظ البيانات في قاعدة البيانات السحابية
    const query = 'INSERT INTO Transactions (Description, Amount, TransactionDate, Category, Type) VALUES (?, ?, NOW(), ?, ?)';
    const category = isIncome ? "Salary/Transfer" : "Shopping/Bills";

    db.query(query, [description, amount, category, type], (err, result) => {
        if (err) {
            console.error('❌ Error processing raw SMS:', err.message);
            return res.status(500).json({ error: 'Database save failed' });
        }
        console.log(`✅ Success! ${type} of ${amount} for ${description} saved.`);
        res.json({ success: true, id: result.insertId });
    });
});
// Dynamic Port for Cloud Deployment
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server is now running on port: ${PORT}`);
});