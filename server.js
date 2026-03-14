const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();
const { Resend } = require('resend');
const nodemailer = require('nodemailer');
const html_to_pdf = require('html-pdf-node');


// تهيئة الخدمة باستخدام المفتاح
const resend = new Resend(process.env.RESEND_API_KEY);
const app = express();

app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_financial_key_2024';

// ==========================================
// 🔐 Data Encryption Engine (AES-256-CBC)
// ==========================================
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

    // Sequential Table Creation to avoid Foreign Key errors
    const createUsersTable = `
        CREATE TABLE IF NOT EXISTS Users (
            Id INT AUTO_INCREMENT PRIMARY KEY,
            Username VARCHAR(50) UNIQUE NOT NULL,
            PasswordHash VARCHAR(255) NOT NULL,
            Role VARCHAR(20) DEFAULT 'user'
        )
    `;

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

    const createAssetsTable = `
        CREATE TABLE IF NOT EXISTS Assets (
            Id INT AUTO_INCREMENT PRIMARY KEY,
            UserId INT NOT NULL,
            AssetType VARCHAR(50) DEFAULT 'Gold',
            WeightInOunces DECIMAL(10, 4) NOT NULL,
            PurchasePricePerOunce DECIMAL(10, 2) NOT NULL,
            PurchaseDate DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (UserId) REFERENCES Users(Id) ON DELETE CASCADE
        )
    `;

    // 👇 إضافة جدول الأهداف المالية
    const createSavingsGoalsTable = `
        CREATE TABLE IF NOT EXISTS SavingsGoals (
            Id INT AUTO_INCREMENT PRIMARY KEY,
            UserId INT NOT NULL,
            GoalName VARCHAR(255) NOT NULL,
            TargetAmount DECIMAL(10, 2) NOT NULL,
            CurrentAmount DECIMAL(10, 2) DEFAULT 0.00,
            CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (UserId) REFERENCES Users(Id) ON DELETE CASCADE
        )
    `;

    // Execute queries sequentially
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
                        else {
                            console.log('✅ Budgets table is ready!');
                            db.query(createAssetsTable, (err) => {
                                if (err) console.error('❌ Error creating Assets table:', err.message);
                                else {
                                    console.log('✅ Assets table is ready!');
                                    // 👇 تنفيذ إنشاء جدول الأهداف بعد الانتهاء من الذهب
                                    db.query(createSavingsGoalsTable, (err) => {
                                        if (err) console.error('❌ Error creating SavingsGoals table:', err.message);
                                        else console.log('✅ SavingsGoals table is ready!');
                                    });
                                }
                            });
                        }
                    });
                }
            });
        }
    });
});
// دالة مساعدة لتحويل استعلامات قاعدة البيانات لتتوافق مع async/await
const queryAsync = (query, values) => {
    return new Promise((resolve, reject) => {
        db.query(query, values, (err, results) => {
            if (err) reject(err);
            else resolve(results);
        });
    });
};
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
const cron = require('node-cron');
const { Expo } = require('expo-server-sdk');
let expo = new Expo();

// ==========================================
// 📅 نظام التقارير الشهرية التلقائية (نهاية كل شهر) - النسخة الشاملة (Premium)
// يعمل يوم 1 من كل شهر الساعة 08:00 صباحاً ('0 8 1 * *')
// ==========================================

cron.schedule('0 8 1 * *', async () => {
    console.log('⏳ [Monthly Report]: بدء تجميع بيانات التقرير الشهري التلقائي الشامل...');

    const userId = 1; 
    const targetEmail = 'mmyyttt@gmail.com'; 

    try {
        // 1. جلب العمليات
        const allTransactions = await queryAsync('SELECT * FROM Transactions WHERE UserId = ? ORDER BY TransactionDate DESC', [userId]);
        
        let totalIncome = 0; let totalExpense = 0;
        let lastMonthIncome = 0; let lastMonthExpense = 0;
        
        const now = new Date();
        const lastMonth = now.getMonth() === 0 ? 11 : now.getMonth() - 1;
        const yearOfLastMonth = now.getMonth() === 0 ? now.getFullYear() - 1 : now.getFullYear();

        const lastMonthTransactions = [];

        allTransactions.forEach(t => {
            const amt = Number(t.Amount);
            const tDate = new Date(t.TransactionDate);
            
            if (t.Type === 'income') totalIncome += amt;
            else if (t.Type === 'expense') totalExpense += amt;

            if (tDate.getMonth() === lastMonth && tDate.getFullYear() === yearOfLastMonth) {
                // فك تشفير الوصف هنا
                t.Description = decrypt(t.Description) || t.Description;
                t.Notes = t.Notes ? decrypt(t.Notes) : null;
                lastMonthTransactions.push(t);
                
                if (t.Type === 'income') lastMonthIncome += amt;
                else if (t.Type === 'expense') lastMonthExpense += amt;
            }
        });

        const currentBalance = totalIncome - totalExpense;

        // 2. إعداد بيانات المخطط الدائري (Pie Chart) لمصروفات الشهر الماضي
        const categoryTotals = {};
        lastMonthTransactions.forEach(t => {
            if (t.Type === 'expense') {
                categoryTotals[t.Category] = (categoryTotals[t.Category] || 0) + Number(t.Amount);
            }
        });
        const colors = ['#ef4444', '#f59e0b', '#3b82f6', '#10b981', '#8b5cf6', '#ec4899'];
        let chartImageUrl = '';
        const keys = Object.keys(categoryTotals);
        if (keys.length > 0) {
            const chartData = keys.map((key, index) => ({
                name: key,
                amount: categoryTotals[key],
                color: colors[index % colors.length]
            }));
            const chartConfig = {
                type: 'pie',
                data: {
                    labels: chartData.map(d => d.name),
                    datasets: [{
                        data: chartData.map(d => Number(d.amount)),
                        backgroundColor: chartData.map(d => d.color)
                    }]
                },
                options: { plugins: { legend: { position: 'right', labels: { font: { family: 'sans-serif' } } } } }
            };
            chartImageUrl = `https://quickchart.io/chart?c=${encodeURIComponent(JSON.stringify(chartConfig))}&w=400&h=250`;
        }

        // 3. جلب بيانات الذهب
        const goldAssetsQuery = await queryAsync("SELECT * FROM Assets WHERE UserId = ? AND AssetType = 'Gold'", [userId]);
        let goldAsset = null;
        if (goldAssetsQuery.length > 0) {
            let totalGrams = 0;
            let totalCost = 0;
            goldAssetsQuery.forEach(asset => {
                const weight = parseFloat(asset.WeightInOunces) || 0;
                const pricePerGram = parseFloat(asset.PurchasePricePerOunce) || 0;
                totalGrams += weight;
                totalCost += (weight * pricePerGram);
            });

            // جلب السعر المباشر (أو استخدام السعر التقريبي في حال فشل الـ API)
            let livePriceSAR_Gram = 0;
            try {
                const goldRes = await fetch('https://www.goldapi.io/api/XAU/USD', {
                    headers: { 'x-access-token': process.env.GOLD_API_KEY || '' }
                });
                const goldData = await goldRes.json();
                const livePricePerOunceUSD = goldData.price || 2700.00;
                livePriceSAR_Gram = (livePricePerOunceUSD * 3.75) / 31.1035;
            } catch(e) {
                console.log("⚠️ تعذر جلب السعر المباشر للذهب، سيتم استخدام التكلفة الأصلية كمرجع.");
                livePriceSAR_Gram = totalCost / totalGrams; 
            }

            const currentValue = totalGrams * livePriceSAR_Gram;
            const profitLoss = currentValue - totalCost;
            goldAsset = {
                totalGrams: Number(totalGrams.toFixed(2)),
                currentValue: Number(currentValue.toFixed(2)),
                profitLoss: Number(profitLoss.toFixed(2)),
                profitLossPercentage: totalCost > 0 ? Number(((profitLoss / totalCost) * 100).toFixed(2)) : 0
            };
        }

        // 4. جلب الميزانيات والأهداف وتجهيز الـ HTML لها
        const budgets = await queryAsync('SELECT * FROM Budgets WHERE UserId = ?', [userId]);
        const goals = await queryAsync('SELECT * FROM SavingsGoals WHERE UserId = ?', [userId]);

        const budgetsHtml = budgets.map(b => {
            let spent = 0;
            lastMonthTransactions.forEach(t => {
                if (t.Type === 'expense' && t.Category === b.Category) spent += Number(t.Amount);
            });
            const limit = Number(b.AmountLimit);
            const percent = limit > 0 ? Math.min((spent / limit) * 100, 100) : 0;
            const color = percent >= 100 ? '#ef4444' : (percent >= 80 ? '#f59e0b' : '#10b981');
            return `
                <div class="progress-item">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                        <strong>${b.Category}</strong>
                        <span>${spent.toFixed(2)} / ${limit.toFixed(2)} SAR</span>
                    </div>
                    <div class="progress-bg">
                        <div class="progress-fill" style="width: ${percent}%; background-color: ${color};"></div>
                    </div>
                </div>
            `;
        }).join('') || '<p class="text-center text-muted">لا توجد ميزانيات.</p>';

        const goalsHtml = goals.map(g => {
            const percent = Math.min((parseFloat(g.CurrentAmount) / parseFloat(g.TargetAmount)) * 100, 100);
            return `
                <div class="progress-item">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                        <strong>${g.GoalName}</strong>
                        <span>${parseFloat(g.CurrentAmount).toLocaleString()} / ${parseFloat(g.TargetAmount).toLocaleString()} SAR (${percent.toFixed(1)}%)</span>
                    </div>
                    <div class="progress-bg">
                        <div class="progress-fill" style="width: ${percent}%; background-color: #8b5cf6;"></div>
                    </div>
                </div>
            `;
        }).join('') || '<p class="text-center text-muted">لا توجد أهداف.</p>';

        const transactionsHtml = lastMonthTransactions.slice(0, 30).map(t => {
            const isIncome = t.Type === 'income';
            const date = new Date(t.TransactionDate).toLocaleDateString('ar-SA');
            return `
                <tr>
                    <td>${date}</td>
                    <td>${t.Description}</td>
                    <td>${t.Category} / ${t.SubCategory || 'عام'}</td>
                    <td class="${isIncome ? 'text-green' : 'text-red'}">
                        ${isIncome ? '+' : '-'} SAR ${Number(t.Amount).toFixed(2)}
                    </td>
                </tr>
            `;
        }).join('') || '<tr><td colspan="4" class="text-center text-muted">لا توجد حركات مالية مسجلة للشهر الماضي.</td></tr>';

        // 5. بناء الـ HTML الشامل والأنيق (نفس الداشبورد تماماً)
        const htmlContent = `
            <!DOCTYPE html>
            <html dir="rtl" lang="ar">
            <head>
                <meta charset="UTF-8">
                <style>
                    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f3f4f6; color: #1f2937; margin: 0; padding: 30px; line-height: 1.6; }
                    .container { max-width: 900px; margin: auto; background: #fff; padding: 40px; border-radius: 12px; box-shadow: 0 4px 10px rgba(0,0,0,0.05); }
                    .header-section { text-align: center; padding-bottom: 20px; border-bottom: 2px solid #e5e7eb; margin-bottom: 30px; }
                    h1 { color: #1e3a8a; margin: 0 0 10px 0; font-size: 28px; }
                    .report-date { color: #6b7280; font-size: 14px; }
                    .kpi-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 40px; }
                    .kpi-card { padding: 20px; border-radius: 10px; text-align: center; background: #f8fafc; border: 1px solid #e2e8f0; }
                    .kpi-card h3 { margin: 0 0 10px 0; font-size: 16px; color: #4b5563; }
                    .kpi-card p { margin: 0; font-size: 24px; font-weight: bold; }
                    .card-balance { background: #1e3a8a; color: white; border: none; }
                    .card-balance h3 { color: #bfdbfe; }
                    .card-income { border-top: 4px solid #10b981; }
                    .card-expense { border-top: 4px solid #ef4444; }
                    h2 { color: #1e40af; border-bottom: 2px solid #bfdbfe; padding-bottom: 8px; margin-top: 40px; font-size: 20px; }
                    .middle-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin-bottom: 40px; }
                    .chart-container { text-align: center; border: 1px solid #e5e7eb; border-radius: 10px; padding: 20px; background: #fff; }
                    .gold-card { background: linear-gradient(135deg, #b45309 0%, #d97706 100%); color: white; padding: 25px; border-radius: 10px; text-align: center; }
                    .gold-card h3 { margin: 0 0 15px 0; color: #fef3c7; }
                    .gold-value { font-size: 30px; font-weight: bold; margin: 10px 0; }
                    table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; }
                    th, td { border: 1px solid #e5e7eb; padding: 12px; text-align: right; }
                    th { background-color: #f9fafb; color: #374151; font-weight: bold; }
                    tr:nth-child(even) { background-color: #f9fafb; }
                    .text-green { color: #10b981; font-weight: bold; }
                    .text-red { color: #ef4444; font-weight: bold; }
                    .text-muted { color: #9ca3af; }
                    .text-center { text-align: center; }
                    .progress-item { margin-bottom: 15px; }
                    .progress-bg { background: #e5e7eb; height: 12px; border-radius: 6px; overflow: hidden; }
                    .progress-fill { height: 100%; border-radius: 6px; }
                    .page-break-avoid { page-break-inside: avoid; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header-section">
                        <h1>التقرير المالي الشهري</h1>
                        <div class="report-date">تاريخ الإصدار: ${new Date().toLocaleString('ar-SA')}</div>
                    </div>

                    <div class="kpi-grid">
                        <div class="kpi-card card-income">
                            <h3>مداخيل الشهر الماضي</h3>
                            <p class="text-green">SAR ${lastMonthIncome.toFixed(2)}</p>
                        </div>
                        <div class="kpi-card card-balance">
                            <h3>الرصيد الكلي المتاح</h3>
                            <p>SAR ${currentBalance.toFixed(2)}</p>
                        </div>
                        <div class="kpi-card card-expense">
                            <h3>مصروفات الشهر الماضي</h3>
                            <p class="text-red">SAR ${lastMonthExpense.toFixed(2)}</p>
                        </div>
                    </div>

                    <div class="middle-grid page-break-avoid">
                        <div class="chart-container">
                            <h3 style="margin-top: 0; color: #4b5563;">تحليل مصروفات الشهر</h3>
                            ${chartImageUrl ? `<img src="${chartImageUrl}" alt="Pie Chart" style="max-width: 100%; height: auto;">` : '<p class="text-muted">لا توجد مصروفات لرسم المخطط</p>'}
                        </div>

                        ${goldAsset && goldAsset.totalGrams > 0 ? `
                        <div class="gold-card">
                            <h3>محفظة الذهب الخالص</h3>
                            <div style="font-size: 16px;">الوزن الإجمالي: ${goldAsset.totalGrams} جرام</div>
                            <div class="gold-value">SAR ${goldAsset.currentValue?.toLocaleString() ?? '0.00'}</div>
                            <div style="background: rgba(0,0,0,0.2); padding: 8px; border-radius: 6px; margin-top: 15px;">
                                ${goldAsset.profitLoss >= 0 ? 'ربح' : 'خسارة'}: SAR ${Math.abs(goldAsset.profitLoss ?? 0).toFixed(2)} 
                                (${goldAsset.profitLossPercentage}%)
                            </div>
                        </div>
                        ` : '<div class="chart-container"><h3 style="margin-top: 0; color: #4b5563;">محفظة الذهب</h3><p class="text-muted">لا توجد أصول ذهبية مسجلة</p></div>'}
                    </div>

                    <div class="middle-grid page-break-avoid" style="margin-bottom: 20px;">
                        <div style="border: 1px solid #e5e7eb; border-radius: 10px; padding: 20px;">
                            <h3 style="margin-top: 0; border-bottom: 1px solid #e5e7eb; padding-bottom: 10px;">أداء الميزانية</h3>
                            ${budgetsHtml}
                        </div>
                        <div style="border: 1px solid #e5e7eb; border-radius: 10px; padding: 20px;">
                            <h3 style="margin-top: 0; border-bottom: 1px solid #e5e7eb; padding-bottom: 10px;">الأهداف المالية</h3>
                            ${goalsHtml}
                        </div>
                    </div>

                    <h2 class="page-break-avoid">سجل العمليات (الشهر الماضي)</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>التاريخ</th>
                                <th>الوصف</th>
                                <th>التصنيف</th>
                                <th>المبلغ</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${transactionsHtml}
                        </tbody>
                    </table>
                </div>
            </body>
            </html>
        `;

        // 6. توليد الـ PDF وإرساله عبر Resend
        const options = { format: 'A4', printBackground: true };
        const file = { content: htmlContent };
        const pdfBuffer = await html_to_pdf.generatePdf(file, options);

        const monthNames = ["يناير", "فبراير", "مارس", "أبريل", "مايو", "يونيو", "يوليو", "أغسطس", "سبتمبر", "أكتوبر", "نوفمبر", "ديسمبر"];
        const reportMonth = monthNames[lastMonth];

        const { data, error } = await resend.emails.send({
            from: 'Finance App <onboarding@resend.dev>',
            to: targetEmail,
            subject: `📊 تقريرك المالي الشامل لشهر ${reportMonth}`,
            html: `
                <div dir="rtl" style="font-family: Arial, sans-serif;">
                    <h2>مرحباً بك! 👋</h2>
                    <p>لقد قمنا بتجهيز تقريرك المالي المتميز لشهر <strong>${reportMonth}</strong>.</p>
                    <p>تجد في المرفقات نسختك الشاملة.</p>
                </div>
            `,
            attachments: [{ filename: `Financial_Report_${reportMonth}.pdf`, content: pdfBuffer }]
        });

        if (error) throw error;
        console.log(`✅ [Monthly Report]: تم إرسال التقرير الشامل بنجاح! ID: ${data.id}`);

    } catch (error) {
        console.error('❌ [Monthly Report Error]:', error);
    }
});

// ✅ وظيفة ترحيل فائض الميزانية (تعمل يومياً الساعة 11:50 مساءً وتنفذ فقط في آخر يوم من الشهر)
cron.schedule('50 23 28-31 * *', () => {
    // التحقق هل غداً هو اليوم الأول من الشهر؟
    const tomorrow = new Date(new Date().getTime() + 24 * 60 * 60 * 1000);
    if (tomorrow.getDate() !== 1) return; // إذا لم يكن غداً يوم 1، توقف

    console.log('🧹 [Month-End Sweep]: جاري البحث عن فائض الميزانيات وترحيلها...');

    db.query('SELECT Id FROM Users', (err, users) => {
        if (err) return;

        users.forEach(user => {
            const userId = user.Id;
            // التحقق هل لدى المستخدم هدف يقبل ترحيل الفائض؟
            db.query('SELECT Id, GoalName FROM SavingsGoals WHERE UserId = ? AND SweepSurplus = 1 LIMIT 1', [userId], (err, goals) => {
                if (err || goals.length === 0) return;
                const sweepGoal = goals[0];

                // حساب إجمالي الميزانية
                db.query('SELECT SUM(AmountLimit) as TotalBudget FROM Budgets WHERE UserId = ?', [userId], (err, budgetRes) => {
                    const totalBudget = budgetRes[0]?.TotalBudget || 0;
                    if (totalBudget <= 0) return;

                    // حساب ما تم صرفه هذا الشهر
                    db.query(`SELECT SUM(Amount) as TotalSpent FROM Transactions WHERE UserId = ? AND Type = 'expense' AND MONTH(TransactionDate) = MONTH(CURRENT_DATE()) AND YEAR(TransactionDate) = YEAR(CURRENT_DATE()) AND Source != 'AutoSave'`, [userId], (err, transRes) => {
                        const totalSpent = transRes[0]?.TotalSpent || 0;
                        const surplus = totalBudget - totalSpent;

                        // إذا كان هناك فائض، حوله للهدف
                        if (surplus > 0) {
                            db.query('UPDATE SavingsGoals SET CurrentAmount = CurrentAmount + ? WHERE Id = ?', [surplus, sweepGoal.Id]);

                            const encryptedDesc = encrypt(`تحويل فائض ميزانية الشهر للهدف: ${sweepGoal.GoalName}`);
                            db.query(`INSERT INTO Transactions (UserId, Amount, Type, Category, SubCategory, Description, TransactionDate, PaymentMethod, Source) VALUES (?, ?, 'expense', 'ادخار', 'ترحيل فائض', ?, NOW(), 'System', 'Sweep')`, [userId, surplus, encryptedDesc]);

                            console.log(`✅ [Month-End Sweep]: تم ترحيل مبلغ ${surplus} للمستخدم ${userId}`);
                        }
                    });
                });
            });
        });
    });
});
// ✅ وظيفة برمجية تعمل تلقائياً كل ساعتين
// السلسلة '0 */2 * * *' تعني (عند الدقيقة 0 من كل ساعتين)
cron.schedule('0 */2 * * *', async () => {
    console.log('⏰ Running Gold Price Notification Task...');

    try {
        // 1. جلب السعر المباشر (نفس المنطق الذي وضعناه سابقاً)
        const GOLD_API_KEY = process.env.GOLD_API_KEY || 'YOUR_API_KEY';
        const goldRes = await fetch('https://www.goldapi.io/api/XAU/USD', {
            headers: { 'x-access-token': GOLD_API_KEY }
        });
        const goldData = await goldRes.json();
        const livePriceSAR_Gram = (goldData.price * 3.75) / 31.1035;

        // 2. جلب المستخدمين الذين لديهم ذهب (هنا كمثال لمستخدمك رقم 1)
        // في التطبيق الفعلي، يمكنك عمل Loop على كل المستخدمين
        const query = 'SELECT * FROM Assets WHERE AssetType = "Gold"';

        db.query(query, async (err, results) => {
            if (err) return console.error(err);

            // تجميع البيانات لكل مستخدم (تبسيط للمثال)
            let totalGrams = 0;
            let totalCost = 0;
            results.forEach(asset => {
                totalGrams += parseFloat(asset.WeightInOunces);
                totalCost += (parseFloat(asset.WeightInOunces) * parseFloat(asset.PurchasePricePerOunce));
            });

            const currentValue = totalGrams * livePriceSAR_Gram;
            const profitLoss = currentValue - totalCost;
            const status = profitLoss >= 0 ? 'ربح' : 'خسارة';

            // 3. إرسال الإشعار (يحتاج أن يكون لديك Expo Push Token للمستخدم مخزناً في الداتا بيز)
            // سأفترض أننا سنطبع النتيجة في الكونسول الآن، ولتفعيل الإشعارات للجوال 
            // يجب ربطها بـ Expo Push Token الخاص بجهازك.
            // داخل cron.schedule
            const messages = [];
            // جلب المستخدمين مع التوكنات الخاصة بهم
            db.query('SELECT ExpoPushToken FROM Users WHERE Id = ?', [1], (err, users) => {
                for (let user of users) {
                    if (!Expo.isExpoPushToken(user.ExpoPushToken)) continue;

                    messages.push({
                        to: user.ExpoPushToken,
                        sound: 'default',
                        title: '💰 تحديث محفظة الذهب',
                        body: `سعر الجرام: ${livePriceSAR_Gram.toFixed(2)} ر.س | حالتك: ${status} ${Math.abs(profitLoss).toFixed(2)} ر.س`,
                        data: { withSome: 'data' },
                    });
                }

                let chunks = expo.chunkPushNotifications(messages);
                (async () => {
                    for (let chunk of chunks) {
                        try {
                            await expo.sendPushNotificationsAsync(chunk);
                        } catch (error) {
                            console.error(error);
                        }
                    }
                })();
            });

            // هنا يوضع كود إرسال الإشعار الفعلي للجوال عبر Expo
        });

    } catch (error) {
        console.error('Cron Job Error:', error);
    }
});
// دالة مساعدة لاقتطاع نسبة من الدخل تلقائياً
function processAutoSavings(userId, incomeAmount) {
    if (incomeAmount <= 0) return;

    // جلب الأهداف التي تحتوي على نسبة اقتطاع
    db.query('SELECT * FROM SavingsGoals WHERE UserId = ? AND AutoSavePercentage > 0', [userId], (err, goals) => {
        if (err || goals.length === 0) return;

        goals.forEach(goal => {
            const cutAmount = (incomeAmount * goal.AutoSavePercentage) / 100;
            if (cutAmount > 0) {
                // 1. زيادة رصيد الهدف
                db.query('UPDATE SavingsGoals SET CurrentAmount = CurrentAmount + ? WHERE Id = ?', [cutAmount, goal.Id]);

                // 2. تسجيل عملية "مصروف" في المعاملات حتى يتم خصمها من رصيد المحفظة العام
                const encryptedDesc = encrypt(`ادخار تلقائي (${goal.AutoSavePercentage}%) للهدف: ${goal.GoalName}`);
                const query = `INSERT INTO Transactions (UserId, Amount, Type, Category, SubCategory, Description, TransactionDate, PaymentMethod, Source) VALUES (?, ?, 'expense', 'ادخار', 'تلقائي', ?, NOW(), 'System', 'AutoSave')`;

                db.query(query, [userId, cutAmount, encryptedDesc]);
            }
        });
    });
}
// أضف هذا المسار في server.js لتجربة الإرسال اليدوي
app.get('/api/test-notification', async (req, res) => {
    const { Expo } = require('expo-server-sdk');
    let expo = new Expo();
    let messages = [];

    messages.push({
        to: 'ExponentPushToken[H9buiaICZx-H6o8R-OpXC-]', // التوكن الخاص بك
        sound: 'default',
        title: '🤖 اختبار سيرفر الذهب',
        body: 'مرحباً من Render! إذا وصلك هذا، فالسيرفر متصل بجوالك بنجاح.',
    });

    try {
        let chunks = expo.chunkPushNotifications(messages);
        for (let chunk of chunks) {
            await expo.sendPushNotificationsAsync(chunk);
        }
        res.json({ success: true, message: 'تم إرسال الإشعار من السيرفر!' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'فشل إرسال الإشعار' });
    }
});
app.post('/api/auth/update-push-token', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const { pushToken } = req.body;

    if (!pushToken) return res.status(400).json({ error: 'Push token is required' });

    db.query('UPDATE Users SET ExpoPushToken = ? WHERE Id = ?', [pushToken, userId], (err) => {
        if (err) {
            console.error("❌ Error updating push token:", err);
            return res.status(500).json({ error: 'Database error' });
        }
        console.log(`✅ Push Token updated for user ${userId}`);
        res.json({ success: true, message: 'Token updated successfully' });
    });
});
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







// ==========================================
// 🎯 مسارات الأهداف المالية (Savings Goals)
// ==========================================

// 1. جلب جميع الأهداف للمستخدم
app.get('/api/goals', authenticateToken, (req, res) => {
    db.query(
        'SELECT * FROM SavingsGoals WHERE UserId = ? ORDER BY CreatedAt DESC',
        [req.user.id],
        (err, goals) => {
            if (err) {
                console.error('Error fetching goals:', err);
                return res.status(500).json({ error: 'فشل في جلب الأهداف' });
            }
            res.json(goals);
        }
    );
});

// تحديث بنية الجدول تلقائياً (ضعه بعد التأكد من الاتصال بقاعدة البيانات)
db.query("SHOW COLUMNS FROM SavingsGoals LIKE 'AutoSavePercentage'", (err, res) => {
    if (res && res.length === 0) {
        db.query("ALTER TABLE SavingsGoals ADD COLUMN AutoSavePercentage INT DEFAULT 0, ADD COLUMN SweepSurplus BOOLEAN DEFAULT FALSE");
        console.log('✅ Added AutoSave columns to SavingsGoals table');
    }
});

// 2. تحديث مسار إضافة هدف جديد
app.post('/api/goals', authenticateToken, (req, res) => {
    const { GoalName, TargetAmount, AutoSavePercentage, SweepSurplus } = req.body;

    if (!GoalName || !TargetAmount) {
        return res.status(400).json({ error: 'اسم الهدف والمبلغ المستهدف مطلوبان' });
    }

    const autoPercentage = parseInt(AutoSavePercentage) || 0;
    const sweep = SweepSurplus ? 1 : 0;

    db.query(
        'INSERT INTO SavingsGoals (UserId, GoalName, TargetAmount, CurrentAmount, AutoSavePercentage, SweepSurplus) VALUES (?, ?, ?, 0, ?, ?)',
        [req.user.id, GoalName, TargetAmount, autoPercentage, sweep],
        (err, result) => {
            if (err) {
                console.error('Error adding goal:', err);
                return res.status(500).json({ error: 'فشل في إضافة الهدف' });
            }
            res.json({ success: true, message: 'تمت إضافة الهدف بنجاح', id: result.insertId });
        }
    );
});

// 3. إضافة مبلغ لمدخرات الهدف (تحديث CurrentAmount)
app.put('/api/goals/:id/add-funds', authenticateToken, (req, res) => {
    const goalId = req.params.id;
    const { amountToAdd } = req.body;

    if (!amountToAdd || amountToAdd <= 0) {
        return res.status(400).json({ error: 'المبلغ المضاف يجب أن يكون أكبر من صفر' });
    }

    db.query(
        'UPDATE SavingsGoals SET CurrentAmount = CurrentAmount + ? WHERE Id = ? AND UserId = ?',
        [amountToAdd, goalId, req.user.id],
        (err, result) => {
            if (err) {
                console.error('Error updating goal:', err);
                return res.status(500).json({ error: 'فشل في تحديث الهدف' });
            }
            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'الهدف غير موجود أو غير مصرح لك بتعديله' });
            }
            res.json({ success: true, message: 'تم تحديث المدخرات بنجاح' });
        }
    );
});

// 4. حذف هدف
app.delete('/api/goals/:id', authenticateToken, (req, res) => {
    const goalId = req.params.id;

    db.query(
        'DELETE FROM SavingsGoals WHERE Id = ? AND UserId = ?',
        [goalId, req.user.id],
        (err, result) => {
            if (err) {
                console.error('Error deleting goal:', err);
                return res.status(500).json({ error: 'فشل في حذف الهدف' });
            }
            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'الهدف غير موجود أو غير مصرح لك بحذفه' });
            }
            res.json({ success: true, message: 'تم حذف الهدف بنجاح' });
        }
    );
});





// --- أضف هذه المسارات في server.js ---

// 1. جلب قائمة المشتريات بالتفصيل (للعرض والحذف)
app.get('/api/assets/gold/list', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const query = 'SELECT * FROM Assets WHERE UserId = ? AND AssetType = "Gold" ORDER BY PurchaseDate DESC';

    db.query(query, [userId], (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(results);
    });
});

// ✅ Corrected DELETE Route
app.delete('/api/assets/gold/:id', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const assetId = req.params.id;

    // نتحقق من AssetId وأيضاً UserId لضمان أمان البيانات (لا يمكن حذف أصل لمستخدم آخر)
    const query = 'DELETE FROM Assets WHERE Id = ? AND UserId = ?';

    db.query(query, [assetId, userId], (err, result) => {
        if (err) {
            console.error("❌ Delete error:", err.message);
            return res.status(500).json({ error: 'Database error' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Asset not found or unauthorized' });
        }

        res.json({ success: true, message: 'تم حذف العملية بنجاح' });
    });
});

// ✅ Corrected Gold Assets Route with LIVE Data
app.get('/api/assets/gold', authenticateToken, async (req, res) => {
    const userId = req.user.id;

    try {
        // 1. جلب السعر المباشر من API خارجي
        // ملاحظة: يمكنك وضع الـ API Key في ملف .env
        const GOLD_API_KEY = process.env.GOLD_API_KEY || 'YOUR_FREE_API_KEY_HERE';

        const goldRes = await fetch('https://www.goldapi.io/api/XAU/USD', {
            headers: {
                'x-access-token': GOLD_API_KEY,
                'Content-Type': 'application/json'
            }
        });

        const goldData = await goldRes.json();

        // التحقق من صحة البيانات القادمة من الـ API
        // السعر العالمي للأونصة بالدولار
        const livePricePerOunceUSD = goldData.price || 2700.00;
        const usdToSar = 3.75;
        const gramsPerOunce = 31.1035;

        // حسابات دقيقة
        const livePriceSAR_Ounce = livePricePerOunceUSD * usdToSar; // سعر الأونصة بالريال
        const livePriceSAR_Gram = livePriceSAR_Ounce / gramsPerOunce; // سعر الجرام بالريال

        console.log(`📊 Live Market: Ounce $${livePricePerOunceUSD} | Gram SAR ${livePriceSAR_Gram.toFixed(2)}`);

        // 2. جلب أصول المستخدم من قاعدة البيانات
        const query = 'SELECT * FROM Assets WHERE UserId = ? AND AssetType = ?';
        db.query(query, [userId, 'Gold'], (err, results) => {
            if (err) return res.status(500).json({ error: 'Database error' });

            let totalGrams = 0;
            let totalCost = 0;

            results.forEach(asset => {
                const weight = parseFloat(asset.WeightInOunces) || 0;
                const pricePerGram = parseFloat(asset.PurchasePricePerOunce) || 0;

                totalGrams += weight;
                totalCost += (weight * pricePerGram);
            });

            const currentValue = totalGrams * livePriceSAR_Gram;
            const profitLoss = currentValue - totalCost;

            res.json({
                totalGrams: Number(totalGrams.toFixed(2)),
                currentValue: Number(currentValue.toFixed(2)),
                totalCost: Number(totalCost.toFixed(2)),
                profitLoss: Number(profitLoss.toFixed(2)),
                profitLossPercentage: totalCost > 0 ? Number(((profitLoss / totalCost) * 100).toFixed(2)) : 0,
                livePriceSAR: Number(livePriceSAR_Gram.toFixed(2)), // سعر الجرام بالريال
                livePriceOunceUSD: Number(livePricePerOunceUSD.toFixed(2)), // سعر الأونصة بالدولار
                items: results
            });
        });

    } catch (error) {
        console.error("❌ External API Error:", error.message);
        res.status(500).json({ error: 'Failed to fetch live gold price' });
    }
});

// مسار لإضافة ذهب جديد - مع تعقب محسن
app.post('/api/assets/gold', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const { WeightInOunces, PurchasePricePerOunce } = req.body;

    console.log(`📝 Adding gold for user ${userId}:`, { WeightInOunces, PurchasePricePerOunce });

    // Validate input
    if (!WeightInOunces || !PurchasePricePerOunce) {
        console.log('❌ Missing required fields');
        return res.status(400).json({ error: 'Weight and price are required' });
    }

    const weight = parseFloat(WeightInOunces);
    const price = parseFloat(PurchasePricePerOunce);

    if (isNaN(weight) || weight <= 0 || isNaN(price) || price <= 0) {
        console.log('❌ Invalid values:', { weight, price });
        return res.status(400).json({ error: 'Invalid weight or price values' });
    }

    const query = "INSERT INTO Assets (UserId, AssetType, WeightInOunces, PurchasePricePerOunce) VALUES (?, 'Gold', ?, ?)";

    db.query(query, [userId, weight, price], (err, result) => {
        if (err) {
            console.error('❌ Database error while adding asset:', err.message);
            console.error('❌ SQL Error details:', err);
            return res.status(500).json({
                error: 'Failed to add asset',
                details: err.message,
                sqlError: err.code
            });
        }

        console.log('✅ Asset added successfully:', {
            insertId: result.insertId,
            affectedRows: result.affectedRows
        });

        res.status(201).json({
            success: true,
            message: 'تم إضافة الأصل بنجاح',
            id: result.insertId
        });
    });
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
        if (Type === 'income') {
            processAutoSavings(userId, Amount);
        }
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

    const ignoreKeywords = ["رمز مؤقت", "رمز التفعيل", "تم تفعيل", "إضافة مستفيد", "كود", "OTP", "رمز", "تأكيد", "تفعيل"];
    if (!rawText || rawText.trim().length < 10 || ignoreKeywords.some(key => rawText.includes(key))) {
        console.log('🚫 [Ignored]: SMS is not a financial transaction or too short.');
        return res.json({ status: "ignored" });
    }

    let amount = 0;
    const amountMatch = rawText.match(/(?:مبلغ|بـ|SAR)\s*:?\s*([\d,.]+)/i) || rawText.match(/([\d,.]+)\s*(?:ريال|SAR)/i);
    if (amountMatch) amount = parseFloat(amountMatch[1].replace(/,/g, ''));

    const textLower = rawText.toLowerCase();
    const isIncome = rawText.includes("واردة") || rawText.includes("إيداع") || rawText.includes("استرجاع") || rawText.includes("محولة");
    const type = isIncome ? "income" : "expense";

    let paymentMethod = 'Bank Transfer';
    if (textLower.includes("applepay") || textLower.includes("ابل باي")) paymentMethod = 'Apple Pay';
    else if (textLower.includes("بطاقة") || textLower.includes("مدى") || textLower.includes("شراء") || textLower.includes("مشتريات")) paymentMethod = 'Card (Mada)';
    else if (textLower.includes("stc pay")) paymentMethod = 'STC Pay';

    console.log(`💰 [Initial Data]: Amount: ${amount} | Type: ${type} | Payment Method: ${paymentMethod}`);

    // Default settings
    let description = "عملية بنكية";
    let category = isIncome ? "حوالات واردة" : "مصروفات عامة";
    let subCategory = "عام";
    let isRecurring = false;
    let needsAI = true;


    const merchantsDictionary = [
        // ========== 🚗 محطات الوقود وصيانة السيارات ==========
        { keys: ["joil", "j oil", "جي اويل", "جويل"], name: "جي أويل", cat: "السيارة والمواصلات", sub: "محطات وقود" },
        { keys: ["aldrees", "الدريس"], name: "الدريس", cat: "السيارة والمواصلات", sub: "محطات وقود" },
        { keys: ["sasco", "ساسكو"], name: "ساسكو", cat: "السيارة والمواصلات", sub: "محطات وقود" },
        { keys: ["petromin", "بترومين"], name: "بترومين", cat: "السيارة والمواصلات", sub: "صيانة ووقود" },
        { keys: ["shell", "شل"], name: "شل", cat: "السيارة والمواصلات", sub: "محطات وقود" },
        { keys: ["total", "توتال"], name: "توتال", cat: "السيارة والمواصلات", sub: "محطات وقود" },
        { keys: ["enoc", "اينوك"], name: "اينوك", cat: "السيارة والمواصلات", sub: "محطات وقود" },
        { keys: ["adnoc", "ادنوك"], name: "ادنوك", cat: "السيارة والمواصلات", sub: "محطات وقود" },
        { keys: ["naft", "نفط"], name: "محطات نفط", cat: "السيارة والمواصلات", sub: "محطات وقود" },
        { keys: ["sahel", "سهل"], name: "محطات سهل", cat: "السيارة والمواصلات", sub: "محطات وقود" },
        { keys: ["tashelat", "تسهيلات"], name: "محطات تسهيلات", cat: "السيارة والمواصلات", sub: "محطات وقود" },
        { keys: ["mizan", "ميزان", "الميزان"], name: "ميزان سيارات", cat: "السيارة والمواصلات", sub: "صيانة سيارات" },
        { keys: ["aljomaih", "الجميح"], name: "الجميح للسيارات", cat: "السيارة والمواصلات", sub: "صيانة سيارات" },
        { keys: ["abdul latif jameel", "عبداللطيف جميل", "عبد اللطيف جميل"], name: "عبداللطيف جميل", cat: "السيارة والمواصلات", sub: "صيانة سيارات" },

        // ========== 🛒 السوبرماركت والتموين ==========
        { keys: ["panda", "بنده", "باندا"], name: "بنده", cat: "المنزل والمقاضي", sub: "سوبرماركت" },
        { keys: ["danube", "الدانوب"], name: "الدانوب", cat: "المنزل والمقاضي", sub: "سوبرماركت" },
        { keys: ["carrefour", "كارفور"], name: "كارفور", cat: "المنزل والمقاضي", sub: "سوبرماركت" },
        { keys: ["lulu", "لولو"], name: "لولو هايبرماركت", cat: "المنزل والمقاضي", sub: "سوبرماركت" },
        { keys: ["tamimi", "تميمي", "تميمى", "التميمي"], name: "أسواق التميمي", cat: "المنزل والمقاضي", sub: "سوبرماركت" },
        { keys: ["othaim", "العثيم", "عثيم"], name: "أسواق العثيم", cat: "المنزل والمقاضي", sub: "سوبرماركت" },
        { keys: ["farm", "فارم", "الاسرة", "أسواق الأسرة"], name: "أسواق المزرعة", cat: "المنزل والمقاضي", sub: "سوبرماركت" },
        { keys: ["nesto", "نستو"], name: "نستو", cat: "المنزل والمقاضي", sub: "سوبرماركت" },
        { keys: ["bin dawoud", "بن داود", "بن داوود", "bindawood"], name: "بن داود", cat: "المنزل والمقاضي", sub: "سوبرماركت" },
        { keys: ["al-azizia", "العزيزية"], name: "العزيزية", cat: "المنزل والمقاضي", sub: "سوبرماركت" },
        { keys: ["manhal", "المنهل"], name: "المنهل", cat: "المنزل والمقاضي", sub: "مياه وتموين" },
        { keys: ["raghdan", "رغدان"], name: "رغدان", cat: "المنزل والمقاضي", sub: "سوبرماركت" },
        { keys: ["alraya", "الراية"], name: "أسواق الراية", cat: "المنزل والمقاضي", sub: "سوبرماركت" },
        { keys: ["sadhan", "السدحان"], name: "السدحان", cat: "المنزل والمقاضي", sub: "سوبرماركت" },
        { keys: ["spar", "سبار"], name: "سبار", cat: "المنزل والمقاضي", sub: "سوبرماركت" },
        { keys: ["meed", "ميد"], name: "ميد", cat: "المنزل والمقاضي", sub: "تموينات" },
        { keys: ["sarawat", "السروات"], name: "السروات", cat: "المنزل والمقاضي", sub: "سوبرماركت" },

        // ========== 🍔 المطاعم والوجبات السريعة ==========
        { keys: ["mcdonald", "mcd", "ماك", "مكدونالدز", "ماكدونالدز"], name: "ماكدونالدز", cat: "المطاعم والكافيهات", sub: "وجبات سريعة" },
        { keys: ["albaik", "البيك", "البيع"], name: "البيك", cat: "المطاعم والكافيهات", sub: "وجبات سريعة" },
        { keys: ["kfc", "ك إف سي", "كنتاكي", "kentucky"], name: "كنتاكي", cat: "المطاعم والكافيهات", sub: "وجبات سريعة" },
        { keys: ["burger king", "برجر كنج", "برجر كينج"], name: "برجر كنج", cat: "المطاعم والكافيهات", sub: "وجبات سريعة" },
        { keys: ["herfy", "هرفي"], name: "هرفي", cat: "المطاعم والكافيهات", sub: "وجبات سريعة" },
        { keys: ["hardee", "هارديز"], name: "هارديز", cat: "المطاعم والكافيهات", sub: "وجبات سريعة" },
        { keys: ["pizza hut", "بيتزا هت"], name: "بيتزا هت", cat: "المطاعم والكافيهات", sub: "وجبات سريعة" },
        { keys: ["domino", "دومينوز"], name: "دومينوز بيتزا", cat: "المطاعم والكافيهات", sub: "وجبات سريعة" },
        { keys: ["maestro", "مايسترو"], name: "مايسترو بيتزا", cat: "المطاعم والكافيهات", sub: "وجبات سريعة" },
        { keys: ["kudu", "كودو"], name: "كودو", cat: "المطاعم والكافيهات", sub: "وجبات سريعة" },
        { keys: ["subway", "صب واي", "صَب واي"], name: "صب واي", cat: "المطاعم والكافيهات", sub: "وجبات سريعة" },
        { keys: ["texas chicken", "تكساس تشيكن", "تكساس"], name: "تكساس تشيكن", cat: "المطاعم والكافيهات", sub: "وجبات سريعة" },
        { keys: ["shawarmer", "شاورمر"], name: "شاورمر", cat: "المطاعم والكافيهات", sub: "وجبات سريعة" },
        { keys: ["mama noura", "ماما نورة", "ماما نوره"], name: "ماما نورة", cat: "المطاعم والكافيهات", sub: "مطاعم" },
        { keys: ["abu zaid", "ابو زيد", "أبو زيد"], name: "ابو زيد", cat: "المطاعم والكافيهات", sub: "مطاعم" },
        { keys: ["alromansiah", "الرومانسية"], name: "الرومانسية", cat: "المطاعم والكافيهات", sub: "مطاعم" },
        { keys: ["al tazaj", "tazaj", "الطازج"], name: "الطازج", cat: "المطاعم والكافيهات", sub: "وجبات سريعة" },
        { keys: ["shobak", "شوبك"], name: "شوبك", cat: "المطاعم والكافيهات", sub: "مطاعم" },
        { keys: ["canton", "كانتون"], name: "كانتون", cat: "المطاعم والكافيهات", sub: "مطاعم" },
        { keys: ["shawarma", "شاورما"], name: "شاورما", cat: "المطاعم والكافيهات", sub: "وجبات سريعة" },

        // ========== ☕ الكافيهات والمخابز ==========
        { keys: ["starbucks", "ستاربكس"], name: "ستاربكس", cat: "المطاعم والكافيهات", sub: "كافيهات" },
        { keys: ["costa", "كوستا"], name: "كوستا كافيه", cat: "المطاعم والكافيهات", sub: "كافيهات" },
        { keys: ["dunkin", "دنكن", "دانكن"], name: "دنكن دونتس", cat: "المطاعم والكافيهات", sub: "كافيهات" },
        { keys: ["tim hortons", "تيم هورتون", "تيم هورتنز"], name: "تيم هورتنز", cat: "المطاعم والكافيهات", sub: "كافيهات" },
        { keys: ["barn cafe", "بارن كافيه", "barns", "بارنز", "barn"], name: "بارنز", cat: "المطاعم والكافيهات", sub: "كافيهات" },
        { keys: ["dr cafe", "د. كيف", "د كيف"], name: "د. كيف", cat: "المطاعم والكافيهات", sub: "كافيهات" },
        { keys: ["half million", "هاف مليون"], name: "هاف مليون", cat: "المطاعم والكافيهات", sub: "كافيهات" },
        { keys: ["jolt", "جولت"], name: "جولت", cat: "المطاعم والكافيهات", sub: "كافيهات" },
        { keys: ["over dose", "overdose", "اوفر دوز"], name: "اوفر دوز", cat: "المطاعم والكافيهات", sub: "كافيهات" },
        { keys: ["waynes", "واينز"], name: "واينز كافيه", cat: "المطاعم والكافيهات", sub: "كافيهات" },
        { keys: ["caribou", "كاريبو"], name: "كاريبو كافيه", cat: "المطاعم والكافيهات", sub: "كافيهات" },
        { keys: ["krispy kreme", "كريسبي كريم"], name: "كريسبي كريم", cat: "المطاعم والكافيهات", sub: "مخبوزات وحلويات" },
        { keys: ["baskin robbins", "باسكن روبنز"], name: "باسكن روبنز", cat: "المطاعم والكافيهات", sub: "مخبوزات وحلويات" },
        { keys: ["saadeddin", "سعد الدين"], name: "حلويات سعد الدين", cat: "المطاعم والكافيهات", sub: "مخبوزات وحلويات" },

        // ========== 🛵 تطبيقات التوصيل ==========
        { keys: ["jahez", "جاهز"], name: "جاهز", cat: "المطاعم والكافيهات", sub: "توصيل طلبات" },
        { keys: ["hungerstation", "hunger station", "هنقرستيشن", "هنقر ستيشن"], name: "هنقرستيشن", cat: "المطاعم والكافيهات", sub: "توصيل طلبات" },
        { keys: ["toyou", "تويو"], name: "تويو", cat: "المطاعم والكافيهات", sub: "توصيل طلبات" },
        { keys: ["mrsool", "مرسول"], name: "مرسول", cat: "المنزل والمقاضي", sub: "توصيل طلبات" },
        { keys: ["noon food", "نون فود"], name: "نون فود", cat: "المطاعم والكافيهات", sub: "توصيل طلبات" },
        { keys: ["the chefz", "chefz", "ذا شفز", "شيفز"], name: "ذا شفز", cat: "المطاعم والكافيهات", sub: "توصيل طلبات" },
        { keys: ["careem", "كريم"], name: "كريم", cat: "السيارة والمواصلات", sub: "تطبيقات نقل" },
        { keys: ["uber", "اوبر", "أوبر"], name: "أوبر", cat: "السيارة والمواصلات", sub: "تطبيقات نقل" },
        { keys: ["jeeny", "جيني"], name: "جيني", cat: "السيارة والمواصلات", sub: "تطبيقات نقل" },
        { keys: ["ego", "ايجو", "إيجو"], name: "ايجو", cat: "السيارة والمواصلات", sub: "تطبيقات نقل" },

        // ========== 💊 الصحة والجمال ==========
        { keys: ["nahdi", "النهدي"], name: "صيدلية النهدي", cat: "الصحة والجمال", sub: "صيدليات" },
        { keys: ["al-dawaa", "الدواء", "aldawaa"], name: "صيدلية الدواء", cat: "الصحة والجمال", sub: "صيدليات" },
        { keys: ["watsons", "واتسون", "واطسون"], name: "واطسون", cat: "الصحة والجمال", sub: "مستحضرات تجميل" },
        { keys: ["whites", "وايتس"], name: "صيدلية وايتس", cat: "الصحة والجمال", sub: "صيدليات" },
        { keys: ["al-saggaf", "السقاف"], name: "صيدلية السقاف", cat: "الصحة والجمال", sub: "صيدليات" },
        { keys: ["abdal samad", "abdulsamad", "عبدالصمد", "عبد الصمد"], name: "عبدالصمد القرشي", cat: "الصحة والجمال", sub: "عطور" },
        { keys: ["arabian oud", "العربية للعود"], name: "العربية للعود", cat: "الصحة والجمال", sub: "عطور" },
        { keys: ["almajmaah", "الماجد للعود", "almajed"], name: "الماجد للعود", cat: "الصحة والجمال", sub: "عطور" },
        { keys: ["ibrahim alqurashi", "ابراهيم القرشي", "إبراهيم القرشي"], name: "إبراهيم القرشي", cat: "الصحة والجمال", sub: "عطور" },
        { keys: ["aljasser", "الجاسر"], name: "الجاسر للعطور", cat: "الصحة والجمال", sub: "عطور" },
        { keys: ["bath & body", "bath and body", "باث اند", "باث آند"], name: "باث آند بودي", cat: "الصحة والجمال", sub: "مستحضرات تجميل" },
        { keys: ["sephora", "سيفورا"], name: "سيفورا", cat: "الصحة والجمال", sub: "مستحضرات تجميل" },
        { keys: ["faces", "فيس", "وجوه"], name: "وجوه (فيسز)", cat: "الصحة والجمال", sub: "مستحضرات تجميل" },
        { keys: ["oud milano", "عود ميلانو"], name: "عود ميلانو", cat: "الصحة والجمال", sub: "مستحضرات تجميل" },
        { keys: ["derma", "ديرما"], name: "ديرما", cat: "الصحة والجمال", sub: "عيادات وتجميل" },

        // ========== 💻 الإلكترونيات والأجهزة ==========
        { keys: ["jarir", "جرير"], name: "مكتبة جرير", cat: "التسوق", sub: "إلكترونيات ومكتبية" },
        { keys: ["extra", "اكسترا", "إكسترا"], name: "إكسترا", cat: "التسوق", sub: "إلكترونيات" },
        { keys: ["xcite", "اكسايت", "إكسايت"], name: "إكسايت", cat: "التسوق", sub: "إلكترونيات" },
        { keys: ["eddy", "ايدي", "إيدي"], name: "إيدي للإلكترونيات", cat: "التسوق", sub: "إلكترونيات" },
        { keys: ["black box", "الصندوق الاسود", "الصندوق الأسود"], name: "الصندوق الأسود", cat: "التسوق", sub: "إلكترونيات" },
        { keys: ["emax", "ايماكس"], name: "إيماكس", cat: "التسوق", sub: "إلكترونيات" },
        { keys: ["virgin mega", "فيرجن ميجا", "فيرجن ميجاب"], name: "فيرجن ميجاستور", cat: "التسوق", sub: "إلكترونيات وترفيه" },
        { keys: ["al-mukmal", "المكمل"], name: "المكمل", cat: "التسوق", sub: "إلكترونيات" },
        { keys: ["apple store", "ابل ستور", "أبل ستور"], name: "أبل ستور", cat: "التسوق", sub: "إلكترونيات" },

        // ========== 👗 الملابس والأزياء ==========
        { keys: ["centrepoint", "سنتربوينت", "سنتر بوينت"], name: "سنتربوينت", cat: "التسوق", sub: "ملابس" },
        { keys: ["splash", "سبلاش"], name: "سبلاش", cat: "التسوق", sub: "ملابس" },
        { keys: ["max", "ماكس", "city max", "سيتي ماكس"], name: "سيتي ماكس", cat: "التسوق", sub: "ملابس" },
        { keys: ["red tag", "redtag", "ريد تاغ", "ريدتاغ"], name: "ريد تاغ", cat: "التسوق", sub: "ملابس" },
        { keys: ["zara", "زارا"], name: "زارا", cat: "التسوق", sub: "ملابس" },
        { keys: ["hm", "h&m", "إتش آند إم", "اتش اند ام"], name: "H&M", cat: "التسوق", sub: "ملابس" },
        { keys: ["sacoor", "ساكور"], name: "ساكور", cat: "التسوق", sub: "ملابس" },
        { keys: ["mango", "مانجو"], name: "مانجو", cat: "التسوق", sub: "ملابس" },
        { keys: ["next", "نكست"], name: "نكست", cat: "التسوق", sub: "ملابس" },
        { keys: ["lc waikiki", "ال سي وايكيكي"], name: "ال سي وايكيكي", cat: "التسوق", sub: "ملابس" },
        { keys: ["riva", "ريفا"], name: "ريفا", cat: "التسوق", sub: "ملابس" },
        { keys: ["milano", "ميلانو"], name: "ميلانو", cat: "التسوق", sub: "أحذية وحقائب" },
        { keys: ["sun and sand", "sun & sand", "الشمس والرمال"], name: "الشمس والرمال", cat: "التسوق", sub: "ملابس رياضية" },
        { keys: ["adidas", "اديداس", "أديداس"], name: "أديداس", cat: "التسوق", sub: "ملابس رياضية" },
        { keys: ["nike", "نايك", "نايكي"], name: "نايك", cat: "التسوق", sub: "ملابس رياضية" },
        { keys: ["puma", "بوما"], name: "بوما", cat: "التسوق", sub: "ملابس رياضية" },
        { keys: ["foot locker", "فوت لوكر"], name: "فوت لوكر", cat: "التسوق", sub: "ملابس رياضية" },

        // ========== 🌐 التسوق عبر الإنترنت ==========
        { keys: ["amazon", "امازون", "أمازون"], name: "أمازون", cat: "التسوق", sub: "تسوق عبر الإنترنت" },
        { keys: ["noon", "نون"], name: "نون", cat: "التسوق", sub: "تسوق عبر الإنترنت" },
        { keys: ["shein", "شي ان", "شي إن"], name: "شي إن", cat: "التسوق", sub: "تسوق عبر الإنترنت" },
        { keys: ["namshi", "نمشي"], name: "نمشي", cat: "التسوق", sub: "تسوق عبر الإنترنت" },
        { keys: ["asos", "اسوس"], name: "أسوس", cat: "التسوق", sub: "تسوق عبر الإنترنت" },
        { keys: ["aliexpress", "ali express", "علي اكسبرس", "علي إكسبرس"], name: "علي إكسبرس", cat: "التسوق", sub: "تسوق عبر الإنترنت" },
        { keys: ["iherb", "اي هيرب", "آي هيرب"], name: "آي هيرب", cat: "التسوق", sub: "تسوق عبر الإنترنت" },
        { keys: ["temu", "تيمو"], name: "تيمو", cat: "التسوق", sub: "تسوق عبر الإنترنت" },
        { keys: ["trendyol", "ترينديول"], name: "ترينديول", cat: "التسوق", sub: "تسوق عبر الإنترنت" },
        { keys: ["golden scent", "قولدن سنت"], name: "قولدن سنت", cat: "التسوق", sub: "تسوق عبر الإنترنت" },
        { keys: ["nice one", "نايس ون"], name: "نايس ون", cat: "التسوق", sub: "تسوق عبر الإنترنت" },

        // ========== 📱 الاشتراكات الرقمية والاتصالات ==========
        { keys: ["stc", "الاتصالات السعودية"], name: "STC", cat: "فواتير واشتراكات", sub: "اتصالات", recurring: true },
        { keys: ["mobily", "موبايلي"], name: "موبايلي", cat: "فواتير واشتراكات", sub: "اتصالات", recurring: true },
        { keys: ["zain", "زين"], name: "زين", cat: "فواتير واشتراكات", sub: "اتصالات", recurring: true },
        { keys: ["virgin mobile", "فيرجن موبايل"], name: "فيرجن موبايل", cat: "فواتير واشتراكات", sub: "اتصالات", recurring: true },
        { keys: ["lebara", "ليبارا"], name: "ليبارا", cat: "فواتير واشتراكات", sub: "اتصالات", recurring: true },
        { keys: ["salam", "سلام موبايل"], name: "سلام", cat: "فواتير واشتراكات", sub: "اتصالات", recurring: true },
        { keys: ["yaqoot", "ياقوت"], name: "ياقوت", cat: "فواتير واشتراكات", sub: "اتصالات", recurring: true },
        { keys: ["jawwy", "جوي"], name: "جوي من STC", cat: "فواتير واشتراكات", sub: "اتصالات", recurring: true },
        { keys: ["netflix", "نتفلكس", "نتفليكس"], name: "Netflix", cat: "فواتير واشتراكات", sub: "ترفيه", recurring: true },
        { keys: ["shahid", "شاهد"], name: "شاهد VIP", cat: "فواتير واشتراكات", sub: "ترفيه", recurring: true },
        { keys: ["spotify", "سبوتيفاي"], name: "Spotify", cat: "فواتير واشتراكات", sub: "ترفيه", recurring: true },
        { keys: ["apple.com/bill", "apple music", "ابل ميوزك", "ابل ستور", "itunes"], name: "Apple Services", cat: "فواتير واشتراكات", sub: "خدمات أبل", recurring: true },
        { keys: ["youtube", "يوتيوب"], name: "YouTube Premium", cat: "فواتير واشتراكات", sub: "ترفيه", recurring: true },
        { keys: ["openai", "chatgpt", "تشات جي بي تي"], name: "OpenAI ChatGPT", cat: "فواتير واشتراكات", sub: "اشتراكات رقمية", recurring: true },
        { keys: ["microsoft", "مايكروسوفت"], name: "Microsoft", cat: "فواتير واشتراكات", sub: "اشتراكات رقمية", recurring: true },
        { keys: ["google", "g.co", "قوقل"], name: "Google Services", cat: "فواتير واشتراكات", sub: "اشتراكات رقمية", recurring: true },
        { keys: ["bein", "بي ان", "بي إن"], name: "beIN Sports", cat: "فواتير واشتراكات", sub: "ترفيه", recurring: true },
        { keys: ["osn", "او اس ان"], name: "OSN", cat: "فواتير واشتراكات", sub: "ترفيه", recurring: true },
        { keys: ["amazon prime", "امازون برايم"], name: "Amazon Prime", cat: "فواتير واشتراكات", sub: "ترفيه", recurring: true },
        { keys: ["playstation", "بليستيشن", "بلايستيشن"], name: "PlayStation Network", cat: "فواتير واشتراكات", sub: "ألعاب", recurring: true },
        { keys: ["xbox", "اكس بوكس"], name: "Xbox Live", cat: "فواتير واشتراكات", sub: "ألعاب", recurring: true },

        // ========== 🏦 البنوك والخدمات المالية ==========
        { keys: ["الاهلي", "البنك الاهلي", "alahli", "snb"], name: "البنك الأهلي", cat: "فواتير واشتراكات", sub: "عمولات بنكية", recurring: true },
        { keys: ["الراجحي", "مصرف الراجحي", "alrajhi"], name: "مصرف الراجحي", cat: "فواتير واشتراكات", sub: "عمولات بنكية", recurring: true },
        { keys: ["الانماء", "مصرف الانماء", "alinma"], name: "مصرف الإنماء", cat: "فواتير واشتراكات", sub: "عمولات بنكية", recurring: true },
        { keys: ["العربي", "البنك العربي", "anb"], name: "البنك العربي", cat: "فواتير واشتراكات", sub: "عمولات بنكية", recurring: true },
        { keys: ["ساب", "sabb", "sbb"], name: "بنك ساب", cat: "فواتير واشتراكات", sub: "عمولات بنكية", recurring: true },
        { keys: ["الرياض", "riyad bank"], name: "بنك الرياض", cat: "فواتير واشتراكات", sub: "عمولات بنكية", recurring: true },
        { keys: ["الجزيرة", "aljazira bank"], name: "بنك الجزيرة", cat: "فواتير واشتراكات", sub: "عمولات بنكية", recurring: true },
        { keys: ["البلاد", "albilad"], name: "بنك البلاد", cat: "فواتير واشتراكات", sub: "عمولات بنكية", recurring: true },
        { keys: ["الفرنسي", "alfransi", "bsf"], name: "البنك السعودي الفرنسي", cat: "فواتير واشتراكات", sub: "عمولات بنكية", recurring: true },
        { keys: ["الاول", "alawwal"], name: "البنك الأول", cat: "فواتير واشتراكات", sub: "عمولات بنكية", recurring: true },
        { keys: ["الاستثمار", "saib"], name: "البنك السعودي للاستثمار", cat: "فواتير واشتراكات", sub: "عمولات بنكية", recurring: true },
        { keys: ["stc pay", "stcpay", "اس تي سي باي"], name: "STC Pay", cat: "مصروفات عامة", sub: "محفظة رقمية", recurring: false },
        { keys: ["urpay", "يورباي", "يور باي"], name: "UrPay", cat: "مصروفات عامة", sub: "محفظة رقمية", recurring: false },
        { keys: ["alinmapay", "الانماء باي", "الإنماء باي"], name: "AlinmaPay", cat: "مصروفات عامة", sub: "محفظة رقمية", recurring: false },

        // ========== 🏛️ الخدمات الحكومية والفواتير ==========
        { keys: ["ساهر", "المرور", "saher", "mror"], name: "مخالفات المرور (ساهر)", cat: "السيارة والمواصلات", sub: "مخالفات", recurring: false },
        { keys: ["الاحوال", "أبشر", "absher"], name: "خدمات أبشر", cat: "فواتير واشتراكات", sub: "خدمات حكومية" },
        { keys: ["الكهرباء", "السعودية للكهرباء", "sec"], name: "الشركة السعودية للكهرباء", cat: "فواتير واشتراكات", sub: "كهرباء", recurring: true },
        { keys: ["المياه", "المياة", "nwc"], name: "شركة المياه الوطنية", cat: "فواتير واشتراكات", sub: "مياه", recurring: true },
        { keys: ["qiwa", "قوى"], name: "منصة قوى", cat: "فواتير واشتراكات", sub: "خدمات حكومية", recurring: true },
        { keys: ["najiz", "ناجز"], name: "منصة ناجز", cat: "فواتير واشتراكات", sub: "خدمات حكومية", recurring: false },
        { keys: ["muqeem", "مقيم"], name: "بوابة مقيم", cat: "فواتير واشتراكات", sub: "خدمات حكومية", recurring: true },
        { keys: ["ejar", "ايجار", "إيجار"], name: "شبكة إيجار", cat: "المنزل والمقاضي", sub: "إيجار", recurring: true },
        { keys: ["jawazat", "الجوازات"], name: "المديرية العامة للجوازات", cat: "فواتير واشتراكات", sub: "خدمات حكومية", recurring: false },
        { keys: ["balady", "بلدي"], name: "منصة بلدي", cat: "فواتير واشتراكات", sub: "خدمات حكومية", recurring: false },
        { keys: ["efaa", "ايفاء", "إيفاء"], name: "منصة إيفاء للمخالفات", cat: "فواتير واشتراكات", sub: "مخالفات", recurring: false },
        { keys: ["ehsan", "احسان", "إحسان"], name: "منصة إحسان", cat: "مصروفات عامة", sub: "تبرعات", recurring: false },

        // ========== 🛡️ التأمين ==========
        { keys: ["tameeni", "تأميني"], name: "تأميني", cat: "السيارة والمواصلات", sub: "تأمين", recurring: true },
        { keys: ["tawuniya", "التعاونية"], name: "التعاونية للتأمين", cat: "السيارة والمواصلات", sub: "تأمين", recurring: true },
        { keys: ["medgulf", "ميدغلف"], name: "ميدغلف للتأمين", cat: "السيارة والمواصلات", sub: "تأمين", recurring: true },
        { keys: ["al rajhi takaful", "الراجحي تكافل"], name: "الراجحي تكافل", cat: "السيارة والمواصلات", sub: "تأمين", recurring: true },
        { keys: ["bupa", "بوبا"], name: "بوبا العربية", cat: "الصحة والجمال", sub: "تأمين طبي", recurring: true },
        { keys: ["enaya", "عناية"], name: "عناية للتأمين", cat: "السيارة والمواصلات", sub: "تأمين", recurring: true },
        { keys: ["alalamiya", "العالمية"], name: "العالمية للتأمين", cat: "السيارة والمواصلات", sub: "تأمين", recurring: true },
        { keys: ["saico", "سايكو"], name: "سايكو للتأمين", cat: "السيارة والمواصلات", sub: "تأمين", recurring: true },
        { keys: ["alhlal", "الهلال"], name: "الهلال للتأمين", cat: "السيارة والمواصلات", sub: "تأمين", recurring: true },
        { keys: ["alazm", "العزم"], name: "العزم للتأمين", cat: "السيارة والمواصلات", sub: "تأمين", recurring: true },
        { keys: ["wafa", "وفا"], name: "وفا للتأمين", cat: "السيارة والمواصلات", sub: "تأمين", recurring: true },
        { keys: ["aljazira takaful", "تكافل الجزيرة"], name: "تكافل الجزيرة", cat: "السيارة والمواصلات", sub: "تأمين", recurring: true },
        { keys: ["malath", "ملاذ"], name: "ملاذ للتأمين", cat: "السيارة والمواصلات", sub: "تأمين", recurring: true },
        { keys: ["walaa", "ولاء"], name: "ولاء للتأمين", cat: "السيارة والمواصلات", sub: "تأمين", recurring: true },
        { keys: ["acig", "اسيج", "أسيج"], name: "أسيج للتأمين", cat: "السيارة والمواصلات", sub: "تأمين", recurring: true },
        { keys: ["chubb", "تشب"], name: "تشب العربية للتأمين", cat: "السيارة والمواصلات", sub: "تأمين", recurring: true },
        { keys: ["gulf union", "اتحاد الخليج"], name: "اتحاد الخليج للتأمين", cat: "السيارة والمواصلات", sub: "تأمين", recurring: true },
        { keys: ["buruj", "بروج"], name: "بروج للتأمين", cat: "السيارة والمواصلات", sub: "تأمين", recurring: true },
        { keys: ["salama", "سلامة"], name: "سلامة للتأمين", cat: "السيارة والمواصلات", sub: "تأمين", recurring: true },
        { keys: ["al sakr", "الصقر"], name: "الصقر للتأمين", cat: "السيارة والمواصلات", sub: "تأمين", recurring: true },

        // ========== 🎟️ الترفيه والسياحة ==========
        { keys: ["vox", "فوكس"], name: "فوكس سينما", cat: "المطاعم والكافيهات", sub: "ترفيه وسينما" },
        { keys: ["amc", "اي ام سي"], name: "AMC سينما", cat: "المطاعم والكافيهات", sub: "ترفيه وسينما" },
        { keys: ["muvi", "موفي"], name: "موفي سينما", cat: "المطاعم والكافيهات", sub: "ترفيه وسينما" },
        { keys: ["empire", "امباير"], name: "إمباير سينما", cat: "المطاعم والكافيهات", sub: "ترفيه وسينما" },
        { keys: ["alhokair", "الحكير"], name: "مجموعة الحكير للترفيه", cat: "المطاعم والكافيهات", sub: "ترفيه" },
        { keys: ["webook", "ويبوك"], name: "ويبوك (تذاكر)", cat: "المطاعم والكافيهات", sub: "تذاكر فعاليات" },
        { keys: ["flynas", "ناس", "طيران ناس"], name: "طيران ناس", cat: "السيارة والمواصلات", sub: "سفر وطيران" },
        { keys: ["flyadeal", "اديل", "طيران اديل"], name: "طيران أديل", cat: "السيارة والمواصلات", sub: "سفر وطيران" },
        { keys: ["saudia", "الخطوط السعودية", "saudi airlines"], name: "الخطوط السعودية", cat: "السيارة والمواصلات", sub: "سفر وطيران" },
        { keys: ["almosafer", "المسافر"], name: "المسافر", cat: "السيارة والمواصلات", sub: "حجوزات وسفر" },
        { keys: ["seera", "سيرا"], name: "مجموعة سيرا", cat: "السيارة والمواصلات", sub: "حجوزات وسفر" },
        { keys: ["agoda", "اجودا", "أجودا"], name: "أجودا", cat: "السيارة والمواصلات", sub: "حجوزات فنادق" },
        { keys: ["booking", "بوكينج", "بوكينق"], name: "Booking.com", cat: "السيارة والمواصلات", sub: "حجوزات فنادق" }
    ];

    function findMerchantInDictionary(text) {
        const cleanText = text.toLowerCase();

        for (let merchant of merchantsDictionary) {
            for (let key of merchant.keys) {
                const keyLower = key.toLowerCase();
                // بحث دقيق: الكلمة يجب أن تكون موجودة كما هي بدون قص عشوائي
                if (cleanText.includes(keyLower)) {
                    return merchant;
                }
            }
        }
        return null;
    }

    // البحث في القاموس المحلي
    const localMerchant = findMerchantInDictionary(rawText);
    if (localMerchant) {
        description = localMerchant.name;
        category = localMerchant.cat;
        subCategory = localMerchant.sub;
        isRecurring = localMerchant.recurring || false;
        needsAI = false;
        console.log(`📖 [Local Dictionary]: ✅ Merchant found (${description}) - No AI needed.`);
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
    // 🤖 نظام التصويت بين عدة موديلات (Voting System)
    // =========================================
    if (needsAI && !isIncome) {
        console.log('🤖 [AI Voting System]: لم يتم العثور على المتجر في القاموس المحلي، جاري تفعيل نظام التصويت...');

        try {
            const Groq = require('groq-sdk');
            const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

            const allowedCategories = ["المطاعم والكافيهات", "المنزل والمقاضي", "التسوق", "الصحة والجمال", "السيارة والمواصلات", "فواتير واشتراكات", "مصروفات عامة"];

            // تعريف الموديلات المستخدمة في التصويت
            const models = [
                { name: 'llama-3.3-70b-versatile', temperature: 0.1, weight: 1 },
                { name: 'llama-3.1-8b-instant', temperature: 0.1, weight: 1 },  // بديل سريع
                { name: 'qwen-qwq-32b', temperature: 0.1, weight: 1 }  // لا يزال نشطاً
            ];

            // البرومبت الموحد لجميع الموديلات
            const basePrompt = `أنت خبير مالي متخصص في تحليل الرسائل البنكية السعودية.
            
الرسالة: "${rawText}"

المهمة:
استخرج اسم المتجر (CleanName) وصنفه إلى Category و SubCategory مناسبة.

قواعد صارمة:
1. لا تترجم الأسماء الإنجليزية إلى العربية أبداً (مثال: "Joil" تبقى "Joil" وليس "جويل")
2. نظف البيانات من أرقام الفروع وأكواد نقاط البيع (مثال: "Joil 1515" -> "Joil")
3. استنتج التصنيف من سياق الاسم. إذا كان الاسم يحتوي على "Oil" أو "Fuel" فتصنيفه "السيارة والمواصلات"
4. إذا كان الاسم غامضاً تماماً ولا توجد دلائل واضحة، لا تفترض أنه مطعم. استخدم "مصروفات عامة" كتصنيف آمن
5. اختر التصنيف الرئيسي بالضبط من هذه القائمة: ${JSON.stringify(allowedCategories)}
6. التصنيف الفرعي يجب أن يكون منطقياً بالعربية

أجب فقط بصيغة JSON صالحة:
{
  "CleanName": "اسم المتجر بعد التنظيف",
  "Category": "التصنيف الرئيسي",
  "SubCategory": "التصنيف الفرعي"
}`;

            // دالة استدعاء موديل معين
            async function callModel(modelConfig) {
                try {
                    const completion = await groq.chat.completions.create({
                        messages: [{ role: 'user', content: basePrompt }],
                        model: modelConfig.name,
                        temperature: modelConfig.temperature,
                        response_format: { type: 'json_object' }
                    });

                    const text = completion.choices[0].message.content.trim();
                    return JSON.parse(text);
                } catch (error) {
                    console.log(`⚠️ [Model ${modelConfig.name}]: Failed - ${error.message}`);
                    return null;
                }
            }

            // استدعاء جميع الموديلات بالتوازي
            console.log('🔄 [AI Voting]: استدعاء الموديلات...');
            const results = await Promise.all(models.map(model => callModel(model)));

            // تصفية النتائج الناجحة
            const validResults = results.filter(r => r !== null && r.CleanName && r.Category);

            if (validResults.length > 0) {
                console.log(`✅ [AI Voting]: تم استلام ${validResults.length} نتائج من أصل ${models.length}`);

                // نظام التصويت المرجح
                const votes = {
                    names: {},
                    categories: {},
                    subCategories: {}
                };

                validResults.forEach((result, index) => {
                    const weight = models[index].weight;

                    // تسجيل الأصوات للاسم
                    votes.names[result.CleanName] = (votes.names[result.CleanName] || 0) + weight;

                    // تسجيل الأصوات للتصنيف
                    votes.categories[result.Category] = (votes.categories[result.Category] || 0) + weight;

                    // تسجيل الأصوات للتصنيف الفرعي
                    votes.subCategories[result.SubCategory] = (votes.subCategories[result.SubCategory] || 0) + weight;
                });

                // اختيار الفائزين
                const winningName = Object.keys(votes.names).reduce((a, b) => votes.names[a] > votes.names[b] ? a : b);
                const winningCategory = Object.keys(votes.categories).reduce((a, b) => votes.categories[a] > votes.categories[b] ? a : b);
                const winningSubCategory = Object.keys(votes.subCategories).reduce((a, b) => votes.subCategories[a] > votes.subCategories[b] ? a : b);

                // التحقق من الاتساق - إذا كان الفائز بالتصنيف "مطاعم" ولكن الاسم يحتوي على "oil" أو "fuel"
                const nameLower = winningName.toLowerCase();
                if (winningCategory === "المطاعم والكافيهات" &&
                    (nameLower.includes('oil') || nameLower.includes('fuel') || nameLower.includes('petrol'))) {
                    console.log('⚠️ [AI Voting]: تنبيه - تم اكتشاف عدم اتساق! تصنيف مطاعم لاسم يحتوي على كلمات وقود.');
                    console.log('🔄 [AI Voting]: تجاوز التصويت واستخدام التصنيف الافتراضي "السيارة والمواصلات"');

                    description = winningName;
                    category = "السيارة والمواصلات";
                    subCategory = "محطات وقود";
                } else {
                    description = winningName;
                    category = winningCategory;
                    subCategory = winningSubCategory;
                }

                console.log('📊 [AI Voting - Results]:', {
                    votes: votes,
                    winner: { name: winningName, category: winningCategory, subCategory: winningSubCategory }
                });

                // إضافة المتجر الجديد للقاموس المحلي مؤقتاً (في الذاكرة)
                // يمكن تخزينه في قاعدة بيانات لاحقاً
                if (!localMerchant) {
                    // إضافة للمصفوفة مؤقتاً للاستخدام المستقبلي في نفس الجلسة
                    merchantsDictionary.push({
                        keys: [description.toLowerCase()],
                        name: description,
                        cat: category,
                        sub: subCategory,
                        recurring: false
                    });
                    console.log(`💾 [AI Voting]: تم إضافة "${description}" إلى القاموس المحلي مؤقتاً.`);
                }

            } else {
                throw new Error('لم تنجح أي من الموديلات في التصنيف');
            }

        } catch (error) {
            console.error("❌ [AI Voting - Error]:", error.message);

            // خطة بديلة متعددة المستويات
            let fallbackSuccess = false;

            // المستوى 1: محاولة استخراج الاسم من النص
            const nameMatch = rawText.match(/لـ\s*([A-Za-z\u0600-\u06FF\s]+)(?:\n|\r|؜|بـ|عبر)/i) ||
                rawText.match(/في\s*([A-Za-z\u0600-\u06FF\s]+)(?:\n|\r|؜)/i) ||
                rawText.match(/([A-Za-z\u0600-\u06FF]{3,})\s*\d{4,}/i);

            if (nameMatch && nameMatch[1].trim().length > 2) {
                description = nameMatch[1].trim();
                fallbackSuccess = true;
                console.log(`⚠️ [Fallback Level 1]: تم استخراج الاسم من النص (${description}).`);
            }

            // المستوى 2: البحث عن كلمات مفتاحية في النص
            if (!fallbackSuccess) {
                if (rawText.includes("بنزين") || rawText.includes("محطة")) {
                    description = "محطة وقود";
                    category = "السيارة والمواصلات";
                    subCategory = "بنزين";
                    fallbackSuccess = true;
                    console.log(`⚠️ [Fallback Level 2]: تم التصنيف بناءً على كلمات مفتاحية (${description}).`);
                } else if (rawText.includes("مطعم") || rawText.includes("كافي")) {
                    description = "مطعم";
                    category = "المطاعم والكافيهات";
                    subCategory = "مطاعم";
                    fallbackSuccess = true;
                    console.log(`⚠️ [Fallback Level 2]: تم التصنيف بناءً على كلمات مفتاحية (${description}).`);
                }
            }

            // المستوى 3: استخدام أول كلمة إنجليزية أو عربية طويلة
            if (!fallbackSuccess) {
                const words = rawText.split(/[\s\n\r]+/);
                for (let word of words) {
                    if (word.length > 3 && !word.match(/^\d+$/)) {
                        description = word;
                        fallbackSuccess = true;
                        console.log(`⚠️ [Fallback Level 3]: تم استخدام أول كلمة ذات معنى (${description}).`);
                        break;
                    }
                }
            }

            if (!fallbackSuccess) {
                console.log(`⚠️ [Fallback Level 4]: استخدام الاسم الافتراضي.`);
            }
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
        if (type === 'income') {
            processAutoSavings(userId, amount);
        }
        res.json({ success: true, id: result.insertId });
    });
});

// دالة استخراج التاريخ (احتفظ بالدالة الموجودة كما هي)
function extractTransactionDate(rawText) {
    // ... الكود الموجود لديك لاستخراج التاريخ
    return null; // عدل هذا حسب الدالة الموجودة لديك
}

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

// AI Advisor Route
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
            /* // ⛔ تم تعليق كود Gemini مؤقتاً
            const { GoogleGenAI } = require('@google/genai');
            const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
            const response = await ai.models.generateContent({
                model: "gemini-3-flash-preview",
                contents: prompt,
            });
            res.json({ advice: response.text.trim() });
            */

            // ✅ تفعيل محرك Groq للحصول على نصيحة سريعة
            console.log('\n🤖 [Groq Advisor]: جاري طلب النصيحة المالية من Groq...');

            const Groq = require('groq-sdk');
            const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

            const chatCompletion = await groq.chat.completions.create({
                messages: [{ role: 'user', content: prompt }],
                model: 'llama-3.3-70b-versatile',
                temperature: 0.7, // إعطاء مساحة للإبداع في النصيحة
            });

            const aiAdvice = chatCompletion.choices[0].message.content.trim();
            console.log('✅ [Groq Advisor - نجاح]: تم توليد النصيحة بنجاح.');

            res.json({ advice: aiAdvice });

        } catch (error) {
            console.error('❌ [Groq Advisor - خطأ]:', error);
            res.status(500).json({ error: `خطأ من الخادم: ${error.message}` });
        }
    });
});

// ==========================================
// 💬 المساعد المالي الذكي (Chatbot)
// ==========================================
app.post('/api/chat', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const { message } = req.body;

    if (!message) return res.status(400).json({ error: 'الرسالة مطلوبة' });

    try {
        // 1. تجميع بيانات المستخدم لإنشاء "الوعي المالي" للبوت
        const currentMonth = new Date().getMonth() + 1;
        const currentYear = new Date().getFullYear();

        // جلب العمليات، الميزانيات، الأهداف، والذهب
        const allTransactions = await queryAsync('SELECT * FROM Transactions WHERE UserId = ?', [userId]);
        const budgets = await queryAsync('SELECT * FROM Budgets WHERE UserId = ?', [userId]);
        const goals = await queryAsync('SELECT * FROM SavingsGoals WHERE UserId = ?', [userId]);
        const goldAssets = await queryAsync('SELECT * FROM Assets WHERE UserId = ? AND AssetType = "Gold"', [userId]);

        // حساب الرصيد الكلي ومصروفات الشهر الحالي حسب التصنيف
        let totalBalance = 0;
        let currentMonthExpense = 0;
        const expensesByCategory = {};

        allTransactions.forEach(t => {
            const amt = Number(t.Amount);
            const tDate = new Date(t.TransactionDate);
            
            if (t.Type === 'income') totalBalance += amt;
            else if (t.Type === 'expense') {
                totalBalance -= amt;
                // إذا كانت العملية في هذا الشهر، أضفها لتفاصيل المصروفات
                if (tDate.getMonth() + 1 === currentMonth && tDate.getFullYear() === currentYear) {
                    currentMonthExpense += amt;
                    expensesByCategory[t.Category] = (expensesByCategory[t.Category] || 0) + amt;
                }
            }
        });

        // حساب وزن الذهب الكلي
        let totalGoldGrams = 0;
        goldAssets.forEach(g => {
            totalGoldGrams += parseFloat(g.WeightInOunces) || 0;
        });

        // 2. صياغة السياق المالي (البيانات التي سيفهمها البوت)
        const financialContext = `
        معلومات المستخدم المالية الحالية:
        - الرصيد الإجمالي المتاح في المحفظة: ${totalBalance.toFixed(2)} ريال.
        - إجمالي ما تم صرفه هذا الشهر: ${currentMonthExpense.toFixed(2)} ريال.
        - تفصيل ما تم صرفه هذا الشهر حسب الأقسام: ${JSON.stringify(expensesByCategory)}.
        - ميزانيات المستخدم (الحد الأقصى للصرف لكل قسم): ${JSON.stringify(budgets.map(b => ({ القسم: b.Category, الحد: b.AmountLimit }))) }.
        - أهداف المستخدم للادخار: ${JSON.stringify(goals.map(g => ({ الهدف: g.GoalName, المستهدف: g.TargetAmount, المجمع_حاليا: g.CurrentAmount }))) }.
        - الأصول: يمتلك المستخدم ${totalGoldGrams.toFixed(2)} جرام من الذهب.
        `;

        // 3. صياغة القواعد الصارمة (System Prompt)
        const systemPrompt = `أنت مساعد مالي ذكي وخبير داخل تطبيق سعودي لإدارة المصاريف الشخصية.
        
        القواعد الصارمة جداً:
        1. الإطار المالي فقط: يجب أن تنحصر إجاباتك في الإدارة المالية، الميزانية، الإدخار، والمصاريف. إذا سألك المستخدم عن (الطقس، التاريخ، السياسة، البرمجة، معلومات عامة، أو أي شيء خارج المال)، يجب أن تعتذر بلباقة وتقول: "عذراً، أنا مبرمج حصرياً كمستشار مالي لمساعدتك في ميزانيتك ومصاريفك فقط."
        2. الإجابة المبنية على البيانات: إذا سألك "هل أستطيع شراء كذا بقيمة كذا؟"، يجب أن تقارن القيمة برصيده الإجمالي، وتتحقق من ميزانيته لهذا الشهر. أعطه نصيحة واقعية (مثلاً: نعم تستطيع، لكنك ستتجاوز ميزانية التسوق، أو لا أنصحك لأن رصيدك لا يكفي).
        3. تحدث باللغة العربية، بأسلوب ودي واحترافي، وتجنب ذكر الأرقام كأكواد برمجية، بل اكتبها كأرقام عادية.
        4. كن مختصراً في إجابتك ولا تكتب فقرات طويلة جداً.
        
        ${financialContext}
        `;

        // 4. الاتصال بمحرك Groq
        const Groq = require('groq-sdk');
        const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

        const chatCompletion = await groq.chat.completions.create({
            messages: [
                { role: 'system', content: systemPrompt },
                { role: 'user', content: message }
            ],
            model: 'llama-3.3-70b-versatile',
            temperature: 0.3, // رقم منخفض ليجعله دقيقاً وملتزماً بالقواعد
        });

        const reply = chatCompletion.choices[0].message.content.trim();
        res.json({ reply });

    } catch (error) {
        console.error('❌ Chatbot Error:', error);
        res.status(500).json({ error: 'حدث خطأ في معالجة رسالتك' });
    }
});

// ==========================================
// 📧 نظام إرسال التقارير التلقائي (المسار التجريبي)
// ==========================================

const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    tls: {
        rejectUnauthorized: false
    },
    family: 4 // 👈 هذا السطر السحري يجبر السيرفر على استخدام IPv4 بدلاً من IPv6
});

// ==========================================
// 📧 نظام إرسال التقارير التلقائي (عبر واجهة Resend)
// ==========================================

app.get('/api/test-email-report', async (req, res) => {
    const targetEmail = req.query.email;

    if (!targetEmail) {
        return res.status(400).send('<h2 dir="rtl" style="font-family: sans-serif; text-align: center; color: red;">❌ الرجاء تمرير الإيميل في الرابط</h2>');
    }

    try {
        console.log(`⏳ جاري تجهيز التقرير لإرساله إلى: ${targetEmail}...`);

        const htmlContent = `
            <!DOCTYPE html>
            <html dir="rtl" lang="ar">
                <body style="font-family: Arial, sans-serif; text-align: center; padding: 40px; background-color: #f3f4f6;">
                    <div style="background: white; padding: 30px; border-radius: 12px; max-width: 600px; margin: auto; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
                        <h1 style="color: #1e3a8a;">تقرير مالي تجريبي 🚀</h1>
                        <p style="color: #4b5563; font-size: 16px;">مرحباً! هذا التقرير تم توليده تلقائياً من الخادم عبر API.</p>
                        <div style="background: #10b981; color: white; padding: 20px; border-radius: 8px; margin-top: 30px;">
                            <h3 style="margin: 0 0 10px 0;">الرصيد المتاح (عينة)</h3>
                            <h2 style="margin: 0; font-size: 32px;">SAR 5,430.00</h2>
                        </div>
                    </div>
                </body>
            </html>
        `;

        let options = { format: 'A4', printBackground: true };
        let file = { content: htmlContent };

        console.log('📄 جاري توليد ملف PDF في الذاكرة...');
        const pdfBuffer = await html_to_pdf.generatePdf(file, options);

        console.log('📧 جاري إرسال الإيميل عبر Resend...');

        // استخدام Resend لإرسال الإيميل مع المرفق
        const { data, error } = await resend.emails.send({
            from: 'Finance App <onboarding@resend.dev>', // إيميل الاختبار الافتراضي من Resend
            to: targetEmail,
            subject: '📊 تقريرك المالي الشامل',
            html: '<p dir="rtl">مرحباً، تجد في المرفقات التقرير المالي الشامل الخاص بك بصيغة PDF.</p>',
            attachments: [
                {
                    filename: 'Financial_Report.pdf',
                    content: pdfBuffer, // نمرر الـ Buffer مباشرة
                }
            ]
        });

        if (error) {
            console.error('❌ خطأ من خدمة Resend:', error);
            return res.status(500).send(`<h2 dir="rtl" style="font-family: sans-serif; text-align: center; color: red;">❌ خطأ في الإرسال: ${error.message}</h2>`);
        }

        console.log('✅ تم الإرسال بنجاح! رقم العملية:', data.id);
        res.send(`<h2 dir="rtl" style="font-family: sans-serif; text-align: center; color: green;">✅ تم توليد الـ PDF وإرساله بنجاح إلى: <br><br> ${targetEmail}</h2>`);

    } catch (error) {
        console.error('❌ خطأ داخلي:', error);
        res.status(500).send(`<h2 dir="rtl" style="font-family: sans-serif; text-align: center; color: red;">❌ حدث خطأ: ${error.message}</h2>`);
    }
});

// Dynamic Port
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`🚀 Server is now running on port: ${PORT}`);
});