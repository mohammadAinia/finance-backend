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

// Dynamic Port for Cloud Deployment
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server is now running on port: ${PORT}`);
});