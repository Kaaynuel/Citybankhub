const express = require('express');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key-city-bank';

app.use(cors());
app.use(express.json());

// ==========================================================================
// AUTHENTICATION MIDDLEWARE
// ==========================================================================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// ==========================================================================
// AUTH ROUTES
// ==========================================================================

// Register New User & Account
app.post('/api/auth/register', async (req, res) => {
  const { username, fullName, pin } = req.body;

  try {
    const existingUser = await prisma.user.findUnique({ where: { username } });
    if (existingUser) return res.status(400).json({ error: 'Username taken' });

    const pinHash = await bcrypt.hash(pin, 10);
    const randomAccountNo = Math.floor(1000000000 + Math.random() * 9000000000).toString();

    const user = await prisma.user.create({
      data: {
        username,
        fullName,
        pinHash,
        accounts: {
          create: {
            accountNumber: randomAccountNo,
            balance: 1000.00 // $1,000 Welcome Bonus
          }
        }
      },
      include: { accounts: true }
    });

    const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '2h' });
    res.status(201).json({ token, user: { name: user.fullName, account: user.accounts[0] } });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create user' });
  }
});

// Login User
app.post('/api/auth/login', async (req, res) => {
  const { username, pin } = req.body;

  try {
    const user = await prisma.user.findUnique({
      where: { username },
      include: { accounts: true }
    });

    if (!user) return res.status(400).json({ error: 'Invalid user or PIN' });

    const validPin = await bcrypt.compare(pin, user.pinHash);
    if (!validPin) return res.status(400).json({ error: 'Invalid user or PIN' });

    const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '2h' });
    res.json({ token, user: { name: user.fullName, account: user.accounts[0] } });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// ==========================================================================
// BANKING API ROUTES (PROTECTED)
// ==========================================================================

// Get Dashboard Data
app.get('/api/dashboard', authenticateToken, async (req, res) => {
  try {
    const account = await prisma.account.findFirst({
      where: { userId: req.user.userId }
    });

    const transactions = await prisma.transaction.findMany({
      where: {
        OR: [
          { senderAccountId: account.id },
          { recipientAccountId: account.id }
        ]
      },
      orderBy: { createdAt: 'desc' },
      take: 20
    });

    res.json({ account, transactions });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  }
});

// Atomic Transfer Funds Route (ACID Compliant)
app.post('/api/transfer', authenticateToken, async (req, res) => {
  const { recipientAccountNo, amount } = req.body;
  const transferAmount = parseFloat(amount);

  if (isNaN(transferAmount) || transferAmount <= 0) {
    return res.status(400).json({ error: 'Invalid transfer amount' });
  }

  try {
    // 1. Fetch Sender Account
    const senderAccount = await prisma.account.findFirst({
      where: { userId: req.user.userId }
    });

    if (senderAccount.balance < transferAmount) {
      return res.status(400).json({ error: 'Insufficient account balance' });
    }

    // 2. Fetch Recipient Account
    const recipientAccount = await prisma.account.findUnique({
      where: { accountNumber: recipientAccountNo }
    });

    if (!recipientAccount) {
      return res.status(404).json({ error: 'Recipient account not found' });
    }

    if (senderAccount.id === recipientAccount.id) {
      return res.status(400).json({ error: 'Cannot transfer to same account' });
    }

    // 3. Execute DB Transaction (All or Nothing)
    const [updatedSender, updatedRecipient, transactionLog] = await prisma.$transaction([
      // Deduct from Sender
      prisma.account.update({
        where: { id: senderAccount.id },
        data: { balance: { decrement: transferAmount } }
      }),
      // Add to Recipient
      prisma.account.update({
        where: { id: recipientAccount.id },
        data: { balance: { increment: transferAmount } }
      }),
      // Create Transaction Record
      prisma.transaction.create({
        data: {
          amount: transferAmount,
          type: 'TRANSFER',
          senderAccountId: senderAccount.id,
          recipientAccountId: recipientAccount.id
        }
      })
    ]);

    res.json({
      message: 'Transfer successful',
      newBalance: updatedSender.balance,
      transaction: transactionLog
    });
  } catch (err) {
    res.status(500).json({ error: 'Transaction failed to complete' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`City Bank Server running on port ${PORT}`));
                                                # This workflow will do a clean installation of node dependencies, cache/restore them, build the source code and run tests across different versions of node
# For more information see: https://docs.github.com/en/actions/automating-builds-and-tests/building-and-testing-nodejs

name: Node.js CI

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  build:

    runs-on: ubuntu-latest

    strategy:
      matrix:
        node-version: [18.x, 20.x, 22.x]
        # See supported Node.js release schedule at https://nodejs.org/en/about/releases/

    steps:
    - uses: actions/checkout@v4
    - name: Use Node.js ${{ matrix.node-version }}
      uses: actions/setup-node@v4
      with:
        node-version: ${{ matrix.node-version }}
        cache: 'npm'
    - run: npm ci
    - run: npm run build --if-present
    - run: npm test
