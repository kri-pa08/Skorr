// ============================================================
//  SKORR BACKEND — index.js
//  Yeh file run karo: node index.js
//  Sab kuch yahan se start hota hai
// ============================================================

const express    = require('express')
const bcrypt     = require('bcryptjs')
const jwt        = require('jsonwebtoken')
const cors       = require('cors')
require('dotenv').config()

const app  = express()
const PORT = process.env.PORT || 3001

// ── Middleware ──────────────────────────────────────────────
app.use(cors())           // Frontend ko backend se baat karne deta hai
app.use(express.json())   // JSON data samajhta hai

// ── Simple in-memory store (Supabase se pehle test ke liye) ─
// Jab Supabase add karoge tab yeh hata dena
const users = []

// ── JWT Helper ──────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'skorr-secret-key-change-in-production'

function makeToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' })
}

function verifyToken(req, res, next) {
  const header = req.headers.authorization
  if (!header) return res.status(401).json({ error: 'Login' })

  const token = header.split(' ')[1]
  try {
    const decoded = jwt.verify(token, JWT_SECRET)
    req.userId = decoded.userId
    next()
  } catch {
    return res.status(401).json({ error: 'Invalid Token please try again' })
  }
}

// ============================================================
//  SIGNUP ROUTE
//  POST /api/auth/signup
//  Naya user register karta hai
// ============================================================
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, phone, password, shopName, city, shopType } = req.body

    
    if (!firstName || !email || !phone || !password || !shopName) {
      return res.status(400).json({
        error: 'Fill every important field — name, email, phone, password, shop name'
      })
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: 'Password should be minimum of 8 characters'
      })
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Enter correct email' })
    }

    // ── DUPLICATE EMAIL CHECK ────────────────────────────────
    // Yeh woh part hai jo same email se dobara signup rok ta hai
    const emailExists = users.find(u => u.email === email.toLowerCase())
    if (emailExists) {
      return res.status(400).json({
        error: 'This email is already in use please sign in'
        // Yahi message signup form mein dikhega
      })
    }

    // ── DUPLICATE PHONE CHECK ────────────────────────────────
    const phoneExists = users.find(u => u.phone === phone)
    if (phoneExists) {
      return res.status(400).json({
        error: 'This whatsapp number is already in use'
      })
    }

    // ── Password hash karo (kabhi bhi plain text save mat karo) ─
    const passwordHash = await bcrypt.hash(password, 10)

    // ── User banao ───────────────────────────────────────────
    const newUser = {
      id: 'user_' + Date.now(),         // Real DB mein UUID hoga
      firstName,
      lastName,
      name: firstName + ' ' + lastName,
      email: email.toLowerCase(),
      phone,
      passwordHash,
      shopName,
      city: city || '',
      shopType: shopType || 'retail',
      plan: 'trial',
      trialStarted: new Date(),
      createdAt: new Date()
    }

    users.push(newUser)  // Real DB mein: prisma.users.create()

    // ── Token banao ──────────────────────────────────────────
    const token = makeToken(newUser.id)

    console.log(`✅ New user: ${newUser.name} (${newUser.email}) — ${newUser.shopName}`)

    // ── Response bhejo ───────────────────────────────────────
    res.status(201).json({
      message: 'Your account has been created, Welcome to the Skorr family ',
      token,
      user: {
        id:       newUser.id,
        name:     newUser.name,
        email:    newUser.email,
        shopName: newUser.shopName,
        city:     newUser.city,
        plan:     newUser.plan
      }
    })

  } catch (err) {
    console.error('Signup error:', err)
    res.status(500).json({ error: 'Something wrong in the server please try agian' })
  }
})

// ============================================================
//  LOGIN ROUTE
//  POST /api/auth/login
//  Purana user login karta hai
// ============================================================
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password both are needed' })
    }

    // ── User dhundo ──────────────────────────────────────────
    const user = users.find(u => u.email === email.toLowerCase())

    // Note: "User nahi mila" aur "Wrong password" ka alag alag
    // message nahi dena chahiye security ke liye — ek hi message do
    if (!user) {
      return res.status(401).json({
        error: 'Email or password is wrong'
      })
    }

    // ── Password check karo ──────────────────────────────────
    const passwordMatch = await bcrypt.compare(password, user.passwordHash)
    if (!passwordMatch) {
      return res.status(401).json({
        error: 'Email or password is wrong'
      })
    }

    // ── Token banao ──────────────────────────────────────────
    const token = makeToken(user.id)

    console.log(`🔐 Login: ${user.name} (${user.shopName})`)

    res.json({
      message: `Welcome back, ${user.firstName}!`,
      token,
      user: {
        id:       user.id,
        name:     user.name,
        email:    user.email,
        shopName: user.shopName,
        city:     user.city,
        plan:     user.plan
      }
    })

  } catch (err) {
    console.error('Login error:', err)
    res.status(500).json({ error: 'There is somethingwrong in the server please try again' })
  }
})

// ============================================================
//  ME ROUTE — "Kaun hoon main?"
//  GET /api/auth/me
//  Token se user ka data nikalata hai
//  Dashboard yahi use karta hai apna data load karne ke liye
// ============================================================
app.get('/api/auth/me', verifyToken, (req, res) => {
  const user = users.find(u => u.id === req.userId)

  if (!user) {
    return res.status(404).json({ error: 'User not found' })
  }

  res.json({
    user: {
      id:        user.id,
      name:      user.name,
      firstName: user.firstName,
      email:     user.email,
      shopName:  user.shopName,
      city:      user.city,
      plan:      user.plan,
      createdAt: user.createdAt
    }
  })
})

// ============================================================
//  DASHBOARD DATA ROUTE
//  GET /api/dashboard
//  Yeh woh data hai jo dashboard pe dikhta hai
//  Sirf logged-in user ka data milega — dusre ka nahi
// ============================================================
app.get('/api/dashboard', verifyToken, (req, res) => {
  const user = users.find(u => u.id === req.userId)

  if (!user) return res.status(404).json({ error: 'User not found' })

  // Real app mein yahan database se actual products,
  // sales, margins sab nikalenge
  // Abhi empty data de rahe hain — naye user ka dashboard yahi hoga

  res.json({
    user: {
      name:     user.name,
      shopName: user.shopName,
      plan:     user.plan
    },
    stats: {
      totalProducts:  0,   // Naya user = 0 products
      totalSuppliers: 0,
      todaySales:     0,
      avgMargin:      0
    },
    alerts:    [],         // Koi alert nahi abhi
    recentSales: [],       // Koi sale nahi abhi
    topProducts: [],       // Koi product nahi abhi
    isNewUser: true        // Dashboard "add first product" screen dikhayega
  })
})

// ============================================================
//  TEST ROUTE — check karo server chal raha hai ya nahi
//  GET /
// ============================================================
app.get('/', (req, res) => {
  res.json({
    message: '🚀 Skorr Backend working',
    version: '1.0.0',
    endpoints: {
      signup:    'POST /api/auth/signup',
      login:     'POST /api/auth/login',
      me:        'GET  /api/auth/me',
      dashboard: 'GET  /api/dashboard'
    }
  })
})

// ── Server start ho gya isse thike ───────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
  ╔═══════════════════════════════════╗
  ║   Skorr Backend Running!       ║
  ║   Port: ${PORT}                      ║
  ║   URL:  http://localhost:${PORT}     ║
  ╚═══════════════════════════════════╝
  `)
})