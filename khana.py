const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// --- Connect to MongoDB ---
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error("❌ MongoDB Error:", err.message));

// --- User Schema ---
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  balance: { type: Number, default: 0 }
});
const User = mongoose.model('User', userSchema);

// --- Auth Middleware ---
const protect = async (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ message: "No token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id);
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
};

// --- Routes ---

// Signup
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;
  const exists = await User.findOne({ email });
  if (exists) return res.status(400).json({ message: "Email already exists" });

  const hashed = await bcrypt.hash(password, 10);
  const user = new User({ name, email, password: hashed });
  await user.save();
  res.status(201).json({ message: "Signup successful" });
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ message: "User not found" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ message: "Wrong password" });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1d" });
  res.json({ token });
});

// Get Wallet Balance
app.get('/api/balance', protect, (req, res) => {
  res.json({ balance: req.user.balance });
});

// Add Money
app.post('/api/add', protect, async (req, res) => {
  const { amount } = req.body;
  req.user.balance += amount;
  await req.user.save();
  res.json({ message: `Added Rs. ${amount}`, balance: req.user.balance });
});

// Transfer Money
app.post('/api/transfer', protect, async (req, res) => {
  const { email, amount } = req.body;
  const receiver = await User.findOne({ email });
  if (!receiver) return res.status(404).json({ message: "Receiver not found" });

  if (req.user.balance < amount) {
    return res.status(400).json({ message: "Insufficient balance" });
  }

  req.user.balance -= amount;
  receiver.balance += amount;

  await req.user.save();
  await receiver.save();

  res.json({ message: "Transfer successful", balance: req.user.balance });
});

// --- Start Server ---
app.listen(process.env.PORT, () => {
  console.log(`🚀 Server running on port ${process.env.PORT}`);
});
