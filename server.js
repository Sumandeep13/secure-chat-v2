require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// MongoDB Schemas
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  publicKey: { type: String, default: "" },
  createdAt: { type: Date, default: Date.now }
});

const MessageSchema = new mongoose.Schema({
  sender: String,
  recipient: String,
  encryptedData: String,
  encryptedKey: String,
  iv: String,
  timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Message = mongoose.model('Message', MessageSchema);

// In-Memory Fallback Directories
const activeSockets = {};
const inMemoryUsers = {};

// Registration Endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (mongoose.connection.readyState === 1) {
      const existingUser = await User.findOne({ username });
      if (existingUser) return res.status(400).json({ error: "Username already exists" });

      const hashedPassword = await bcrypt.hash(password, 10);
      const user = new User({ username, password: hashedPassword });
      await user.save();
    } else {
      if (inMemoryUsers[username]) return res.status(400).json({ error: "Username already exists" });
      const hashedPassword = await bcrypt.hash(password, 10);
      inMemoryUsers[username] = { password: hashedPassword, publicKey: "" };
    }
    res.status(201).json({ message: "Registration successful" });
  } catch (err) {
    res.status(500).json({ error: "Server registration error" });
  }
});

// Login Endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    let storedHash = null;

    if (mongoose.connection.readyState === 1) {
      const user = await User.findOne({ username });
      if (user) storedHash = user.password;
    } else {
      if (inMemoryUsers[username]) storedHash = inMemoryUsers[username].password;
    }

    if (!storedHash) return res.status(400).json({ error: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, storedHash);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

    res.json({ username });
  } catch (err) {
    res.status(500).json({ error: "Server authentication error" });
  }
});

// Socket.IO Real-Time Messaging & Key Distribution
io.on('connection', (socket) => {
  socket.on('register_user', async ({ username, publicKey }) => {
    activeSockets[username] = socket.id;

    if (mongoose.connection.readyState === 1) {
      await User.findOneAndUpdate({ username }, { publicKey });
      const allUsers = await User.find({}, 'username publicKey');
      const userMap = {};
      allUsers.forEach(u => { if (u.publicKey) userMap[u.username] = u.publicKey; });
      io.emit('update_user_list', userMap);
    } else {
      if (!inMemoryUsers[username]) inMemoryUsers[username] = {};
      inMemoryUsers[username].publicKey = publicKey;

      const userMap = {};
      for (let u in inMemoryUsers) {
        if (inMemoryUsers[u].publicKey) userMap[u] = inMemoryUsers[u].publicKey;
      }
      io.emit('update_user_list', userMap);
    }
  });

  socket.on('send_encrypted_message', async (data) => {
    if (mongoose.connection.readyState === 1) {
      const msg = new Message(data);
      await msg.save();
    }

    const targetSocket = activeSockets[data.recipient];
    if (targetSocket) {
      io.to(targetSocket).emit('receive_encrypted_message', data);
    }
  });

  socket.on('disconnect', () => {
    for (let user in activeSockets) {
      if (activeSockets[user] === socket.id) {
        delete activeSockets[user];
        break;
      }
    }
  });
});

// Server Initialization
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;

async function startServer() {
  if (MONGO_URI && !MONGO_URI.includes('cluster0.mongodb.net')) {
    try {
      await mongoose.connect(MONGO_URI);
      console.log('MongoDB Connected Successfully');
    } catch (err) {
      console.warn('MongoDB connection failed, running in memory mode:', err.message);
    }
  } else {
    console.log('Running in memory mode without MongoDB cluster');
  }

  server.listen(PORT, () => {
    console.log(`\n==================================================`);
    console.log(`🚀 Production Server running on port ${PORT}`);
    console.log(`==================================================\n`);
  });
}

startServer();
