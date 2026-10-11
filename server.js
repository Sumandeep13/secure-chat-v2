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

// MongoDB Database Schemas
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

// In-memory socket session registry
const activeSockets = {}; 

// Authentication Endpoints
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).json({ error: "Username already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: "Registration successful" });
  } catch (err) {
    res.status(500).json({ error: "Server registration error" });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

    res.json({ username: user.username });
  } catch (err) {
    res.status(500).json({ error: "Server authentication error" });
  }
});

// Real-Time Socket Routing & Message Archiving
io.on('connection', (socket) => {
  socket.on('register_user', async ({ username, publicKey }) => {
    activeSockets[username] = socket.id;
    await User.findOneAndUpdate({ username }, { publicKey });
    
    // Broadcast active directory list with public keys
    const allUsers = await User.find({}, 'username publicKey');
    const userMap = {};
    allUsers.forEach(u => { if(u.publicKey) userMap[u.username] = u.publicKey; });
    
    io.emit('update_user_list', userMap);
  });

  socket.on('send_encrypted_message', async (data) => {
    // Store encrypted ciphertext payload in DB (Zero-Knowledge)
    const msg = new Message(data);
    await msg.save();

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

// Connect DB & Start Server
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/securechat';

mongoose.connect(MONGO_URI)
  .then(() => {
    server.listen(PORT, () => {
      console.log(`\n==================================================`);
      console.log(`🚀 Production Server running on port ${PORT}`);
      console.log(`==================================================\n`);
    });
  })
  .catch(err => console.error("Database connection failure:", err));