// backend/server.js
import express from 'express';
import cors from 'cors';
import http from 'http';
import { WebSocketServer } from 'ws';

import mongoose from 'mongoose';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

import User from './models/User.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// ================= DATABASE =================
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// ================= MIDDLEWARE =================
app.use(cors({
  origin: 'https://reactfront-production-101d.up.railway.app',
  credentials: true
}));
app.use(express.json());

// ================= AUTH: REGISTER =================
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, plantId } = req.body;

    if (!email || !password || !name || !plantId) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required'
      });
    }

    const exists = await User.findOne({ email });
    if (exists) {
      return res.status(409).json({
        success: false,
        message: 'User already exists'
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      email,
      password: hashedPassword,
      name,
      plantId
    });

    const token = jwt.sign(
      { id: user._id, plantId: user.plantId },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        plantId: user.plantId
      },
      token
    });
  } catch (err) {
    console.error('❌ Register error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ================= AUTH: LOGIN =================
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password required'
      });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    const token = jwt.sign(
      { id: user._id, plantId: user.plantId },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        plantId: user.plantId
      },
      token
    });
  } catch (err) {
    console.error('❌ Login error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ================= AUTH: VERIFY =================
app.get('/api/auth/verify', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ success: false });
  }

  try {
    jwt.verify(token, process.env.JWT_SECRET);
    res.json({ success: true });
  } catch {
    res.status(401).json({ success: false });
  }
});
// ================= REGISTER =================
app.post('/api/auth/register', (req, res) => {
  const { email, password, name, plantId } = req.body;

  if (!email || !password || !name || !plantId) {
    return res.status(400).json({
      success: false,
      message: 'All fields are required'
    });
  }

  const exists = users.find(u => u.email === email);
  if (exists) {
    return res.status(409).json({
      success: false,
      message: 'User already exists'
    });
  }

  const newUser = {
    id: users.length + 1,
    email,
    password, // ⚠️ plain for now (OK for demo)
    name,
    plantId
  };

  users.push(newUser);

  const { password: _, ...safeUser } = newUser;

  res.json({
    success: true,
    user: safeUser,
    token: `token_${newUser.id}_${Date.now()}`
  });
});

// ================= HTTP SERVER =================
const server = http.createServer(app);

// ================= WEBSOCKET SERVER =================
const wss = new WebSocketServer({ server });

// plantId -> ws
const agents = new Map();

wss.on('connection', (ws) => {
  console.log('🔌 Agent connected');

  ws.on('message', (msg) => {
    try {
      const data = JSON.parse(msg.toString());

      if (data.type === 'REGISTER_AGENT') {
        ws.plantId = data.plantId;
        agents.set(data.plantId, ws);
        console.log(`✅ Agent registered: ${data.plantId}`);
      }

      if (data.type === 'QUERY_RESPONSE') {
        ws.lastResponse = data.payload;
      }

      if (data.type === 'LIVE_DATA') {
        ws.lastLive = data.payload;
      }
    } catch (err) {
      console.error('❌ WS error:', err.message);
    }
  });

  ws.on('close', () => {
    if (ws.plantId) {
      agents.delete(ws.plantId);
      console.log(`❌ Agent disconnected: ${ws.plantId}`);
    }
  });
});

// ================= QUESTDB QUERY VIA AGENT =================
app.get('/api/questdb/query', async (req, res) => {
  const { sql, plantId } = req.query;

  if (!sql || !plantId) {
    return res.status(400).json({
      error: 'sql and plantId required'
    });
  }

  const agent = agents.get(plantId);
  if (!agent) {
    return res.status(503).json({
      error: `Agent for ${plantId} is offline`,
      columns: [],
      dataset: []
    });
  }

  agent.send(JSON.stringify({
    type: 'EXEC_QUERY',
    sql
  }));

  await new Promise(resolve => setTimeout(resolve, 500));
  res.json(agent.lastResponse || { columns: [], dataset: [] });
});

// ================= HEALTH =================
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    agents: [...agents.keys()],
    time: new Date().toISOString()
  });
});

// ================= START =================
server.listen(PORT, () => {
  console.log(`🚀 Backend running on http://localhost:${PORT}`);
  console.log(`🔌 WebSocket active on same port`);

});
