// backend/server.js
import express from 'express';
import cors from 'cors';
import http from 'http';
import { WebSocketServer } from 'ws';

const app = express();
const PORT = process.env.PORT || 3001;

// ================= MIDDLEWARE =================
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());

// ================= SIMPLE AUTH =================
const users = [
  { id: 1, email: 'admin@example.com', password: 'admin123', name: 'Admin', plantId: 'plantA' },
  { id: 2, email: 'user@example.com', password: 'user123', name: 'User', plantId: 'plantB' }
];

app.post('/api/auth/login', (req, res) => {
  console.log('Login attempt:', req.body);
  
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ 
      success: false, 
      message: 'Email and password required' 
    });
  }

  const user = users.find(
    u => u.email === email && u.password === password
  );

  if (!user) {
    console.log('Login failed: Invalid credentials');
    return res.status(401).json({ 
      success: false,
      message: 'Invalid credentials'
    });
  }

  const { password: _, ...safeUser } = user;

  console.log('Login successful:', safeUser.email);
  
  res.json({
    success: true,
    user: safeUser,
    token: `token_${user.id}_${Date.now()}`
  });
});

app.get('/api/auth/verify', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (token?.startsWith('token_')) {
    res.json({ success: true });
  } else {
    res.status(401).json({ success: false });
  }
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

      // 1️⃣ Register agent
      if (data.type === 'REGISTER_AGENT') {
        ws.plantId = data.plantId;
        agents.set(data.plantId, ws);
        console.log(`✅ Agent registered: ${data.plantId}`);
      }

      // 2️⃣ Query response
      if (data.type === 'QUERY_RESPONSE') {
        ws.lastResponse = data.payload;
      }

      // 3️⃣ Live stream (optional)
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

  console.log('Query request:', { sql, plantId });

  if (!sql || !plantId) {
    return res.status(400).json({
      error: 'sql and plantId required'
    });
  }

  const agent = agents.get(plantId);

  if (!agent) {
    console.log(`❌ Agent for ${plantId} is offline`);
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

  // wait for agent response
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
  console.log(`📝 Test credentials:`);
  console.log(`   - admin@example.com / admin123`);
  console.log(`   - user@example.com / user123`);
});