// backend/server.js - WITH REAL-TIME SUBSCRIPTION SYSTEM
import express from 'express';
import cors from 'cors';
import http from 'http';
import { WebSocketServer } from 'ws';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

import User from './models/User.js';
import InvitationCode from './models/InvitationCode.js';
import Dashboard from './models/Dashboard.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;
const REQUIRE_ADMIN_APPROVAL = process.env.REQUIRE_ADMIN_APPROVAL === 'true';

// ================= TRACKING MAPS =================
const pendingRequests = new Map(); // requestId -> { resolve, reject, timeout }
const agents = new Map(); // plantId -> agent websocket
const agentHealth = new Map(); // plantId -> { lastPing, isAlive }

// ================= SUBSCRIPTION MANAGER =================
class SubscriptionManager {
  constructor() {
    this.subscribers = new Map(); // userId -> { ws, subscriptions: [] }
  }

  subscribe(userId, ws, subscription) {
    if (!this.subscribers.has(userId)) {
      this.subscribers.set(userId, {
        ws: ws,
        subscriptions: []
      });
    }

    this.subscribers.get(userId).subscriptions.push(subscription);
    console.log(`✅ User ${userId} subscribed to query: ${subscription.id}`);
  }

  unsubscribe(userId, queryId) {
    const user = this.subscribers.get(userId);
    if (user) {
      user.subscriptions = user.subscriptions.filter(sub => sub.id !== queryId);
      console.log(`❌ User ${userId} unsubscribed from: ${queryId}`);
    }
  }

  removeUser(userId) {
    this.subscribers.delete(userId);
    console.log(`❌ Removed all subscriptions for user: ${userId}`);
  }

  // Broadcast new data to subscribers
  broadcast(tableName, newData) {
    const { columns, dataset } = newData;
    
    for (const [userId, user] of this.subscribers.entries()) {
      try {
        // Check each subscription for this user
        for (const subscription of user.subscriptions) {
          // Simple check: if query mentions this table, send update
          if (subscription.sql.toLowerCase().includes(tableName.toLowerCase())) {
            user.ws.send(JSON.stringify({
              type: 'QUERY_UPDATE',
              queryId: subscription.id,
              columns: columns,
              dataset: dataset,
              timestamp: Date.now()
            }));
          }
        }
      } catch (err) {
        console.error(`Failed to send to user ${userId}:`, err.message);
      }
    }
  }

  getStats() {
    let totalSubscriptions = 0;
    for (const user of this.subscribers.values()) {
      totalSubscriptions += user.subscriptions.length;
    }
    return {
      activeUsers: this.subscribers.size,
      totalSubscriptions: totalSubscriptions
    };
  }
}

const subscriptionManager = new SubscriptionManager();

// ================= DATABASE =================
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// ================= MIDDLEWARE =================
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', 'https://reactfront-production-101d.up.railway.app');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS,PATCH');
  res.header('Access-Control-Allow-Headers', 'Origin,X-Requested-With,Content-Type,Accept,Authorization');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }

  next();
});

app.use(express.json());

app.use((req, res, next) => {
  req.id = crypto.randomUUID();
  res.setHeader('X-Request-ID', req.id);
  next();
});

// ================= AUTH MIDDLEWARE =================
function authenticateJWT(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ success: false, message: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
}

function requireAdmin(req, res, next) {
  User.findById(req.userId)
    .then(user => {
      if (!user || user.globalRole !== 'admin' && user.globalRole !== 'superadmin') {
        return res.status(403).json({ success: false, message: 'Admin access required' });
      }
      req.user = user;
      next();
    })
    .catch(err => {
      res.status(500).json({ success: false, message: 'Server error' });
    });
}

function requirePlantAccess(requiredRole = 'operator') {
  return async (req, res, next) => {
    try {
      const user = await User.findById(req.userId);
      const { plantId } = req.params || req.query || req.body;
      
      if (!plantId) {
        return res.status(400).json({ success: false, message: 'Plant ID required' });
      }

      if (!user.hasPlantAccess(plantId, requiredRole)) {
        return res.status(403).json({ 
          success: false, 
          message: 'Insufficient permissions for this plant' 
        });
      }

      req.user = user;
      req.plantRole = user.getPlantRole(plantId);
      next();
    } catch (err) {
      res.status(500).json({ success: false, message: 'Server error' });
    }
  };
}

// ================= HELPER FUNCTIONS =================
function generateInvitationCode(plantId) {
  const randomBytes = crypto.randomBytes(8).toString('hex').toUpperCase();
  const prefix = plantId.toUpperCase().substring(0, 6).padEnd(6, 'X');
  return `${prefix}-${randomBytes}`;
}

// ================= ADMIN: INVITATION MANAGEMENT ================= 
// (keeping all your existing admin routes - truncated for brevity)
// ... (lines 119-218 from your original file)

app.post('/api/admin/invitations', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    const { plantId, role = 'operator', expiresInDays = 7, maxUses = 1 } = req.body;

    if (!plantId) {
      return res.status(400).json({ success: false, message: 'Plant ID required' });
    }

    const code = generateInvitationCode(plantId);
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + expiresInDays);

    const invitation = await InvitationCode.create({
      code,
      plantId,
      role,
      createdBy: req.userId,
      expiresAt,
      maxUses
    });

    res.json({
      success: true,
      code: invitation.code,
      plantId: invitation.plantId,
      role: invitation.role,
      expiresAt: invitation.expiresAt,
      maxUses: invitation.maxUses,
      shareUrl: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/register?code=${invitation.code}`
    });
  } catch (err) {
    console.error('❌ Generate invitation error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/admin/invitations', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    const { plantId, status } = req.query;
    const filter = {};

    if (plantId) filter.plantId = plantId;
    if (status === 'active') {
      filter.isActive = true;
      filter.expiresAt = { $gt: new Date() };
    } else if (status === 'expired') {
      filter.expiresAt = { $lte: new Date() };
    } else if (status === 'used') {
      filter.usedBy = { $ne: null };
    }

    const invitations = await InvitationCode.find(filter)
      .populate('createdBy', 'name email')
      .populate('usedBy', 'name email')
      .sort({ createdAt: -1 })
      .limit(100);

    res.json({
      success: true,
      invitations: invitations.map(inv => ({
        code: inv.code,
        plantId: inv.plantId,
        role: inv.role,
        createdBy: inv.createdBy?.name,
        createdAt: inv.createdAt,
        expiresAt: inv.expiresAt,
        isActive: inv.isActive,
        isValid: inv.isValid(),
        usedBy: inv.usedBy?.name,
        usedAt: inv.usedAt,
        maxUses: inv.maxUses,
        timesUsed: inv.timesUsed
      }))
    });
  } catch (err) {
    console.error('❌ List invitations error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.delete('/api/admin/invitations/:code', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    const { code } = req.params;
    
    const invitation = await InvitationCode.findOne({ code });
    if (!invitation) {
      return res.status(404).json({ success: false, message: 'Invitation not found' });
    }

    invitation.isActive = false;
    await invitation.save();

    res.json({ success: true, message: 'Invitation revoked' });
  } catch (err) {
    console.error('❌ Revoke invitation error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ================= ADMIN: USER MANAGEMENT =================
// (keeping all your existing user management routes)

app.get('/api/admin/users', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    const { plantId, status } = req.query;
    const filter = {};

    if (status) filter.status = status;
    if (plantId) filter['plantAccess.plantId'] = plantId;

    const users = await User.find(filter)
      .select('-password')
      .sort({ createdAt: -1 });

    res.json({
      success: true,
      users: users.map(user => ({
        id: user._id,
        email: user.email,
        name: user.name,
        status: user.status,
        globalRole: user.globalRole,
        plantAccess: user.plantAccess,
        invitationCode: user.invitationCode,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin
      }))
    });
  } catch (err) {
    console.error('❌ List users error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/admin/users/:userId/approve', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (user.status !== 'pending') {
      return res.status(400).json({ success: false, message: 'User is not pending approval' });
    }

    user.status = 'active';
    await user.save();

    res.json({ 
      success: true, 
      message: 'User approved',
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        status: user.status
      }
    });
  } catch (err) {
    console.error('❌ Approve user error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/admin/users/:userId/suspend', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    user.status = 'suspended';
    await user.save();

    res.json({ success: true, message: 'User suspended' });
  } catch (err) {
    console.error('❌ Suspend user error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ================= DASHBOARD API (Your existing routes) =================
app.get('/api/dashboards', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    const plantId = user.plantId || user.plantAccess[0]?.plantId;

    const dashboards = await Dashboard.find({
      $or: [
        { createdBy: req.userId },
        { plantId: plantId, shared: true }
      ]
    }).sort({ lastModified: -1 });

    res.json({ success: true, dashboards });
  } catch (err) {
    console.error('❌ Get dashboards error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/dashboards', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    const plantId = user.plantId || user.plantAccess[0]?.plantId;

    const dashboard = await Dashboard.create({
      ...req.body,
      createdBy: req.userId,
      plantId: plantId
    });

    res.json({ success: true, dashboard });
  } catch (err) {
    console.error('❌ Create dashboard error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.put('/api/dashboards/:id', authenticateJWT, async (req, res) => {
  try {
    const dashboard = await Dashboard.findOne({
      _id: req.params.id,
      $or: [
        { createdBy: req.userId },
        { shared: true }
      ]
    });

    if (!dashboard) {
      return res.status(404).json({ success: false, message: 'Dashboard not found' });
    }

    Object.assign(dashboard, req.body, { lastModified: new Date() });
    await dashboard.save();

    res.json({ success: true, dashboard });
  } catch (err) {
    console.error('❌ Update dashboard error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.delete('/api/dashboards/:id', authenticateJWT, async (req, res) => {
  try {
    const dashboard = await Dashboard.findOne({
      _id: req.params.id,
      createdBy: req.userId
    });

    if (!dashboard) {
      return res.status(404).json({ success: false, message: 'Dashboard not found or no permission' });
    }

    await dashboard.deleteOne();
    res.json({ success: true });
  } catch (err) {
    console.error('❌ Delete dashboard error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ================= AUTH API =================
app.get('/api/auth/verify-invitation', async (req, res) => {
  try {
    const { code } = req.query;

    if (!code) {
      return res.status(400).json({ success: false, message: 'Code required' });
    }

    const invitation = await InvitationCode.findOne({ code: code.toUpperCase() });

    if (!invitation) {
      return res.json({ 
        success: true, 
        valid: false, 
        message: 'Invalid invitation code' 
      });
    }

    if (!invitation.isValid()) {
      return res.json({ 
        success: true, 
        valid: false, 
        message: invitation.expiresAt < new Date() ? 'Invitation code expired' : 'Invitation code already used' 
      });
    }

    res.json({
      success: true,
      valid: true,
      plantId: invitation.plantId,
      role: invitation.role,
      expiresAt: invitation.expiresAt
    });
  } catch (err) {
    console.error('❌ Verify invitation error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, invitationCode } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }

    if (!invitationCode) {
      return res.status(400).json({ success: false, message: 'Invitation code is required' });
    }

    const exists = await User.findOne({ email });
    if (exists) {
      return res.status(409).json({ success: false, message: 'User already exists' });
    }

    const invitation = await InvitationCode.findOne({ code: invitationCode.toUpperCase() });
    
    if (!invitation || !invitation.isValid()) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid or expired invitation code' 
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const status = REQUIRE_ADMIN_APPROVAL ? 'pending' : 'active';

    const user = await User.create({
      email,
      password: hashedPassword,
      name,
      plantId: invitation.plantId,
      plantAccess: [{
        plantId: invitation.plantId,
        role: invitation.role,
        grantedBy: invitation.createdBy,
        grantedAt: new Date()
      }],
      status,
      invitationCode: invitation.code
    });

    invitation.timesUsed += 1;
    if (invitation.timesUsed >= invitation.maxUses) {
      invitation.usedBy = user._id;
      invitation.usedAt = new Date();
    }
    await invitation.save();

    const token = jwt.sign(
      { id: user._id, plantId: invitation.plantId }, 
      process.env.JWT_SECRET, 
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      message: status === 'pending' 
        ? 'Account created. Awaiting admin approval.' 
        : 'Account created successfully',
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        status: user.status,
        plantAccess: user.plantAccess
      },
      token,
      requiresApproval: status === 'pending'
    });
  } catch (err) {
    console.error('❌ Register error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    if (user.status === 'suspended') {
      return res.status(403).json({ 
        success: false, 
        message: 'Account suspended. Contact administrator.' 
      });
    }

    if (user.status === 'pending') {
      return res.status(403).json({ 
        success: false, 
        message: 'Account pending admin approval',
        requiresApproval: true
      });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    user.lastLogin = new Date();
    await user.save();

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
        plantId: user.plantId,
        plantAccess: user.plantAccess,
        globalRole: user.globalRole
      },
      token
    });
  } catch (err) {
    console.error('❌ Login error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/auth/verify', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    
    if (!user) {
      return res.status(401).json({ success: false });
    }

    res.json({ 
      success: true,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        status: user.status,
        plantAccess: user.plantAccess,
        globalRole: user.globalRole
      }
    });
  } catch (err) {
    res.status(401).json({ success: false });
  }
});

// ================= HTTP SERVER =================
const server = http.createServer(app);

// ================= AGENT WEBSOCKET SERVER =================
const wss = new WebSocketServer({ 
  server, 
  path: '/ws/agent',
  perMessageDeflate: false // Disable compression
});

wss.on('connection', (ws) => {
  console.log('🔌 Agent attempting connection');
  
  ws.isAlive = true;
  
  ws.on('pong', () => {
    ws.isAlive = true;
  });

  ws.on('message', (msg) => {
    try {
      const data = JSON.parse(msg.toString());

      // ================= AGENT REGISTRATION =================
      if (data.type === 'REGISTER_AGENT') {
        ws.plantId = data.plantId;
        agents.set(data.plantId, ws);
        agentHealth.set(data.plantId, { 
          lastPing: Date.now(), 
          isAlive: true 
        });
        console.log(`✅ Agent registered: ${data.plantId}`);
      }

      // ================= QUERY RESPONSE =================
      if (data.type === 'QUERY_RESPONSE' && data.requestId) {
        const pending = pendingRequests.get(data.requestId);
        if (pending) {
          clearTimeout(pending.timeout);
          pending.resolve(data.payload);
          pendingRequests.delete(data.requestId);
        } else {
          console.warn(`⚠️  Received response for unknown request: ${data.requestId}`);
        }
      }

      // ================= LIVE DATA STREAM (NEW) =================
      if (data.type === 'LIVE_DATA_STREAM') {
        console.log(`📡 Received live data from ${data.tableName}: ${data.payload.count} rows`);
        // Broadcast to subscribed frontend clients
        subscriptionManager.broadcast(data.tableName, data.payload);
      }

      // ================= TABLES REFRESHED =================
      if (data.type === 'TABLES_REFRESHED') {
        ws.tableInfo = data.payload;
      }

    } catch (err) {
      console.error('❌ WS message error:', err.message);
    }
  });

  ws.on('close', () => {
    if (ws.plantId) {
      agents.delete(ws.plantId);
      agentHealth.delete(ws.plantId);
      console.log(`❌ Agent disconnected: ${ws.plantId}`);
    }
  });

  ws.on('error', (err) => {
    console.error('❌ WS connection error:', err.message);
  });
});

// ================= FRONTEND WEBSOCKET SERVER (NEW) =================
const frontendWss = new WebSocketServer({ 
  server, 
  path: '/ws/live',
  perMessageDeflate: false // Disable compression
});

frontendWss.on('connection', (ws, req) => {
  const token = new URL(req.url, 'http://localhost').searchParams.get('token');
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    ws.userId = decoded.id;
    
    console.log(`🔌 Frontend connected: User ${ws.userId}`);

    ws.on('message', (msg) => {
      try {
        const data = JSON.parse(msg.toString());

        if (data.type === 'SUBSCRIBE_QUERY') {
          subscriptionManager.subscribe(ws.userId, ws, {
            id: data.queryId,
            sql: data.sql
          });
        }

        if (data.type === 'UNSUBSCRIBE_QUERY') {
          subscriptionManager.unsubscribe(ws.userId, data.queryId);
        }

      } catch (err) {
        console.error('Error handling frontend message:', err);
      }
    });

    ws.on('close', () => {
      subscriptionManager.removeUser(ws.userId);
      console.log(`❌ Frontend disconnected: User ${ws.userId}`);
    });

  } catch (err) {
    console.error('❌ Frontend auth failed:', err.message);
    ws.close();
  }
});

// ================= AGENT HEALTH MONITORING =================
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) {
      if (ws.plantId) {
        agents.delete(ws.plantId);
        agentHealth.delete(ws.plantId);
        console.log(`💀 Agent ${ws.plantId} died, terminating connection`);
      }
      return ws.terminate();
    }

    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

// ================= QUESTDB QUERY (FALLBACK FOR ONE-TIME QUERIES) =================
app.get('/api/questdb/query', async (req, res) => {
  const { sql, plantId } = req.query;
  const requestId = crypto.randomUUID();

  if (!sql || !plantId) {
    return res.status(400).json({ 
      error: 'sql and plantId required',
      columns: [],
      dataset: []
    });
  }

  const agent = agents.get(plantId);
  if (!agent || !agent.isAlive) {
    return res.status(503).json({ 
      error: `Agent for ${plantId} is offline`, 
      columns: [], 
      dataset: [] 
    });
  }

  const timeoutMs = 10000;

  const responsePromise = new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      pendingRequests.delete(requestId);
      reject(new Error('Query timeout - agent did not respond in time'));
    }, timeoutMs);

    pendingRequests.set(requestId, { resolve, reject, timeout });
  });

  try {
    agent.send(JSON.stringify({ 
      type: 'EXEC_QUERY', 
      sql,
      requestId 
    }));

    const result = await responsePromise;
    
    res.json(result || { columns: [], dataset: [] });
  } catch (error) {
    console.error(`❌ Query error [${requestId}]:`, error.message);
    res.status(500).json({ 
      error: error.message,
      columns: [], 
      dataset: [] 
    });
  }
});

// ================= AGENT STATUS =================
app.get('/api/questdb/agent-status/:plantId', authenticateJWT, async (req, res) => {
  const { plantId } = req.params;
  
  const agent = agents.get(plantId);
  const health = agentHealth.get(plantId);
  
  res.json({
    plantId,
    connected: !!agent,
    isAlive: agent?.isAlive || false,
    lastPing: health?.lastPing || null,
    tableInfo: agent?.tableInfo || null
  });
});

// ================= HEALTH =================
app.get('/api/health', (req, res) => {
  const agentStatuses = {};
  
  for (const [plantId, agent] of agents.entries()) {
    agentStatuses[plantId] = {
      connected: true,
      isAlive: agent.isAlive,
      health: agentHealth.get(plantId)
    };
  }

  const subStats = subscriptionManager.getStats();

  res.json({ 
    status: 'ok',
    timestamp: new Date().toISOString(),
    agents: agentStatuses,
    pendingRequests: pendingRequests.size,
    subscriptions: subStats
  });
});

// ================= CLEANUP ON SHUTDOWN =================
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received, cleaning up...');
  
  for (const [requestId, pending] of pendingRequests.entries()) {
    clearTimeout(pending.timeout);
    pending.reject(new Error('Server shutting down'));
  }
  pendingRequests.clear();
  
  wss.clients.forEach(ws => ws.close());
  frontendWss.clients.forEach(ws => ws.close());
  
  server.close(() => {
    console.log('✅ Server closed');
    process.exit(0);
  });
});

// ================= START =================
server.listen(PORT, () => {
  console.log(`🚀 Backend running on http://localhost:${PORT}`);
  console.log(`🔌 Agent WebSocket: ws://localhost:${PORT}/ws/agent`);
  console.log(`🔌 Frontend WebSocket: ws://localhost:${PORT}/ws/live`);
  console.log(`🔐 Admin approval required: ${REQUIRE_ADMIN_APPROVAL}`);
  console.log(`✅ Request correlation enabled`);
  console.log(`✅ Agent health monitoring enabled`);
  console.log(`✅ Real-time subscriptions enabled`);
});
