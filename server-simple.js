const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3001;

// ==================== CORS CONFIGURADO CORRETAMENTE ====================
const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:3000',
  'https://frontend-qefwepww7-sobreiras-projects.vercel.app',
  /https:\/\/(frontend|planner)-[a-z0-9-]+-sobreiras-projects\.vercel\.app/
];

const corsOptions = {
  origin(origin, callback) {
    // Permite requests sem origin (curl, health checks)
    if (!origin) return callback(null, true);
    
    // Verifica se a origin está na lista permitida
    const isAllowed = allowedOrigins.some(allowed => 
      allowed instanceof RegExp ? allowed.test(origin) : allowed === origin
    );
    
    if (isAllowed) {
      callback(null, true);
    } else {
      console.log('CORS blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 204
};

// Aplicar CORS
app.use(cors(corsOptions));

// Middleware para JSON
app.use(express.json());

// ==================== LOGS PARA DEBUG ====================
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  console.log('Origin:', req.headers.origin);
  console.log('User-Agent:', req.headers['user-agent']);
  next();
});

// ==================== ROTAS ====================

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    message: 'Backend simples funcionando!',
    timestamp: new Date().toISOString(),
    cors: 'Configurado corretamente'
  });
});

// Login mock
app.post('/api/auth/login', (req, res) => {
  console.log('=== LOGIN ATTEMPT ===');
  console.log('Body:', req.body);

  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email e senha são obrigatórios' });
  }

  // Mock user para teste
  if (email === 'teste@planner.com' && password === '123456') {
    const token = jwt.sign(
      { userId: 'mock-user-id', email: email },
      'fallback-secret',
      { expiresIn: '7d' }
    );

    console.log('Login successful for:', email);
    res.json({
      success: true,
      user: { id: 'mock-user-id', email: email, name: 'Usuário Teste' },
      token
    });
  } else {
    console.log('Invalid credentials:', email);
    res.status(401).json({ error: 'Email ou senha inválidos' });
  }
});

// Google Login mock
app.post('/api/auth/google', (req, res) => {
  console.log('=== GOOGLE LOGIN ATTEMPT ===');
  console.log('Body:', req.body);

  const { email, name, googleId } = req.body;

  if (!email || !name || !googleId) {
    return res.status(400).json({ error: 'Dados obrigatórios não fornecidos' });
  }

  const token = jwt.sign(
    { userId: 'google-user-id', email: email },
    'fallback-secret',
    { expiresIn: '7d' }
  );

  console.log('Google login successful for:', email);
  res.json({
    success: true,
    user: { id: 'google-user-id', email: email, name: name },
    token
  });
});

// ==================== MIDDLEWARE DE AUTENTICAÇÃO ====================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token não fornecido' });
  }

  jwt.verify(token, 'fallback-secret', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido' });
    }
    req.user = user;
    next();
  });
};

// ==================== ROTAS PROTEGIDAS ====================

// Goals
app.get('/api/goals', authenticateToken, (req, res) => {
  console.log('GET /api/goals - User:', req.user.userId);
  res.json([]);
});

app.post('/api/goals', authenticateToken, (req, res) => {
  console.log('POST /api/goals - User:', req.user.userId, 'Data:', req.body);
  res.json({ id: 'mock-goal-id', ...req.body, userId: req.user.userId });
});

// Finances
app.get('/api/finances', authenticateToken, (req, res) => {
  console.log('GET /api/finances - User:', req.user.userId);
  res.json([]);
});

app.post('/api/finances', authenticateToken, (req, res) => {
  console.log('POST /api/finances - User:', req.user.userId, 'Data:', req.body);
  res.json({ id: 'mock-finance-id', ...req.body, userId: req.user.userId });
});

// Projects
app.get('/api/projects', authenticateToken, (req, res) => {
  console.log('GET /api/projects - User:', req.user.userId);
  res.json([]);
});

app.post('/api/projects', authenticateToken, (req, res) => {
  console.log('POST /api/projects - User:', req.user.userId, 'Data:', req.body);
  res.json({ id: 'mock-project-id', ...req.body, userId: req.user.userId });
});

// Travels
app.get('/api/travels', authenticateToken, (req, res) => {
  console.log('GET /api/travels - User:', req.user.userId);
  res.json([]);
});

app.post('/api/travels', authenticateToken, (req, res) => {
  console.log('POST /api/travels - User:', req.user.userId, 'Data:', req.body);
  res.json({ id: 'mock-travel-id', ...req.body, userId: req.user.userId });
});

// Calendar
app.get('/api/calendar', authenticateToken, (req, res) => {
  console.log('GET /api/calendar - User:', req.user.userId);
  res.json([]);
});

app.post('/api/calendar', authenticateToken, (req, res) => {
  console.log('POST /api/calendar - User:', req.user.userId, 'Data:', req.body);
  res.json({ id: 'mock-calendar-id', ...req.body, userId: req.user.userId });
});

// Financial Planning
app.get('/api/financial-planning', authenticateToken, (req, res) => {
  console.log('GET /api/financial-planning - User:', req.user.userId);
  res.json([]);
});

app.post('/api/financial-planning', authenticateToken, (req, res) => {
  console.log('POST /api/financial-planning - User:', req.user.userId, 'Data:', req.body);
  res.json({ id: 'mock-planning-id', ...req.body, userId: req.user.userId });
});

// ==================== INICIAR SERVIDOR ====================
app.listen(PORT, () => {
  console.log(`🚀 Backend simples rodando na porta ${PORT}`);
  console.log(`📡 Health check: http://localhost:${PORT}/api/health`);
  console.log(`🔒 CORS configurado para aceitar frontend Vercel`);
  console.log(`👤 Login: teste@planner.com / 123456`);
});
