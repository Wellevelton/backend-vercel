const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const { body, validationResult } = require('express-validator');

const app = express();
let prisma;

// Inicializar Prisma apenas se DATABASE_URL estiver disponível
try {
  prisma = new PrismaClient();
  console.log('✅ Prisma conectado com sucesso');
} catch (error) {
  console.log('⚠️ Prisma não conectado, usando modo mock');
  prisma = null;
}

const PORT = process.env.PORT || 3001;

// ==================== CORS CONFIGURADO CORRETAMENTE ====================
const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:3000',
  'https://frontend-ji5jbkq4c-sobreiras-projects.vercel.app',
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
    message: 'Backend limpo funcionando!',
    timestamp: new Date().toISOString(),
    cors: 'Configurado corretamente'
  });
});

// Login
app.post('/api/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 1 })
], async (req, res) => {
  console.log('=== LOGIN ATTEMPT ===');
  console.log('Body:', { email: req.body.email, password: req.body.password ? 'present' : 'missing' });

  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Dados inválidos', details: errors.array() });
    }

    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email e senha são obrigatórios' });
    }

    // Mock user para teste
    if (email === 'teste@planner.com' && password === '123456') {
      const token = jwt.sign(
        { userId: 'mock-user-id', email: email },
        process.env.JWT_SECRET || 'fallback-secret',
        { expiresIn: '7d' }
      );

      console.log('Login successful for:', email);
      res.json({
        success: true,
        user: { id: 'mock-user-id', email: email, name: 'Usuário Teste' },
        token
      });
      return;
    }

    // Se tiver banco, usar Prisma
    if (prisma) {
      const user = await prisma.user.findUnique({
        where: { email }
      });

      if (!user) {
        console.log('User not found:', email);
        return res.status(401).json({ error: 'Email ou senha inválidos' });
      }

      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) {
        console.log('Invalid password for user:', email);
        return res.status(401).json({ error: 'Email ou senha inválidos' });
      }

      const token = jwt.sign(
        { userId: user.id, email: user.email },
        process.env.JWT_SECRET || 'fallback-secret',
        { expiresIn: '7d' }
      );

      console.log('Login successful for:', email);
      res.json({
        success: true,
        user: { id: user.id, email: user.email, name: user.name },
        token
      });
    } else {
      console.log('Invalid credentials:', email);
      res.status(401).json({ error: 'Email ou senha inválidos' });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Google Login
app.post('/api/auth/google', async (req, res) => {
  console.log('=== GOOGLE LOGIN ATTEMPT ===');
  console.log('Body:', req.body);

  try {
    const { idToken, email, name, googleId } = req.body;

    if (!email || !name || !googleId) {
      return res.status(400).json({ error: 'Dados obrigatórios não fornecidos' });
    }

    // Verificar se usuário já existe
    let user = await prisma.user.findUnique({
      where: { email }
    });

    if (!user) {
      // Criar novo usuário se não existir
      user = await prisma.user.create({
        data: {
          email,
          name,
          googleId: googleId,
          password: '' // Usuários Google não têm senha
        }
      });
      console.log('New Google user created:', email);
    } else {
      // Atualizar googleId se usuário existir
      user = await prisma.user.update({
        where: { id: user.id },
        data: { googleId: googleId }
      });
      console.log('Existing Google user updated:', email);
    }

    // Gerar token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      user: { id: user.id, email: user.email, name: user.name },
      token
    });
  } catch (error) {
    console.error('Google login error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Registro
app.post('/api/auth/register', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 }),
  body('name').notEmpty().trim()
], async (req, res) => {
  console.log('=== REGISTER ATTEMPT ===');
  console.log('Body:', { email: req.body.email, name: req.body.name, password: req.body.password ? 'present' : 'missing' });

  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Dados inválidos', details: errors.array() });
    }

    const { email, password, name } = req.body;

    // Verificar se usuário já existe
    const existingUser = await prisma.user.findUnique({
      where: { email }
    });

    if (existingUser) {
      return res.status(400).json({ error: 'Email já cadastrado' });
    }

    // Hash da senha
    const hashedPassword = await bcrypt.hash(password, 12);

    // Criar usuário
    const user = await prisma.user.create({
      data: {
        email,
        name,
        password: hashedPassword
      }
    });

    // Gerar token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: '7d' }
    );

    console.log('Registration successful for:', email);
    res.json({
      success: true,
      user: { id: user.id, email: user.email, name: user.name },
      token
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// ==================== MIDDLEWARE DE AUTENTICAÇÃO ====================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token não fornecido' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido' });
    }
    req.user = user;
    next();
  });
};

// ==================== ROTAS PROTEGIDAS ====================

// Goals
app.get('/api/goals', authenticateToken, async (req, res) => {
  try {
    const goals = await prisma.goal.findMany({
      where: { userId: req.user.userId }
    });
    res.json(goals);
  } catch (error) {
    console.error('Get goals error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/api/goals', authenticateToken, async (req, res) => {
  try {
    const goal = await prisma.goal.create({
      data: {
        ...req.body,
        userId: req.user.userId
      }
    });
    res.json(goal);
  } catch (error) {
    console.error('Create goal error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Finances
app.get('/api/finances', authenticateToken, async (req, res) => {
  try {
    const finances = await prisma.finance.findMany({
      where: { userId: req.user.userId }
    });
    res.json(finances);
  } catch (error) {
    console.error('Get finances error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/api/finances', authenticateToken, async (req, res) => {
  try {
    const finance = await prisma.finance.create({
      data: {
        ...req.body,
        userId: req.user.userId
      }
    });
    res.json(finance);
  } catch (error) {
    console.error('Create finance error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Projects
app.get('/api/projects', authenticateToken, async (req, res) => {
  try {
    const projects = await prisma.project.findMany({
      where: { userId: req.user.userId }
    });
    res.json(projects);
  } catch (error) {
    console.error('Get projects error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/api/projects', authenticateToken, async (req, res) => {
  try {
    const project = await prisma.project.create({
      data: {
        ...req.body,
        userId: req.user.userId
      }
    });
    res.json(project);
  } catch (error) {
    console.error('Create project error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Travels
app.get('/api/travels', authenticateToken, async (req, res) => {
  try {
    const travels = await prisma.travel.findMany({
      where: { userId: req.user.userId }
    });
    res.json(travels);
  } catch (error) {
    console.error('Get travels error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/api/travels', authenticateToken, async (req, res) => {
  try {
    const travel = await prisma.travel.create({
      data: {
        ...req.body,
        userId: req.user.userId
      }
    });
    res.json(travel);
  } catch (error) {
    console.error('Create travel error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Calendar
app.get('/api/calendar', authenticateToken, async (req, res) => {
  try {
    const events = await prisma.calendarEvent.findMany({
      where: { userId: req.user.userId }
    });
    res.json(events);
  } catch (error) {
    console.error('Get calendar error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/api/calendar', authenticateToken, async (req, res) => {
  try {
    const event = await prisma.calendarEvent.create({
      data: {
        ...req.body,
        userId: req.user.userId
      }
    });
    res.json(event);
  } catch (error) {
    console.error('Create calendar event error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Financial Planning
app.get('/api/financial-planning', authenticateToken, async (req, res) => {
  try {
    const planning = await prisma.financialPlanning.findMany({
      where: { userId: req.user.userId }
    });
    res.json(planning);
  } catch (error) {
    console.error('Get financial planning error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/api/financial-planning', authenticateToken, async (req, res) => {
  try {
    const planning = await prisma.financialPlanning.create({
      data: {
        ...req.body,
        userId: req.user.userId
      }
    });
    res.json(planning);
  } catch (error) {
    console.error('Create financial planning error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// ==================== INICIAR SERVIDOR ====================
app.listen(PORT, () => {
  console.log(`🚀 Backend limpo rodando na porta ${PORT}`);
  console.log(`📡 Health check: http://localhost:${PORT}/api/health`);
  console.log(`🔒 CORS configurado para aceitar frontend Vercel`);
});
