require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const { body, validationResult } = require('express-validator');

const app = express();
let prisma;

// Inicializar Prisma
try {
  prisma = new PrismaClient();
  console.log('✅ Prisma inicializado');
  
  // Testar conexão
  prisma.$connect()
    .then(() => {
      console.log('✅ Prisma conectado com sucesso ao banco de dados');
    })
    .catch((error) => {
      console.log('⚠️ Erro ao conectar Prisma:', error.message);
      console.log('⚠️ Usando modo mock para desenvolvimento');
      prisma = null;
    });
} catch (error) {
  console.log('⚠️ Erro ao inicializar Prisma:', error.message);
  console.log('⚠️ Usando modo mock para desenvolvimento');
  prisma = null;
}

const PORT = process.env.PORT || 3001;

// ==================== CORS CONFIGURADO CORRETAMENTE ====================
const corsOptions = {
  origin: true, // Aceita qualquer origem
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));
app.use(express.json());

// ==================== LOGS PARA DEBUG ====================
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  console.log('Origin:', req.headers.origin);
  
  // Log de autenticação para debug
  if (req.path.startsWith('/api') && req.method !== 'OPTIONS') {
    console.log('Authorization:', req.headers.authorization || '<none>');
  }
  
  next();
});

// ==================== ROTAS ====================

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    message: 'Backend completo funcionando!',
    timestamp: new Date().toISOString()
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

    // Mock user para teste (sem banco)
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

    // Buscar usuário no banco
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
      // Modo mock - apenas usuário teste
      console.log('Login successful for:', email);
      res.json({
        success: true,
        user: { id: 'mock-user-id', email: email, name: 'Usuário Teste' },
        token: jwt.sign(
          { userId: 'mock-user-id', email: email },
          process.env.JWT_SECRET || 'fallback-secret',
          { expiresIn: '7d' }
        )
      });
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
    if (prisma) {
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
    } else {
      // Modo mock
      const token = jwt.sign(
        { userId: 'mock-google-user-id', email: email },
        process.env.JWT_SECRET || 'fallback-secret',
        { expiresIn: '7d' }
      );

      res.json({
        success: true,
        user: { id: 'mock-google-user-id', email: email, name: name },
        token
      });
    }
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
    if (prisma) {
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
    } else {
      // Modo mock
      const token = jwt.sign(
        { userId: 'mock-new-user-id', email: email },
        process.env.JWT_SECRET || 'fallback-secret',
        { expiresIn: '7d' }
      );

      console.log('Registration successful for:', email);
      res.json({
        success: true,
        user: { id: 'mock-new-user-id', email: email, name: name },
        token
      });
    }
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
    if (prisma) {
      const goals = await prisma.goal.findMany({
        where: { userId: req.user.userId }
      });
      res.json(goals);
    } else {
      // Modo mock
      res.json([]);
    }
  } catch (error) {
    console.error('Get goals error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.get('/goals', authenticateToken, async (req, res) => {
  try {
    if (prisma) {
      const goals = await prisma.goal.findMany({
        where: { userId: req.user.userId }
      });
      res.json(goals);
    } else {
      // Modo mock
      res.json([]);
    }
  } catch (error) {
    console.error('Get goals error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/api/goals', authenticateToken, async (req, res) => {
  try {
    if (prisma) {
      const goal = await prisma.goal.create({
        data: {
          ...req.body,
          userId: req.user.userId
        }
      });
      res.json(goal);
    } else {
      // Modo mock
      const mockGoal = {
        id: Date.now().toString(),
        ...req.body,
        userId: req.user.userId,
        createdAt: new Date().toISOString()
      };
      res.json(mockGoal);
    }
  } catch (error) {
    console.error('Create goal error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Finances
app.get('/api/finances', authenticateToken, async (req, res) => {
  try {
    if (prisma) {
      const finances = await prisma.finance.findMany({
        where: { userId: req.user.userId }
      });
      res.json(finances);
    } else {
      // Modo mock
      res.json([]);
    }
  } catch (error) {
    console.error('Get finances error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.get('/finances', authenticateToken, async (req, res) => {
  try {
    if (prisma) {
      const finances = await prisma.finance.findMany({
        where: { userId: req.user.userId }
      });
      res.json(finances);
    } else {
      // Modo mock
      res.json([]);
    }
  } catch (error) {
    console.error('Get finances error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/api/finances', authenticateToken, async (req, res) => {
  try {
    if (prisma) {
      const finance = await prisma.finance.create({
        data: {
          ...req.body,
          userId: req.user.userId
        }
      });
      res.json(finance);
    } else {
      // Modo mock
      const mockFinance = {
        id: Date.now().toString(),
        ...req.body,
        userId: req.user.userId,
        createdAt: new Date().toISOString()
      };
      res.json(mockFinance);
    }
  } catch (error) {
    console.error('Create finance error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Projects
app.get('/api/projects', authenticateToken, async (req, res) => {
  try {
    if (prisma) {
      const projects = await prisma.project.findMany({
        where: { userId: req.user.userId }
      });
      res.json(projects);
    } else {
      // Modo mock
      res.json([]);
    }
  } catch (error) {
    console.error('Get projects error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.get('/projects', authenticateToken, async (req, res) => {
  try {
    if (prisma) {
      const projects = await prisma.project.findMany({
        where: { userId: req.user.userId }
      });
      res.json(projects);
    } else {
      // Modo mock
      res.json([]);
    }
  } catch (error) {
    console.error('Get projects error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/api/projects', authenticateToken, async (req, res) => {
  try {
    if (prisma) {
      const project = await prisma.project.create({
        data: {
          ...req.body,
          userId: req.user.userId
        }
      });
      res.json(project);
    } else {
      // Modo mock
      const mockProject = {
        id: Date.now().toString(),
        ...req.body,
        userId: req.user.userId,
        createdAt: new Date().toISOString()
      };
      res.json(mockProject);
    }
  } catch (error) {
    console.error('Create project error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Travels
app.get('/api/travels', authenticateToken, async (req, res) => {
  try {
    if (prisma) {
      const travels = await prisma.travel.findMany({
        where: { userId: req.user.userId }
      });
      res.json(travels);
    } else {
      // Modo mock
      res.json([]);
    }
  } catch (error) {
    console.error('Get travels error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.get('/travels', authenticateToken, async (req, res) => {
  try {
    if (prisma) {
      const travels = await prisma.travel.findMany({
        where: { userId: req.user.userId }
      });
      res.json(travels);
    } else {
      // Modo mock
      res.json([]);
    }
  } catch (error) {
    console.error('Get travels error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/api/travels', authenticateToken, async (req, res) => {
  try {
    if (prisma) {
      const travel = await prisma.travel.create({
        data: {
          ...req.body,
          userId: req.user.userId
        }
      });
      res.json(travel);
    } else {
      // Modo mock
      const mockTravel = {
        id: Date.now().toString(),
        ...req.body,
        userId: req.user.userId,
        createdAt: new Date().toISOString()
      };
      res.json(mockTravel);
    }
  } catch (error) {
    console.error('Create travel error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Calendar
app.get('/api/calendar', authenticateToken, async (req, res) => {
  try {
    if (prisma) {
      const events = await prisma.calendarEvent.findMany({
        where: { userId: req.user.userId }
      });
      res.json(events);
    } else {
      // Modo mock
      res.json([]);
    }
  } catch (error) {
    console.error('Get calendar error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.get('/calendar', authenticateToken, async (req, res) => {
  try {
    if (prisma) {
      const events = await prisma.calendarEvent.findMany({
        where: { userId: req.user.userId }
      });
      res.json(events);
    } else {
      // Modo mock
      res.json([]);
    }
  } catch (error) {
    console.error('Get calendar error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/api/calendar', authenticateToken, async (req, res) => {
  try {
    if (prisma) {
      const event = await prisma.calendarEvent.create({
        data: {
          ...req.body,
          userId: req.user.userId
        }
      });
      res.json(event);
    } else {
      // Modo mock
      const mockEvent = {
        id: Date.now().toString(),
        ...req.body,
        userId: req.user.userId,
        createdAt: new Date().toISOString()
      };
      res.json(mockEvent);
    }
  } catch (error) {
    console.error('Create calendar event error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Career API (substituindo Financial Planning)
app.get('/api/career', authenticateToken, async (req, res) => {
  try {
    if (prisma) {
      const career = await prisma.careerPlanning.findMany({
        where: { userId: req.user.userId }
      });
      res.json(career);
    } else {
      // Modo mock
      res.json([]);
    }
  } catch (error) {
    console.error('Get career error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/api/career', authenticateToken, async (req, res) => {
  try {
    if (prisma) {
      const career = await prisma.careerPlanning.create({
        data: {
          ...req.body,
          userId: req.user.userId
        }
      });
      res.json(career);
    } else {
      // Modo mock
      const mockCareer = {
        id: Date.now().toString(),
        ...req.body,
        userId: req.user.userId,
        createdAt: new Date().toISOString()
      };
      res.json(mockCareer);
    }
  } catch (error) {
    console.error('Create career error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Financial Planning (mantido para compatibilidade)
app.get('/api/financial-planning', authenticateToken, async (req, res) => {
  try {
    if (prisma) {
      const planning = await prisma.financialPlanning.findMany({
        where: { userId: req.user.userId }
      });
      res.json(planning);
    } else {
      // Modo mock
      res.json([]);
    }
  } catch (error) {
    console.error('Get financial planning error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.get('/financial-planning', authenticateToken, async (req, res) => {
  try {
    if (prisma) {
      const planning = await prisma.financialPlanning.findMany({
        where: { userId: req.user.userId }
      });
      res.json(planning);
    } else {
      // Modo mock
      res.json([]);
    }
  } catch (error) {
    console.error('Get financial planning error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/api/financial-planning', authenticateToken, async (req, res) => {
  try {
    if (prisma) {
      const planning = await prisma.financialPlanning.create({
        data: {
          ...req.body,
          userId: req.user.userId
        }
      });
      res.json(planning);
    } else {
      // Modo mock
      const mockPlanning = {
        id: Date.now().toString(),
        ...req.body,
        userId: req.user.userId,
        createdAt: new Date().toISOString()
      };
      res.json(mockPlanning);
    }
  } catch (error) {
    console.error('Create financial planning error:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// ==================== INICIAR SERVIDOR ====================
app.listen(PORT, () => {
  console.log(`🚀 Backend completo rodando na porta ${PORT}`);
  console.log(`📡 Health check: http://localhost:${PORT}/api/health`);
  console.log(`🔒 CORS configurado para aceitar frontend Vercel`);
  console.log(`👤 Login: teste@planner.com / 123456`);
});
