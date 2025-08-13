# Planner Pro Backend

Backend completo para o Planner Pro - aplicação de planejamento pessoal e profissional.

## 🚀 Tecnologias

- **Node.js** - Runtime JavaScript
- **Express.js** - Framework web
- **Prisma** - ORM para banco de dados
- **PostgreSQL** - Banco de dados (opcional, funciona em modo mock)
- **JWT** - Autenticação
- **bcryptjs** - Hash de senhas
- **CORS** - Cross-origin resource sharing

## 📋 Funcionalidades

- ✅ **Autenticação JWT**
- ✅ **Login/Registro de usuários**
- ✅ **Login com Google**
- ✅ **Gestão de Metas**
- ✅ **Gestão de Projetos**
- ✅ **Gestão Financeira**
- ✅ **Gestão de Viagens**
- ✅ **Calendário de Eventos**
- ✅ **Planejamento de Carreira**
- ✅ **Modo Mock** (funciona sem banco de dados)

## 🔧 Instalação

```bash
# Instalar dependências
npm install

# Configurar variáveis de ambiente
cp env.example .env

# Executar em desenvolvimento
npm run dev

# Executar em produção
npm start
```

## 🌐 Deploy

O backend está configurado para deploy no Vercel como serverless functions.

## 📡 Endpoints

### Autenticação
- `POST /api/auth/login` - Login
- `POST /api/auth/register` - Registro
- `POST /api/auth/google` - Login Google

### Dados
- `GET /api/goals` - Listar metas
- `GET /api/projects` - Listar projetos
- `GET /api/finances` - Listar finanças
- `GET /api/travels` - Listar viagens
- `GET /api/calendar` - Listar eventos
- `GET /api/career` - Listar carreira

### Health Check
- `GET /api/health` - Status do servidor

## 🔒 Autenticação

Todas as rotas protegidas requerem o header:
```
Authorization: Bearer <JWT_TOKEN>
```

## 🎯 Modo Mock

O backend funciona em modo mock quando não há conexão com banco de dados, permitindo desenvolvimento e testes sem configuração de banco.
