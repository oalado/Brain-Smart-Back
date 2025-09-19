import express from "express";
import cors from "cors";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();
const prisma = new PrismaClient();

// Configuração do CORS
app.use(cors({
  origin: "http://localhost:3000", // endereço do frontend
  credentials: true,               // permite envio de cookies/autenticação
}));
app.use(express.json());

// Chave secreta do JWT (em produção use variável de ambiente)
const JWT_SECRET = "seuSegredoJWT";

// =======================
// Rotas públicas
// =======================

// Rota de teste
app.get("/", (req, res) => {
  res.json({ message: "Backend rodando 🚀" });
});

// Cadastro de usuário
app.post("/register", async (req, res) => {
  const { name, email, password, cpf, apelido } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: { 
        name, 
        email, 
        password: hashedPassword,
        cpf, 
        apelido
      },
    });

    res.json({ message: "Usuário cadastrado com sucesso!", user });
  } catch (error) {
    res.status(400).json({ error: "Erro ao cadastrar usuário (email ou CPF pode já existir)" });
  }
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(400).json({ error: "Usuário não encontrado" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: "Senha inválida" });

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "1h" });

  res.json({ message: "Login realizado!", token });
});

// =======================
// Middleware de autenticação
// =======================
function authMiddleware(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ error: "Token não fornecido" });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Token inválido" });
    req.user = decoded;
    next();
  });
}

// =======================
// Rotas protegidas
// =======================

// Obter dados do usuário logado
app.get("/me", authMiddleware, async (req, res) => {
  const user = await prisma.user.findUnique({
    where: { id: req.user.userId },
    select: { id: true, name: true, email: true, cpf: true, apelido: true, createdAt: true },
  });

  if (!user) return res.status(404).json({ error: "Usuário não encontrado" });

  res.json(user);
});

// =======================
// Inicialização do servidor
// =======================
const PORT = 3001;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
