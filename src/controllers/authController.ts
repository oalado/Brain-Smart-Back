import { Request, Response } from "express";
import prisma from "../prisma/client";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

// Registro
export const register = async (req: Request, res: Response) => {
  try {
    const body = req.body as {
      name?: string;
      email?: string;
      password?: string;
      cpf?: string;
      apelido?: string;
    };

    const name = body.name?.trim() ?? "";
    const email = body.email?.trim().toLowerCase() ?? "";
    const password = body.password ?? "";
    const cpf = body.cpf?.trim() ?? "";
    const apelido = body.apelido?.trim() ?? "";

    if (!name || !email || !password || !cpf || !apelido) {
      return res.status(400).json({ error: "Todos os campos são obrigatórios" });
    }

    // Verifica email único
    const emailExists = await prisma.user.findUnique({
      where: { email },
    });
    if (emailExists) {
      return res.status(400).json({ error: "E-mail já registrado" });
    }

    // Verifica cpf único (requer que cpf exista no schema.prisma)
    const cpfExists = await prisma.user.findFirst({
      where: { cpf },
    });
    if (cpfExists) {
      return res.status(400).json({ error: "CPF já registrado" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
        cpf,
        apelido,
      },
      select: {
        id: true,
        name: true,
        email: true,
        cpf: true,
        apelido: true,
        createdAt: true,
      },
    });

    return res.status(201).json({ message: "Usuário registrado", user });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Erro ao registrar usuário" });
  }
};

// Login
export const login = async (req: Request, res: Response) => {
  try {
    const body = req.body as { email?: string; password?: string };
    const email = body.email?.trim().toLowerCase() ?? "";
    const password = body.password ?? "";

    if (!email || !password) {
      return res.status(400).json({ error: "E-mail e senha são obrigatórios" });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(400).json({ error: "E-mail não cadastrado" });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: "Senha inválida" });
    }

    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      console.error("JWT_SECRET não está definido");
      return res.status(500).json({ error: "Configuração de autenticação ausente" });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, jwtSecret, { expiresIn: "1d" });

    return res.json({
      message: "Login bem sucedido",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        cpf: user.cpf,
        apelido: user.apelido,
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Erro no login" });
  }
};
