require("dotenv").config();

const express = require("express");
const sql = require("mssql");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const speakeasy = require("speakeasy");
const helmet = require("helmet");
const cors = require("cors");
const nodemailer = require("nodemailer");

const app = express();
const localhostOriginPattern = /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/;

app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(
  cors({
    origin(origin, callback) {
      if (!origin || localhostOriginPattern.test(origin)) {
        return callback(null, true);
      }

      return callback(new Error("Origen no permitido por CORS."));
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Origin", "X-Requested-With", "Content-Type", "Accept", "Authorization"],
  })
);
app.use((error, _req, res, next) => {
  if (error && error.message === "Origen no permitido por CORS.") {
    return res.status(403).json({ message: error.message });
  }

  next();
});
app.use(express.json());

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "cambia-este-secreto-en-produccion";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "8h";
const PREAUTH_EXPIRES_IN_MINUTES = Number(process.env.PREAUTH_EXPIRES_IN_MINUTES || 5);
const PASSWORD_EXPIRY_DAYS = Number(process.env.PASSWORD_EXPIRY_DAYS || 90);
const MAX_FAILED_ATTEMPTS = Number(process.env.MAX_FAILED_ATTEMPTS || 3);
const LOCKOUT_MINUTES = Number(process.env.LOCKOUT_MINUTES || 15);
const RESET_TOKEN_MINUTES = Number(process.env.RESET_TOKEN_MINUTES || 15);
const BCRYPT_ROUNDS = Number(process.env.BCRYPT_ROUNDS || 12);
const SMTP_HOST = (process.env.SMTP_HOST || "smtp.gmail.com").trim();
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_SECURE = String(process.env.SMTP_SECURE || "false").toLowerCase() === "true";
const SMTP_USER = (process.env.SMTP_USER || "").trim();
const SMTP_PASS = (process.env.SMTP_PASS || "").trim();
const SMTP_FROM = (process.env.SMTP_FROM || SMTP_USER).trim();
const APP_BASE_URL = (process.env.APP_BASE_URL || "http://localhost:54321").trim();

const dbConfig = {
  user: process.env.DB_USER || "sa",
  password: process.env.DB_PASSWORD || "root12345",
  server: process.env.DB_SERVER || "JORDYPRADO",
  database: process.env.DB_NAME || "bd_optica_modelo_estrella",
  port: 1433,
  options: {
    encrypt: false,
    trustServerCertificate: true,
    enableArithAbort: true,
  },
  connectionTimeout: 30000,
  requestTimeout: 30000,
};
let pool;
let mailTransporter;

async function getPool() {
  if (!pool) {
    pool = await sql.connect(dbConfig);
  }

  return pool;
}

function canSendEmail() {
  return Boolean(SMTP_USER && SMTP_PASS && SMTP_FROM);
}

function getMailTransporter() {
  if (!canSendEmail()) {
    return null;
  }

  if (!mailTransporter) {
    mailTransporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_SECURE,
      auth: {
        user: SMTP_USER,
        pass: SMTP_PASS,
      },
    });
  }

  return mailTransporter;
}

async function sendTemporaryPasswordEmail({ email, identifier, temporaryPassword }) {
  const transporter = getMailTransporter();

  if (!transporter) {
    throw new Error("SMTP no configurado. Completa SMTP_USER, SMTP_PASS y SMTP_FROM.");
  }

  const appUrl = APP_BASE_URL;

  await transporter.sendMail({
    from: SMTP_FROM,
    to: email,
    subject: "Clave temporal - Optometria Movil",
    text: [
      "Recibimos una solicitud de recuperacion de contrasena.",
      `Usuario: ${identifier}`,
      `Clave temporal: ${temporaryPassword}`,
      "Inicia sesion con esta clave temporal y luego cambia tu contrasena.",
      `Acceso: ${appUrl}`,
    ].join("\n"),
    html: `
      <div style="font-family: Arial, sans-serif; line-height: 1.5; color: #163939;">
        <h2>Clave temporal de acceso</h2>
        <p>Recibimos una solicitud de recuperacion de contrasena.</p>
        <p><strong>Usuario:</strong> ${identifier}</p>
        <p><strong>Clave temporal:</strong> ${temporaryPassword}</p>
        <p>
          Inicia sesion con esta clave temporal y luego cambia tu contrasena.
        </p>
        <p><a href="${appUrl}">Abrir aplicacion</a></p>
      </div>
    `,
  });
}

async function sendAccountLockedEmail({ email, identifier, lockoutUntil }) {
  const transporter = getMailTransporter();

  if (!transporter) {
    throw new Error("SMTP no configurado. Completa SMTP_USER, SMTP_PASS y SMTP_FROM.");
  }

  const recoveryUrl =
    `${APP_BASE_URL}/recover-password` +
    `?identifier=${encodeURIComponent(identifier)}`;

  const lockoutText = lockoutUntil
    ? new Date(lockoutUntil).toLocaleString("es-CO")
    : "temporalmente";

  await transporter.sendMail({
    from: SMTP_FROM,
    to: email,
    subject: "Alerta de seguridad - Cuenta bloqueada",
    text: [
      "Tu cuenta fue bloqueada temporalmente por intentos fallidos de inicio de sesion.",
      `Bloqueo hasta: ${lockoutText}`,
      `Si no fuiste tu, te recomendamos cambiar tu contrasena o iniciar recuperacion desde: ${recoveryUrl}`,
    ].join("\n"),
    html: `
      <div style="font-family: Arial, sans-serif; line-height: 1.5; color: #163939;">
        <h2>Alerta de seguridad</h2>
        <p>Tu cuenta fue bloqueada temporalmente por intentos fallidos de inicio de sesion.</p>
        <p><strong>Bloqueo hasta:</strong> ${lockoutText}</p>
        <p>
          Si no fuiste tu, te recomendamos cambiar tu contrasena o iniciar recuperacion.
        </p>
        <p>
          <a href="${recoveryUrl}">Ir a recuperacion de contrasena</a>
        </p>
      </div>
    `,
  });
}

async function ensureSecuritySchema() {
  const connection = await getPool();

  await connection.request().query(`
    IF COL_LENGTH('dbo.tbl_usuario_seguridad', 'failed_attempts') IS NULL
    BEGIN
      ALTER TABLE dbo.tbl_usuario_seguridad ADD failed_attempts INT NOT NULL CONSTRAINT DF_tbl_usuario_seguridad_failed_attempts DEFAULT(0);
    END;

    IF COL_LENGTH('dbo.tbl_usuario_seguridad', 'lockout_until') IS NULL
    BEGIN
      ALTER TABLE dbo.tbl_usuario_seguridad ADD lockout_until DATETIME NULL;
    END;

    IF COL_LENGTH('dbo.tbl_usuario_seguridad', 'reset_token_hash') IS NULL
    BEGIN
      ALTER TABLE dbo.tbl_usuario_seguridad ADD reset_token_hash VARCHAR(255) NULL;
    END;

    IF COL_LENGTH('dbo.tbl_usuario_seguridad', 'reset_token_expires_at') IS NULL
    BEGIN
      ALTER TABLE dbo.tbl_usuario_seguridad ADD reset_token_expires_at DATETIME NULL;
    END;

    IF COL_LENGTH('dbo.tbl_usuario_seguridad', 'last_login_at') IS NULL
    BEGIN
      ALTER TABLE dbo.tbl_usuario_seguridad ADD last_login_at DATETIME NULL;
    END;

    IF COL_LENGTH('dbo.tbl_usuario_seguridad', 'password_expires_at') IS NULL
    BEGIN
      ALTER TABLE dbo.tbl_usuario_seguridad ADD password_expires_at DATETIME NULL;
    END;
  `);
}

async function ensureUserSecurityRow(userId) {
  const connection = await getPool();

  await connection
    .request()
    .input("userId", sql.Int, userId)
    .query(`
      IF NOT EXISTS (SELECT 1 FROM dbo.tbl_usuario_seguridad WHERE id_usuario = @userId)
      BEGIN
        INSERT INTO dbo.tbl_usuario_seguridad (
          id_usuario,
          two_factor_enabled,
          authenticator_secret,
          recovery_password_hash,
          recovery_password_expires_at,
          must_change_password,
          created_at,
          updated_at,
          password_changed_at,
          failed_attempts,
          lockout_until,
          reset_token_hash,
          reset_token_expires_at,
          last_login_at,
          password_expires_at
        )
        VALUES (
          @userId,
          0,
          NULL,
          NULL,
          NULL,
          0,
          GETDATE(),
          GETDATE(),
          GETDATE(),
          0,
          NULL,
          NULL,
          NULL,
          NULL,
          DATEADD(DAY, ${PASSWORD_EXPIRY_DAYS}, GETDATE())
        );
      END;
    `);
}

function normalizeIdentifier(value) {
  return String(value || "").trim();
}

function buildPasswordExpiryDate() {
  const now = new Date();
  now.setDate(now.getDate() + PASSWORD_EXPIRY_DAYS);
  return now;
}

function generateJwt(user) {
  return jwt.sign(
    {
      sub: user.id_usuario,
      usuario: user.usuario,
      email: user.email,
      rolId: user.id_rol,
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

function generatePreAuthToken(userId) {
  return jwt.sign(
    { sub: userId, stage: "pre-2fa" },
    JWT_SECRET,
    { expiresIn: `${PREAUTH_EXPIRES_IN_MINUTES}m` }
  );
}

function generateTemporaryPassword() {
  const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  const lower = "abcdefghijkmnopqrstuvwxyz";
  const numbers = "23456789";
  const specials = "@#$%&*!?";
  const all = upper + lower + numbers + specials;
  const pick = (chars) => chars[crypto.randomInt(0, chars.length)];

  const basePassword = [pick(upper), pick(lower), pick(numbers), pick(specials)];

  while (basePassword.length < 12) {
    basePassword.push(pick(all));
  }

  for (let index = basePassword.length - 1; index > 0; index -= 1) {
    const swapIndex = crypto.randomInt(0, index + 1);
    [basePassword[index], basePassword[swapIndex]] = [
      basePassword[swapIndex],
      basePassword[index],
    ];
  }

  return basePassword.join("");
}

function buildPasswordPolicyErrors(password, user = {}) {
  const errors = [];
  const normalizedPassword = String(password || "");

  if (normalizedPassword.length < 12) {
    errors.push("La contrasena debe tener minimo 12 caracteres.");
  }

  if (!/[A-Z]/.test(normalizedPassword)) {
    errors.push("La contrasena debe incluir al menos una letra mayuscula.");
  }

  if (!/[a-z]/.test(normalizedPassword)) {
    errors.push("La contrasena debe incluir al menos una letra minuscula.");
  }

  if (!/[0-9]/.test(normalizedPassword)) {
    errors.push("La contrasena debe incluir al menos un numero.");
  }

  if (!/[^A-Za-z0-9]/.test(normalizedPassword)) {
    errors.push("La contrasena debe incluir al menos un caracter especial.");
  }

  const lowerPassword = normalizedPassword.toLowerCase();
  const personalData = [user.usuario, user.email, user.nombres, user.apellidos]
    .filter(Boolean)
    .map((item) => String(item).toLowerCase());

  if (personalData.some((value) => value.length >= 3 && lowerPassword.includes(value))) {
    errors.push("La contrasena no debe contener datos personales evidentes del usuario.");
  }

  return errors;
}

async function getUserByIdentifier(identifier) {
  const connection = await getPool();
  const safeIdentifier = normalizeIdentifier(identifier);

  const result = await connection
    .request()
    .input("identifier", sql.VarChar(150), safeIdentifier)
    .query(`
      SELECT TOP 1
        u.id_usuario,
        u.id_rol,
        u.nombres,
        u.apellidos,
        u.email,
        u.usuario,
        u.password_hash,
        u.activo,
        u.intentos_fallidos,
        u.bloqueado,
        u.ultimo_cambio_password,
        s.two_factor_enabled,
        s.authenticator_secret,
        s.must_change_password,
        s.password_changed_at,
        s.failed_attempts,
        s.lockout_until,
        s.reset_token_hash,
        s.reset_token_expires_at,
        s.password_expires_at
      FROM dbo.tbl_usuario u
      LEFT JOIN dbo.tbl_usuario_seguridad s
        ON s.id_usuario = u.id_usuario
      WHERE u.usuario = @identifier OR u.email = @identifier
    `);

  const user = result.recordset[0];

  if (user) {
    await ensureUserSecurityRow(user.id_usuario);

    const refreshed = await connection
      .request()
      .input("userId", sql.Int, user.id_usuario)
      .query(`
        SELECT TOP 1
          u.id_usuario,
          u.id_rol,
          u.nombres,
          u.apellidos,
          u.email,
          u.usuario,
          u.password_hash,
          u.activo,
          u.intentos_fallidos,
          u.bloqueado,
          u.ultimo_cambio_password,
          s.two_factor_enabled,
          s.authenticator_secret,
          s.must_change_password,
          s.password_changed_at,
          s.failed_attempts,
          s.lockout_until,
          s.reset_token_hash,
          s.reset_token_expires_at,
          s.password_expires_at
        FROM dbo.tbl_usuario u
        INNER JOIN dbo.tbl_usuario_seguridad s
          ON s.id_usuario = u.id_usuario
        WHERE u.id_usuario = @userId
      `);

    return refreshed.recordset[0];
  }

  return null;
}

function isPasswordExpired(user) {
  if (!user.password_expires_at) {
    return false;
  }

  return new Date(user.password_expires_at) <= new Date();
}

function isLocked(user) {
  if (user.bloqueado) {
    return true;
  }

  if (!user.lockout_until) {
    return false;
  }

  return new Date(user.lockout_until) > new Date();
}

async function registerFailedLogin(user) {
  const connection = await getPool();
  const previousAttempts = Number(user.failed_attempts || 0);

  await connection
    .request()
    .input("userId", sql.Int, user.id_usuario)
    .input("maxAttempts", sql.Int, MAX_FAILED_ATTEMPTS)
    .input("lockoutMinutes", sql.Int, LOCKOUT_MINUTES)
    .query(`
      UPDATE s
      SET
        failed_attempts = ISNULL(s.failed_attempts, 0) + 1,
        lockout_until = CASE
          WHEN ISNULL(s.failed_attempts, 0) + 1 >= @maxAttempts THEN DATEADD(MINUTE, @lockoutMinutes, GETDATE())
          ELSE s.lockout_until
        END,
        updated_at = GETDATE()
      FROM dbo.tbl_usuario_seguridad s
      WHERE s.id_usuario = @userId;

      UPDATE u
      SET
        intentos_fallidos = ISNULL(intentos_fallidos, 0) + 1,
        bloqueado = CASE
          WHEN ISNULL(intentos_fallidos, 0) + 1 >= @maxAttempts THEN 1
          ELSE 0
        END
      FROM dbo.tbl_usuario u
      WHERE u.id_usuario = @userId;
    `);

  const refreshedUser = await getUserByIdentifier(user.usuario || user.email);
  const justLocked =
    previousAttempts + 1 >= MAX_FAILED_ATTEMPTS &&
    refreshedUser &&
    isLocked(refreshedUser);

  return {
    justLocked: Boolean(justLocked),
    user: refreshedUser,
  };
}

async function clearFailedLoginState(userId) {
  const connection = await getPool();

  await connection
    .request()
    .input("userId", sql.Int, userId)
    .query(`
      UPDATE dbo.tbl_usuario_seguridad
      SET
        failed_attempts = 0,
        lockout_until = NULL,
        updated_at = GETDATE(),
        last_login_at = GETDATE()
      WHERE id_usuario = @userId;

      UPDATE dbo.tbl_usuario
      SET
        intentos_fallidos = 0,
        bloqueado = 0
      WHERE id_usuario = @userId;
    `);
}

async function setPassword(user, plainPassword) {
  const connection = await getPool();
  const newHash = await bcrypt.hash(plainPassword, BCRYPT_ROUNDS);
  const expiresAt = buildPasswordExpiryDate();

  await connection
    .request()
    .input("userId", sql.Int, user.id_usuario)
    .input("passwordHash", sql.VarChar(255), newHash)
    .input("expiresAt", sql.DateTime, expiresAt)
    .query(`
      UPDATE dbo.tbl_usuario
      SET
        password_hash = @passwordHash,
        ultimo_cambio_password = CAST(GETDATE() AS DATE)
      WHERE id_usuario = @userId;

      UPDATE dbo.tbl_usuario_seguridad
      SET
        must_change_password = 0,
        password_changed_at = GETDATE(),
        password_expires_at = @expiresAt,
        recovery_password_hash = NULL,
        recovery_password_expires_at = NULL,
        reset_token_hash = NULL,
        reset_token_expires_at = NULL,
        updated_at = GETDATE()
      WHERE id_usuario = @userId;
    `);
}

async function setTemporaryPassword(user, temporaryPassword) {
  const connection = await getPool();
  const temporaryPasswordHash = await bcrypt.hash(temporaryPassword, BCRYPT_ROUNDS);
  const expiresAt = buildPasswordExpiryDate();

  await connection
    .request()
    .input("userId", sql.Int, user.id_usuario)
    .input("passwordHash", sql.VarChar(255), temporaryPasswordHash)
    .input("expiresAt", sql.DateTime, expiresAt)
    .query(`
      UPDATE dbo.tbl_usuario
      SET
        password_hash = @passwordHash,
        ultimo_cambio_password = CAST(GETDATE() AS DATE),
        intentos_fallidos = 0,
        bloqueado = 0
      WHERE id_usuario = @userId;

      UPDATE dbo.tbl_usuario_seguridad
      SET
        must_change_password = 1,
        password_changed_at = GETDATE(),
        password_expires_at = @expiresAt,
        recovery_password_hash = NULL,
        recovery_password_expires_at = NULL,
        reset_token_hash = NULL,
        reset_token_expires_at = NULL,
        failed_attempts = 0,
        lockout_until = NULL,
        updated_at = GETDATE()
      WHERE id_usuario = @userId;
    `);
}

async function authenticatePassword(identifier, plainPassword) {
  const user = await getUserByIdentifier(identifier);

  if (!user) {
    return { ok: false, status: 401, message: "Credenciales invalidas." };
  }

  if (!user.activo) {
    return { ok: false, status: 403, message: "Usuario inactivo." };
  }

  if (isLocked(user)) {
    return {
      ok: false,
      status: 423,
      message: "Usuario bloqueado temporalmente por intentos fallidos.",
      lockoutUntil: user.lockout_until,
    };
  }

  const validPassword = await bcrypt.compare(plainPassword, user.password_hash);

  if (!validPassword) {
    const failedLoginResult = await registerFailedLogin(user);

    if (failedLoginResult.justLocked && user.email) {
      try {
        await sendAccountLockedEmail({
          email: user.email,
          identifier: user.usuario || user.email,
          lockoutUntil: failedLoginResult.user?.lockout_until,
        });
      } catch (error) {
        console.error("No se pudo enviar el correo de bloqueo:", error.message);
      }
    }

    return { ok: false, status: 401, message: "Credenciales invalidas." };
  }

  return { ok: true, user };
}

async function getUserSessionById(userId) {
  const connection = await getPool();
  const result = await connection
    .request()
    .input("userId", sql.Int, userId)
    .query(`
      SELECT TOP 1
        u.id_usuario,
        u.usuario,
        u.nombres,
        u.apellidos,
        u.email,
        u.activo,
        s.must_change_password,
        s.password_expires_at,
        s.two_factor_enabled,
        s.last_login_at
      FROM dbo.tbl_usuario u
      LEFT JOIN dbo.tbl_usuario_seguridad s
        ON s.id_usuario = u.id_usuario
      WHERE u.id_usuario = @userId
    `);

  return result.recordset[0] || null;
}

function verifyAuth(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ message: "Token requerido." });
  }

  try {
    req.auth = jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    return res.status(401).json({ message: "Token invalido o expirado." });
  }
}

app.get("/health", async (_req, res) => {
  try {
    await getPool();
    return res.json({ ok: true, db: "connected" });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.get("/auth/session", verifyAuth, async (req, res) => {
  try {
    const user = await getUserSessionById(req.auth.sub);

    if (!user) {
      return res.status(404).json({ message: "Usuario no encontrado." });
    }

    if (!user.activo) {
      return res.status(403).json({ message: "Usuario inactivo." });
    }

    return res.json({
      message: "Sesion valida.",
      usuario: user.usuario,
      nombres: user.nombres,
      apellidos: user.apellidos,
      email: user.email,
      twoFactorEnabled: Boolean(user.two_factor_enabled),
      passwordExpired: isPasswordExpired(user),
      mustChangePassword: Boolean(user.must_change_password),
      lastLoginAt: user.last_login_at,
    });
  } catch (error) {
    return res.status(500).json({ message: "Error validando la sesion.", error: error.message });
  }
});

app.post("/auth/register", async (req, res) => {
  try {
    const { nombres, apellidos, email, usuario, telefono, password } = req.body;
    const idRol = 2;

    if (!nombres || !apellidos || !usuario || !password) {
      return res.status(400).json({ message: "Faltan campos obligatorios." });
    }

    const policyErrors = buildPasswordPolicyErrors(password, { usuario, email, nombres, apellidos });
    if (policyErrors.length > 0) {
      return res.status(400).json({ message: "La contrasena no cumple la politica.", errors: policyErrors });
    }

    const connection = await getPool();
    const exists = await connection
      .request()
      .input("usuario", sql.VarChar(100), usuario)
      .input("email", sql.VarChar(150), email || null)
      .query(`
        SELECT TOP 1 id_usuario
        FROM dbo.tbl_usuario
        WHERE usuario = @usuario OR (@email IS NOT NULL AND email = @email)
      `);

    if (exists.recordset.length > 0) {
      return res.status(409).json({ message: "El usuario o email ya existen." });
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const expiresAt = buildPasswordExpiryDate();

    const result = await connection
      .request()
      .input("idRol", sql.Int, idRol)
      .input("nombres", sql.VarChar(100), nombres)
      .input("apellidos", sql.VarChar(100), apellidos)
      .input("email", sql.VarChar(150), email || null)
      .input("usuario", sql.VarChar(100), usuario)
      .input("passwordHash", sql.VarChar(255), passwordHash)
      .input("telefono", sql.VarChar(20), telefono || null)
      .input("expiresAt", sql.DateTime, expiresAt)
      .query(`
        INSERT INTO dbo.tbl_usuario (
          id_rol,
          nombres,
          apellidos,
          email,
          usuario,
          password_hash,
          telefono,
          activo,
          intentos_fallidos,
          bloqueado,
          ultimo_cambio_password,
          fecha_creacion
        )
        OUTPUT INSERTED.id_usuario
        VALUES (
          @idRol,
          @nombres,
          @apellidos,
          @email,
          @usuario,
          @passwordHash,
          @telefono,
          1,
          0,
          0,
          CAST(GETDATE() AS DATE),
          GETDATE()
        );
      `);

    const userId = result.recordset[0].id_usuario;
    await ensureUserSecurityRow(userId);

    await connection
      .request()
      .input("userId", sql.Int, userId)
      .input("expiresAt", sql.DateTime, expiresAt)
      .query(`
        UPDATE dbo.tbl_usuario_seguridad
        SET
          password_changed_at = GETDATE(),
          password_expires_at = @expiresAt,
          updated_at = GETDATE()
        WHERE id_usuario = @userId;
      `);

    return res.status(201).json({
      message: "Usuario registrado correctamente.",
      userId,
    });
  } catch (error) {
    return res.status(500).json({ message: "Error registrando usuario.", error: error.message });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const { identifier, password } = req.body;

    if (!identifier || !password) {
      return res.status(400).json({ message: "Usuario/email y contrasena son obligatorios." });
    }

    const authResult = await authenticatePassword(identifier, password);
    if (!authResult.ok) {
      return res.status(authResult.status).json(authResult);
    }

    const { user } = authResult;

    if (user.two_factor_enabled) {
      const preAuthToken = generatePreAuthToken(user.id_usuario);
      return res.json({
        requiresTwoFactor: true,
        preAuthToken,
        message: "Se requiere codigo 2FA.",
      });
    }

    await clearFailedLoginState(user.id_usuario);

    return res.json({
      message: "Autenticacion exitosa.",
      accessToken: generateJwt(user),
      passwordExpired: isPasswordExpired(user),
      mustChangePassword: Boolean(user.must_change_password),
    });
  } catch (error) {
    return res.status(500).json({ message: "Error durante el login.", error: error.message });
  }
});

app.post("/auth/verify-2fa-login", async (req, res) => {
  try {
    const { preAuthToken, otp } = req.body;

    if (!preAuthToken || !otp) {
      return res.status(400).json({ message: "preAuthToken y otp son obligatorios." });
    }

    let payload;
    try {
      payload = jwt.verify(preAuthToken, JWT_SECRET);
    } catch (_error) {
      return res.status(401).json({ message: "preAuthToken invalido o expirado." });
    }

    if (payload.stage !== "pre-2fa") {
      return res.status(400).json({ message: "Token no valido para flujo 2FA." });
    }

    const connection = await getPool();
    const result = await connection
      .request()
      .input("userId", sql.Int, payload.sub)
      .query(`
        SELECT TOP 1
          u.id_usuario,
          u.id_rol,
          u.email,
          u.usuario,
          s.two_factor_enabled,
          s.authenticator_secret,
          s.must_change_password,
          s.password_expires_at
        FROM dbo.tbl_usuario u
        INNER JOIN dbo.tbl_usuario_seguridad s
          ON s.id_usuario = u.id_usuario
        WHERE u.id_usuario = @userId
      `);

    const user = result.recordset[0];

    if (!user || !user.two_factor_enabled || !user.authenticator_secret) {
      return res.status(400).json({ message: "El usuario no tiene 2FA configurado." });
    }

    const validOtp = speakeasy.totp.verify({
      secret: user.authenticator_secret,
      encoding: "base32",
      token: String(otp),
      window: 1,
    });

    if (!validOtp) {
      return res.status(401).json({ message: "Codigo 2FA invalido." });
    }

    await clearFailedLoginState(user.id_usuario);

    return res.json({
      message: "Autenticacion 2FA exitosa.",
      accessToken: generateJwt(user),
      passwordExpired: isPasswordExpired(user),
      mustChangePassword: Boolean(user.must_change_password),
    });
  } catch (error) {
    return res.status(500).json({ message: "Error verificando 2FA.", error: error.message });
  }
});

app.post("/auth/2fa/setup", verifyAuth, async (req, res) => {
  try {
    const connection = await getPool();
    const secret = speakeasy.generateSecret({
      name: `OptometriaMovil (${req.auth.usuario})`,
      issuer: "OptometriaMovil",
      length: 20,
    });

    await connection
      .request()
      .input("userId", sql.Int, req.auth.sub)
      .input("secret", sql.VarChar(128), secret.base32)
      .query(`
        UPDATE dbo.tbl_usuario_seguridad
        SET
          authenticator_secret = @secret,
          two_factor_enabled = 0,
          updated_at = GETDATE()
        WHERE id_usuario = @userId;
      `);

    return res.json({
      message: "Escanea este secreto en Google Authenticator, Microsoft Authenticator o Authy.",
      secret: secret.base32,
      otpauthUrl: secret.otpauth_url,
    });
  } catch (error) {
    return res.status(500).json({ message: "Error configurando 2FA.", error: error.message });
  }
});

app.post("/auth/2fa/confirm", verifyAuth, async (req, res) => {
  try {
    const { otp } = req.body;

    if (!otp) {
      return res.status(400).json({ message: "El otp es obligatorio." });
    }

    const connection = await getPool();
    const result = await connection
      .request()
      .input("userId", sql.Int, req.auth.sub)
      .query(`
        SELECT TOP 1 authenticator_secret
        FROM dbo.tbl_usuario_seguridad
        WHERE id_usuario = @userId
      `);

    const record = result.recordset[0];
    if (!record || !record.authenticator_secret) {
      return res.status(400).json({ message: "Primero debes iniciar la configuracion de 2FA." });
    }

    const validOtp = speakeasy.totp.verify({
      secret: record.authenticator_secret,
      encoding: "base32",
      token: String(otp),
      window: 1,
    });

    if (!validOtp) {
      return res.status(401).json({ message: "Codigo 2FA invalido." });
    }

    await connection
      .request()
      .input("userId", sql.Int, req.auth.sub)
      .query(`
        UPDATE dbo.tbl_usuario_seguridad
        SET
          two_factor_enabled = 1,
          updated_at = GETDATE()
        WHERE id_usuario = @userId
      `);

    return res.json({ message: "2FA activado correctamente." });
  } catch (error) {
    return res.status(500).json({ message: "Error activando 2FA.", error: error.message });
  }
});

app.post("/auth/request-password-reset", async (req, res) => {
  try {
    const { identifier } = req.body;

    if (!identifier) {
      return res.status(400).json({ message: "Debes enviar usuario o email." });
    }

    const user = await getUserByIdentifier(identifier);
    if (!user) {
      return res.json({
        message: "Si el usuario existe, se ha generado el flujo de recuperacion.",
      });
    }

    const temporaryPassword = generateTemporaryPassword();
    await setTemporaryPassword(user, temporaryPassword);

    if (user.email) {
      await sendTemporaryPasswordEmail({
        email: user.email,
        identifier: user.usuario || user.email,
        temporaryPassword,
      });
    }

    return res.json({
      message: user.email
        ? "Clave temporal enviada al correo del usuario."
        : "El usuario no tiene email registrado. Se genero una clave temporal, pero no se pudo enviar correo.",
    });
  } catch (error) {
    return res.status(500).json({ message: "Error generando recuperacion.", error: error.message });
  }
});

app.post("/auth/change-password", verifyAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: "Debes enviar currentPassword y newPassword." });
    }

    const connection = await getPool();
    const result = await connection
      .request()
      .input("userId", sql.Int, req.auth.sub)
      .query(`
        SELECT TOP 1
          u.id_usuario,
          u.nombres,
          u.apellidos,
          u.email,
          u.usuario,
          u.password_hash
        FROM dbo.tbl_usuario u
        WHERE u.id_usuario = @userId
      `);

    const user = result.recordset[0];
    if (!user) {
      return res.status(404).json({ message: "Usuario no encontrado." });
    }

    const validPassword = await bcrypt.compare(currentPassword, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ message: "La contrasena actual es incorrecta." });
    }

    const policyErrors = buildPasswordPolicyErrors(newPassword, user);
    if (policyErrors.length > 0) {
      return res.status(400).json({ message: "La contrasena no cumple la politica.", errors: policyErrors });
    }

    const sameAsCurrent = await bcrypt.compare(newPassword, user.password_hash);
    if (sameAsCurrent) {
      return res.status(400).json({ message: "La nueva contrasena no puede ser igual a la actual." });
    }

    await setPassword(user, newPassword);

    return res.json({ message: "Contrasena actualizada correctamente." });
  } catch (error) {
    return res.status(500).json({ message: "Error cambiando contrasena.", error: error.message });
  }
});

app.get("/auth/password-policy", (_req, res) => {
  return res.json({
    minLength: 12,
    requiresUppercase: true,
    requiresLowercase: true,
    requiresNumber: true,
    requiresSpecialChar: true,
    disallowPersonalData: true,
    expiresInDays: PASSWORD_EXPIRY_DAYS,
    maxFailedAttempts: MAX_FAILED_ATTEMPTS,
    lockoutMinutes: LOCKOUT_MINUTES,
    twoFactorSupported: true,
  });
});

async function start() {
  try {
    await getPool();
    await ensureSecuritySchema();
    app.listen(PORT, () => {
      console.log(`Auth server ejecutandose en http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error("No se pudo iniciar el servidor:", error);
    process.exit(1);
  }
}

start();
