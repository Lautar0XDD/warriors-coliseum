const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
const SECRET = process.env.JWT_SECRET || "warriors_secret_key_change_in_prod";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(cors());
app.use(express.json());
app.use(express.static("public"));

// ── Crear tablas ──────────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS stats (
      user_id INTEGER PRIMARY KEY REFERENCES users(id),
      wins INTEGER DEFAULT 0,
      losses INTEGER DEFAULT 0
    );
  `);
  console.log("Base de datos lista");
}

// ── Middleware auth ───────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token requerido" });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Token inválido" });
  }
}

// ── REGISTRO ──────────────────────────────────────────────────
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "Usuario y contraseña requeridos" });
  if (username.length < 3)
    return res.status(400).json({ error: "Usuario muy corto (mín. 3 caracteres)" });
  if (password.length < 4)
    return res.status(400).json({ error: "Contraseña muy corta (mín. 4 caracteres)" });

  try {
    const hash = bcrypt.hashSync(password, 10);
    const result = await pool.query(
      "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id",
      [username, hash]
    );
    await pool.query("INSERT INTO stats (user_id) VALUES ($1)", [result.rows[0].id]);
    res.json({ message: "Cuenta creada exitosamente" });
  } catch (e) {
    if (e.code === "23505")
      return res.status(400).json({ error: "Ese nombre de usuario ya existe" });
    res.status(500).json({ error: "Error del servidor" });
  }
});

// ── LOGIN ─────────────────────────────────────────────────────
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
  const user = result.rows[0];
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: "Usuario o contraseña incorrectos" });

  const token = jwt.sign({ id: user.id, username: user.username }, SECRET, { expiresIn: "7d" });
  res.json({ token, username: user.username });
});

// ── PERFIL ────────────────────────────────────────────────────
app.get("/api/profile", authMiddleware, async (req, res) => {
  const result = await pool.query("SELECT wins, losses FROM stats WHERE user_id = $1", [req.user.id]);
  const stats = result.rows[0];
  const total = stats.wins + stats.losses;
  const winrate = total > 0 ? Math.round((stats.wins / total) * 100) : 0;
  res.json({ username: req.user.username, wins: stats.wins, losses: stats.losses, winrate });
});

// ── GUARDAR RESULTADO ─────────────────────────────────────────
app.post("/api/match", authMiddleware, async (req, res) => {
  const { winner, loser } = req.body;
  if (!winner || !loser)
    return res.status(400).json({ error: "Se requiere winner y loser" });

  const w = await pool.query("SELECT id FROM users WHERE username = $1", [winner]);
  const l = await pool.query("SELECT id FROM users WHERE username = $1", [loser]);

  if (!w.rows[0] || !l.rows[0])
    return res.status(404).json({ error: "Uno o ambos usuarios no existen" });

  await pool.query("UPDATE stats SET wins = wins + 1 WHERE user_id = $1", [w.rows[0].id]);
  await pool.query("UPDATE stats SET losses = losses + 1 WHERE user_id = $1", [l.rows[0].id]);

  res.json({ message: "Resultado guardado" });
});

// ── RANKING ───────────────────────────────────────────────────
app.get("/api/ranking", async (req, res) => {
  const result = await pool.query(`
    SELECT u.username, s.wins, s.losses,
      ROUND(CAST(s.wins AS FLOAT) / GREATEST(s.wins + s.losses, 1) * 100) as winrate
    FROM users u
    JOIN stats s ON u.id = s.user_id
    ORDER BY s.wins DESC, winrate DESC
    LIMIT 50
  `);
  res.json(result.rows);
});

// ── START ─────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
initDB().then(() => {
  app.listen(PORT, () => console.log(`Warriors Coliseum API corriendo en puerto ${PORT}`));
});
