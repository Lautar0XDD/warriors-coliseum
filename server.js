const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
const db = new Database("warriors.db");
const SECRET = process.env.JWT_SECRET || "warriors_secret_key_change_in_prod";

app.use(cors());
app.use(express.json());
app.use(express.static("public"));

// ── Crear tablas ──────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS stats (
    user_id INTEGER PRIMARY KEY,
    wins INTEGER DEFAULT 0,
    losses INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

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
app.post("/api/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "Usuario y contraseña requeridos" });
  if (username.length < 3)
    return res.status(400).json({ error: "Usuario muy corto (mín. 3 caracteres)" });
  if (password.length < 4)
    return res.status(400).json({ error: "Contraseña muy corta (mín. 4 caracteres)" });

  try {
    const hash = bcrypt.hashSync(password, 10);
    const stmt = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    const result = stmt.run(username, hash);
    db.prepare("INSERT INTO stats (user_id) VALUES (?)").run(result.lastInsertRowid);
    res.json({ message: "Cuenta creada exitosamente" });
  } catch (e) {
    if (e.message.includes("UNIQUE"))
      return res.status(400).json({ error: "Ese nombre de usuario ya existe" });
    res.status(500).json({ error: "Error del servidor" });
  }
});

// ── LOGIN ─────────────────────────────────────────────────────
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: "Usuario o contraseña incorrectos" });

  const token = jwt.sign({ id: user.id, username: user.username }, SECRET, { expiresIn: "7d" });
  res.json({ token, username: user.username });
});

// ── PERFIL ────────────────────────────────────────────────────
app.get("/api/profile", authMiddleware, (req, res) => {
  const stats = db
    .prepare("SELECT wins, losses FROM stats WHERE user_id = ?")
    .get(req.user.id);
  const total = stats.wins + stats.losses;
  const winrate = total > 0 ? Math.round((stats.wins / total) * 100) : 0;
  res.json({
    username: req.user.username,
    wins: stats.wins,
    losses: stats.losses,
    winrate,
  });
});

// ── GUARDAR RESULTADO DE PARTIDA ───────────────────────────────
// Llamado desde TurboWarp después de cada pelea
// Body: { winner: "nombreGanador", loser: "nombrePerdedor" }
app.post("/api/match", authMiddleware, (req, res) => {
  const { winner, loser } = req.body;
  if (!winner || !loser)
    return res.status(400).json({ error: "Se requiere winner y loser" });

  const winnerUser = db.prepare("SELECT id FROM users WHERE username = ?").get(winner);
  const loserUser = db.prepare("SELECT id FROM users WHERE username = ?").get(loser);

  if (!winnerUser || !loserUser)
    return res.status(404).json({ error: "Uno o ambos usuarios no existen" });

  db.prepare("UPDATE stats SET wins = wins + 1 WHERE user_id = ?").run(winnerUser.id);
  db.prepare("UPDATE stats SET losses = losses + 1 WHERE user_id = ?").run(loserUser.id);

  res.json({ message: "Resultado guardado" });
});

// ── RANKING ───────────────────────────────────────────────────
app.get("/api/ranking", (req, res) => {
  const rows = db
    .prepare(
      `SELECT u.username, s.wins, s.losses,
        ROUND(CAST(s.wins AS FLOAT) / MAX(s.wins + s.losses, 1) * 100) as winrate
       FROM users u
       JOIN stats s ON u.id = s.user_id
       ORDER BY s.wins DESC, winrate DESC
       LIMIT 50`
    )
    .all();
  res.json(rows);
});

// ── START ─────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Warriors Coliseum API corriendo en puerto ${PORT}`));
