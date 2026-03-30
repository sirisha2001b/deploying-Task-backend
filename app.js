const express = require("express");
const sqlite3 = require("sqlite3");
const { open } = require("sqlite");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const path = require("path");

const dbPath = path.join(__dirname, "taskManager.db");
const app = express();

app.use(express.json());

let db = null;

// -------------------- DB + SERVER --------------------
const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });

    await db.exec(`
      CREATE TABLE IF NOT EXISTS user (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'user'
      );

      CREATE TABLE IF NOT EXISTS task (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        completed BOOLEAN DEFAULT 0,
        user_id INTEGER
      );
    `);

    app.listen(3000, () => {
      console.log("Server running at http://localhost:3000");
    });
  } catch (e) {
    console.log(e.message);
  }
};

initializeDbAndServer();

// -------------------- JWT --------------------
const authenticateToken = (req, res, next) => {
  const auth = req.headers["authorization"];
  if (!auth) return res.status(401).send("Invalid JWT Token");

  const token = auth.split(" ")[1];

  jwt.verify(token, "SECRET_KEY", (err, payload) => {
    if (err) return res.status(401).send("Invalid JWT Token");
    req.user = payload;
    next();
  });
};

// -------------------- REGISTER --------------------
app.post("/register/", async (req, res) => {
  const { username, password } = req.body;

  const user = await db.get(
    "SELECT * FROM user WHERE username = ?",
    username
  );

  if (user) return res.status(400).send("User exists");

  const hash = await bcrypt.hash(password, 10);

  await db.run(
    "INSERT INTO user (username, password) VALUES (?, ?)",
    [username, hash]
  );

  res.send("User created");
});

// -------------------- LOGIN --------------------
app.post("/login/", async (req, res) => {
  const { username, password } = req.body;

  const user = await db.get(
    "SELECT * FROM user WHERE username = ?",
    username
  );

  if (!user) return res.status(400).send("Invalid user");

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) return res.status(400).send("Invalid password");

  const payload = {
    userId: user.id,
    username: user.username,
  };

  const jwtToken = jwt.sign(payload, "SECRET_KEY");

  res.send({ jwtToken });
});

// -------------------- TASKS --------------------
app.get("/tasks/", authenticateToken, async (req, res) => {
  const tasks = await db.all(
    "SELECT * FROM task WHERE user_id = ?",
    req.user.userId
  );
  res.send(tasks);
});

app.post("/tasks/", authenticateToken, async (req, res) => {
  const { title } = req.body;

  await db.run(
    "INSERT INTO task (title, user_id) VALUES (?, ?)",
    [title, req.user.userId]
  );

  res.send("Task added");
});

app.delete("/tasks/:id/", authenticateToken, async (req, res) => {
  await db.run(
    "DELETE FROM task WHERE id = ? AND user_id = ?",
    [req.params.id, req.user.userId]
  );

  res.send("Deleted");
});