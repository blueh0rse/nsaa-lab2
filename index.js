// Imports
const express = require("express");
const logger = require("morgan");
const passport = require("passport");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const https = require("https");
const fs = require("fs");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const scrypt = require("scrypt-js");
const LocalStrategy = require("passport-local").Strategy;
const JwtStrategy = require("passport-jwt").Strategy;

// Initialize Express app and set port
const app = express();
const port = 3000;
const jwtSecret = require("crypto").randomBytes(16);

// Database setup: Connect to SQLite and create users table if it doesn't exist
const db = new sqlite3.Database("users.db", (err) => {
  if (err) throw err;
  db.run(
    "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password TEXT NOT NULL, role TEXT NOT NULL)"
  );
});

// Server options for HTTPS
const options = {
  key: fs.readFileSync("server.key"),
  cert: fs.readFileSync("server.cert"),
};

// Middleware
app.use(bodyParser.json());
app.use(logger("dev"));
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize());

// Password hashing function using scrypt
async function hashPassword(password, user_role) {
  const passwordBuffer = Buffer.from(password);
  const salt = Buffer.from("some_random_salt");
  const fastKDFParams = {
    N: 16384, // Lower cost parameter for fast setup
    r: 8, // Block size parameter
    p: 1, // Parallelization parameter
    dkLen: 32,
  };
  const slowKDFParams = {
    N: 1048576, // Higher cost parameter for slow setup
    r: 8, // Block size parameter
    p: 1, // Parallelization parameter
    dkLen: 32,
  };
  // fast by default
  const params = user_role === "admin" ? slowKDFParams : fastKDFParams;
  console.log(`user_role ${user_role}`);
  const hash = await scrypt.scrypt(
    passwordBuffer,
    salt,
    params.N,
    params.r,
    params.p,
    params.dkLen
  );
  return Buffer.from(hash).toString("hex");
}

// Password verification function
async function verifyPassword(storedHash, providedPassword, user_role) {
  const providedHash = await hashPassword(providedPassword, user_role);
  return storedHash === providedHash;
}

// Passport local strategy for username and password login
passport.use(
  "username-password",
  new LocalStrategy(
    {
      usernameField: "username",
      passwordField: "password",
      session: false,
    },
    (username, password, done) => {
      db.get(
        "SELECT username, password, role FROM users WHERE username = ?",
        [username],
        async (err, row) => {
          if (err) return done(err);
          if (!row)
            return done(null, false, { message: "Incorrect username." });
          console.log(`row.role ${row.role}`);
          if (await verifyPassword(row.password, password, row.role)) {
            return done(null, { username: row.username });
          } else {
            return done(null, false, { message: "Incorrect password." });
          }
        }
      );
    }
  )
);

// JWT strategy for cookie-stored token verification
passport.use(
  "jwtCookie",
  new JwtStrategy(
    {
      jwtFromRequest: (req) => (req && req.cookies ? req.cookies.jwt : null),
      secretOrKey: jwtSecret.toString("hex"),
    },
    (jwtPayload, done) => {
      if (jwtPayload.sub) {
        return done(null, {
          username: jwtPayload.sub,
          role: jwtPayload.role ?? "user",
        });
      }
      return done(null, false);
    }
  )
);

// Routes
// Home page, protected by JWT
app.get(
  "/",
  passport.authenticate("jwtCookie", {
    session: false,
    failureRedirect: "/login",
  }),
  (req, res) => {
    res.send(`Welcome to your private page, ${req.user.username}!`);
  }
);

// Login page
app.get("/login", (req, res) => {
  res.sendFile("login.html", { root: __dirname });
});

// Login handler
app.post(
  "/login",
  passport.authenticate("username-password", {
    failureRedirect: "/login",
    session: false,
  }),
  (req, res) => {
    const jwtClaims = {
      sub: req.user.username,
      iss: "localhost:3000",
      aud: "localhost:3000",
      exp: Math.floor(Date.now() / 1000) + 604800,
      role: req.user.role,
    };
    const token = jwt.sign(jwtClaims, jwtSecret.toString("hex"));
    res.cookie("jwt", token, { httpOnly: true, secure: false });
    res.redirect("/");
  }
);

// Logout handler
app.get("/logout", (req, res) => {
  res.clearCookie("jwt", { httpOnly: true, secure: false });
  res.redirect("/login");
});

// User registration
app.post("/register", async (req, res) => {
  const { username, password, role } = req.body;
  const passwordHash = await hashPassword(password, role);
  db.run(
    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
    [username, passwordHash, role],
    function (err) {
      if (err) res.status(400).json({ error: err.message });
      else res.status(201).json({ userId: this.lastID });
    }
  );
});

// Error handling middleware
app.use((err, req, res, next) => {
  res.status(500).send("Something broke!");
});

// Start the server
app.listen(port, () => {
  console.log(`App listening at http://localhost:${port}`);
});

// Optional: HTTPS server setup
// https.createServer(options, app).listen(3001, () => {
//   console.log("HTTPS server running on https://localhost:3001");
// });
