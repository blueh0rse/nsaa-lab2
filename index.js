// **********
// IMPORTS
// **********
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
const dotenv = require("dotenv");
dotenv.config();
const axios = require("axios");

// **********
// EXPRESS
// **********
const app = express();
const port = 3000;
const jwtSecret = require("crypto").randomBytes(16);

// **********
// DATABASE
// **********
const db = new sqlite3.Database("users.db", (err) => {
  if (err) throw err;
  db.run(
    "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password TEXT NOT NULL, role TEXT NOT NULL)"
  );
});

// Server options for HTTPS
// const options = {
//   key: fs.readFileSync("server.key"),
//   cert: fs.readFileSync("server.cert"),
// };

// **********
// MIDDLEWARES
// **********
app.use(bodyParser.json());
app.use(logger("dev"));
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize());

// **********
// FUNC: HASH PASSWORD - scrypt
// **********
async function hashPassword(password, user_role) {
  console.log("hashPassword()");
  const passwordBuffer = Buffer.from(password);
  const salt = Buffer.from("some_random_salt");
  // Lower cost parameter for fast setup
  const fastKDFParams = {
    N: 16384,
    r: 8,
    p: 1,
    dkLen: 32,
  };
  // Higher cost parameter for slow setup
  const slowKDFParams = {
    N: 1048576,
    r: 8,
    p: 1,
    dkLen: 32,
  };
  // fast by default
  const params = user_role === "admin" ? slowKDFParams : fastKDFParams;
  console.log(`Selecting parameters for role: ${user_role}`);
  console.log("Starting to hash...");
  const hash = await scrypt.scrypt(
    passwordBuffer,
    salt,
    params.N,
    params.r,
    params.p,
    params.dkLen
  );
  console.log("Hashing complete!");
  return Buffer.from(hash).toString("hex");
}

// **********
// FUNC: VERIFY PASSWORD
// **********
async function verifyPassword(storedHash, providedPassword, user_role) {
  console.log("verifyPassword()");
  const providedHash = await hashPassword(providedPassword, user_role);
  return storedHash === providedHash;
}

// **********
// STRAT: USERNAME:PASSWORD LOCAL
// **********
passport.use(
  "username-password",
  new LocalStrategy(
    {
      usernameField: "username",
      passwordField: "password",
      session: false,
    },
    (username, password, done) => {
      console.log("Strategy: username-password");
      db.get(
        "SELECT username, password, role FROM users WHERE username = ?",
        [username],
        async (err, row) => {
          if (err) return done(err);
          if (!row)
            return done(null, false, { message: "Incorrect username." });
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

// **********
// STRAT: JWT COOKIE
// **********
passport.use(
  "jwtCookie",
  new JwtStrategy(
    {
      jwtFromRequest: (req) => (req && req.cookies ? req.cookies.jwt : null),
      secretOrKey: jwtSecret.toString("hex"),
    },
    (jwtPayload, done) => {
      console.log("Strategy: jwtCookie");
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

// **********
// ROUTES
// **********

// HOME: GET /
app.get(
  "/",
  passport.authenticate("jwtCookie", {
    session: false,
    failureRedirect: "/login",
  }),
  (req, res) => {
    console.log("GET /");
    res.send(`Welcome to your private page, ${req.user.username}!`);
  }
);

// LOGIN: GET /LOGIN
app.get("/login", (req, res) => {
  console.log("GET /login");
  res.sendFile("login.html", { root: __dirname });
});

// LOGIN: POST /LOGIN
app.post(
  "/login",
  passport.authenticate("username-password", {
    failureRedirect: "/login",
    session: false,
  }),
  (req, res) => {
    console.log("POST /login");
    const jwtClaims = {
      sub: req.user.username,
      iss: "localhost:3000",
      aud: "localhost:3000",
      exp: Math.floor(Date.now() / 1000) + 604800,
      role: req.user.role,
    };
    const token = jwt.sign(jwtClaims, jwtSecret.toString("hex"));
    console.log(`token: ${token}`);
    res.cookie("jwt", token, { httpOnly: true, secure: false });
    res.redirect("/");
  }
);

// LOGOUT: GET /LOGOUT
app.get("/logout", (req, res) => {
  console.log("GET logout/");
  res.clearCookie("jwt", { httpOnly: true, secure: false });
  res.redirect("/login");
});

// REGISTER: GET /REGISTER
app.post("/register", async (req, res) => {
  console.log("POST /register");
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

// 5.4

app.get("/oauth2cb", async (req, res) => {
  /**
   * 1. Retrieve the authorization code from the query parameters
   */
  const code = req.query.code; // Here we have the received code
  if (code === undefined) {
    const err = new Error("no code provided");
    err.status = 400; // Bad Request
    throw err;
  }

  /**
   * 2. Exchange the authorization code for an actual access token at OUATH2_TOKEN_URL
   */
  const tokenResponse = await axios.post(process.env.OAUTH2_TOKEN_URL, {
    client_id: process.env.OAUTH2_CLIENT_ID,
    client_secret: process.env.OAUTH2_CLIENT_SECRET,
    code,
  });

  // response.data contains the params of the response, including access_token, scopes granted by the use and type.
  console.log(tokenResponse.data);

  // Let us parse them and get the access token and the scope
  const params = new URLSearchParams(tokenResponse.data);
  const accessToken = params.get("access_token");
  const scope = params.get("scope");

  // if the scope does not include what we wanted, authorization fails
  if (scope !== "user:email") {
    console.log(scope);
    const err = new Error("user did not consent to release email");
    err.status = 401; // Unauthorized
    throw err;
  }

  /**
   * 3. Use the access token to retrieve the user email from the USER_API endpoint
   */
  const userDataResponse = await axios.get(process.env.USER_API, {
    headers: {
      Authorization: `Bearer ${accessToken}`, // we send the access token as a bearer token in the authorization header
    },
  });
  console.log(userDataResponse.data);

  /**
   * 4. Create our JWT using the github email as subject, and set the cookie.
   */
  const jwtClaims = {
    sub: userDataResponse.data.email,
    iss: "localhost:3000",
    aud: "localhost:3000",
    exp: Math.floor(Date.now() / 1000) + 604800,
    role: "user",
  };
  const token = jwt.sign(jwtClaims, jwtSecret.toString("hex"));
  console.log(`token: ${token}`);
  res.cookie("jwt", token, { httpOnly: true, secure: false });
  res.redirect("/");
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.log("ERROR!");
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
