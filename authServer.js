require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();

// parses incoming JSON payloads and makes the resulting data available on the request.body property of the incoming request object.
app.use(express.json());

let refreshTokens = [];

// creates a new token
app.post("/token", (req, res) => {
  const refreshToken = req.body.token;
  // 401 status if token does not exist
  if (refreshToken === null) return res.sendStatus(401);
  // 403 status if token has not been refreshed (?)
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);
  // then if we get passed the two first controls, we can control our token is valid
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = generateAccessToken({ name: user.name });
    res.json({ accessToken: accessToken });
  });
});

// de-authenticates refresh tokens to prevent users to create infinite access as long as they have refresh tokens
app.delete("/logout", (req, res) => {
  refreshTokens = refreshTokens.filter((token) => token !== req.body.token);
  res.sendStatus(204);
});

// creates a specific route for user to login so we can chose who can see posts
app.post("/login", (req, res) => {
  // create JWT
  const username = req.body.username;
  const user = { name: username };

  // CREATE ACCESS TOKEN WITHOUT GENERATING IT
  // const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);

  // CREATE ACCESS TOKEN BY GENERATING IT
  const accessToken = generateAccessToken(user);

  // CREATE REFRESH TOKEN
  // we manually handle its expiration time
  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);

  // everytime we create a token, we want to store it by pushing it into the array
  refreshTokens.push(refreshToken);

  res.json({ accessToken: accessToken, refreshToken: refreshToken });
});

// we generate access token so it cannot always be the same
function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "30s" });
}

app.listen(6000);
