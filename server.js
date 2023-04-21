require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();

// parses incoming JSON payloads and makes the resulting data available on the request.body property of the incoming request object.
app.use(express.json());

const posts = [
  {
    username: "Kyle",
    title: "Post 1",
  },
  {
    username: "Jim",
    title: "Post 2",
  },
];

// we added authenticateToken middleware to use it there
app.get("/posts", authenticateToken, (req, res) => {
  // filtering to be able to return only the post user has access to
  res.json(posts.filter((post) => post.username === req.user.name));
});

// middleware that is going to authenticate our token
function authenticateToken(req, res, next) {
  // Bearer TOKEN
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  // control if we have a valid token
  if (token === null) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    // 403 is saying token is here but no longer valid so user does not have access
    if (err) return res.sendStatus(403);
    // then if we get passed all controls, we should have a valid token
    // setting the user
    req.user = user;
    next();
  });
}

app.listen(5000);
