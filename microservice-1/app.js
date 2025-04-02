import express from "express";
import jwt from "jsonwebtoken";

const app = express();
const SECRET_KEY = "supersecret";

function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Invalid token" });
    req.user = decoded;
    next();
  });
}

app.get("/hello", verifyToken, (req, res) => {
  res.json({ message: "Welcome to Microservice 1", user: req.user.username });
});

app.listen(3001, () => console.log("Microservice 1 running"));

