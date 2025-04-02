import express from "express";
import jwt from "jsonwebtoken";
import axios from "axios";

const app = express();
const SECRET_KEY = "supersecret";
const USER_SERVICE_URL = "http://user-service:3000"; // URL for User Service in Docker

// Middleware to verify JWT token
function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Invalid token" });
    req.user = decoded;
    next();
  });
}

// Fetch user details from User Service
app.get("/user/:username", verifyToken, async (req, res) => {
  try {
    const { username } = req.params;
    const response = await axios.get(`${USER_SERVICE_URL}/profile/${username}`);
    res.json(response.data);
  } catch (error) {
    res.status(error.response?.status || 500).json({ error: "Failed to fetch user details" });
  }
});

app.listen(3002, () => console.log("Microservice 2 running on port 3002"));
