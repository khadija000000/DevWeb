// src/middleware/auth.js
import jwt from 'jsonwebtoken';

const SECRET = 'inpt_secret_key';

export function verify(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "unauthorized" });
  }

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ error: "invalid_token" });
  }
}

export function onlyOrganizer(req, res, next) {
  if (req.user?.role !== 'organizer') {
    return res.status(403).json({ error: "forbidden" });
  }
  next();
}
