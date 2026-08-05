const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const { router: authRouter, attachUser } = require('./auth');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cookieParser());
app.use(attachUser); // sets req.user from the session cookie on every request

// Auth API
app.use('/api/auth', authRouter);

app.use(express.static(path.join(__dirname, 'public')));

// SPA fallback — but never swallow unknown API routes.
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`LyricQ running on port ${PORT}`);
});
