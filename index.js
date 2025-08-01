const express = require('express');
const multer = require('multer');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT;

const USER_PASSWORD = process.env.USER_PASSWORD;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRATION = process.env.JWT_EXPIRATION;

app.use(cors({
  origin: 'http://localhost:4200',
  credentials: true
}));
app.use(bodyParser.json());
app.use(cookieParser());

const upload = multer({ storage: multer.memoryStorage() });

app.post('/login', (req, res) => {
  const { password } = req.body;
  let role = null;
  
  if (password === ADMIN_PASSWORD) {
    role = 'admin';
  } else if (password === USER_PASSWORD) {
    role = 'user';
  }
  
  if (role) {
    const token = jwt.sign({ role: role }, JWT_SECRET, { expiresIn: JWT_EXPIRATION });
    res.cookie('token', token, {
      httpOnly: true,
      secure: false, //update later after testing
      sameSite: 'Lax',
      maxAge: 30 * 60 * 1000
    });
    res.status(200).json({ success: true, role: role });
    console.log(`User logged in successfully as ${role}`);
  } else {
    res.status(401).json({ message: 'Unauthorized' });
    console.log('Login failed - invalid password');
  }
});

app.get('/check', authenticateToken, (req, res) => {
  res.status(200).json({ authenticated: true });
  console.log('User is authenticated');
});

function authenticateToken(req, res, next) {
  const token = req.cookies.token;
  if (!token) {
    console.log('Authentication failed: No token provided');
    return res.sendStatus(401);
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log('Authentication failed: Invalid or expired token');
      return res.sendStatus(403);
    }
    req.user = user;
    console.log('Authentication successful');
    next();
  });
}

app.post('/upload', authenticateToken, upload.single('image'), async (req, res) => {
  const imageBuffer = req.file.buffer;

  const result = { text: 'call API here' };

  res.status(200).json({ result: result });
});

app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
