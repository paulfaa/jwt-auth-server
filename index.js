const express = require('express');
const multer = require('multer');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const z = require('zod');
const { playlistSchema, parsedImageSchema } = require('./schema');
const { query } = require('./query');
const { OpenAI } = require('openai');
const { zodTextFormat } = require('openai/helpers/zod');
const { connectToDb, mongoClient } = require('./db');
const { loadAllSecrets, getSecret } = require('./secrets');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT;

const JWT_EXPIRATION = process.env.JWT_EXPIRATION;
const upload = multer({ storage: multer.memoryStorage() });

(async () => {
  await loadAllSecrets();
  db = await connectToDb();
  const openai = new OpenAI({ apiKey: getSecret('openai-api-key') });


  app.use(cors({
    origin: 'http://localhost:4200',
    credentials: true
  }));
  app.use(bodyParser.json());
  app.use(express.json());
  app.use(cookieParser());

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
    console.log('/check - user is authenticated');

    res.status(200).json({
      authenticated: true,
      role: req.user.role,
    });
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
    try {
      const imageBuffer = req.file.buffer;
      const base64Image = imageBuffer.toString('base64');
      const mimeType = req.file.mimetype;
      const dataUrl = `data:${mimeType};base64,${base64Image}`;

      const response = await openai.responses.parse({
        model: "gpt-4o-mini",
        input: [
          {
            role: "system",
            content: query
          },
          {
            role: "user",
            content: [
              {
                type: "input_image",
                image_url: dataUrl,
              },
            ],
          },
        ],
        text: { format: zodTextFormat(parsedImageSchema, "result") },
      });
      const result = response.output_parsed;
      console.log('Parsed result:', result);
      res.status(200).json(result);
    }
    catch (error) {
      console.error('Error processing image:', error);
      res.status(500).json({ error: 'Failed to process image' });
    }
  });

  app.post('/save', authenticateToken, async (req, res) => {
    console.log('/save endpoint received payload:', req.body);
    const parseResult = playlistSchema.safeParse(req.body);

    if (!parseResult.success) {
      return res.status(400).json({
        error: 'Invalid payload',
        details: parseResult.error.flatten(),
      });
    }

    console.log('/save endpoint received valid payload:', parseResult.data);

    sample = {
      playlistName: 'Test Playlist',
      playlistDate: '2023-10-31',
      numberOfEvents: 12,
      numberOfPlayers: 8,
      uploadDate: '2025-02-01',
      uploadedBy: 'Admin',
      players: [
        {
          name: 'Player1',
          lastEventPoints: 15,
          totalPoints: 153,
        },
        {
          name: 'Player2',
          lastEventPoints: 12,
          totalPoints: 144,
        }
      ]
    }

    //need to query DB first to see if playlist already exists for the given date
    try {
      const existingPlaylist = await collection.findOne({ playlistDate: sample.playlistDate });
      if (existingPlaylist) {
        console.log(`Playlist for date ${sample.playlistDate} already exists. Not inserting.`);
        return res.status(400).json({ error: 'Playlist for this date already exists.' });
      }
    }
    catch (err) {
      console.error(`Something went wrong trying to find existing playlist: ${err}\n`);
      return res.status(500).json({ error: 'Internal server error' });
    }

    try {
      const insertResult = await collection.insertOne(sample);
      return res.status(201).json({ message: `Playlist ${insertResult.name} saved successfully` });
    } catch (err) {
      console.error(`Something went wrong trying to insert the new document: ${err}\n`);
    }

    res.status(200).json(sample);
  });

  app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));

})();

process.on('SIGINT', async () => {
  console.log('\nClosing MongoDB connection...');
  await getMongoClient().close();
  process.exit(0);
});

