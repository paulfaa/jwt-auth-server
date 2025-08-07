import express from 'express';
import multer from 'multer';
import cors from 'cors';
import bodyParser from 'body-parser';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { playlistSchema, parsedImageSchema } from './schema.js';
import { query } from './query.js';
import { OpenAI } from 'openai';
import { zodTextFormat } from 'openai/helpers/zod';
import { connectToDb } from './db.js';
import { loadAllSecrets, getSecret } from './secrets.js';
import dotenv from 'dotenv';
dotenv.config();

const app = express();
const port = process.env.PORT;
const JWT_EXPIRATION = process.env.JWT_EXPIRATION;
const upload = multer({ storage: multer.memoryStorage() });
let db;

(async () => {
  await loadAllSecrets();
  db = await connectToDb();
  const collection = db.collection('playlists');
  const openai = new OpenAI({ apiKey: getSecret('openai-api-key') });
  const adminPassword = getSecret('admin-password');
  const userPassword = getSecret('user-password');
  const JWT_SECRET = getSecret('jwt-secret');

  if (process.env.NODE_ENV === 'DEV') {
    app.use(cors({
      origin: 'http://localhost:4200',
      credentials: true
    }));
  }
  if (process.env.NODE_ENV === 'PROD') {
    app.use(cors({
      origin: 'http://paulfaa.github.io',
      credentials: true
    }));
  }
  app.use(bodyParser.json());
  app.use(express.json());
  app.use(cookieParser());

  app.post('/login', (req, res) => {
    const { password } = req.body;
    let role = null;

    if (password === adminPassword) {
      role = 'admin';
    } else if (password === userPassword) {
      role = 'user';
    }

    if (role) {
      console.log('expires in:', JWT_EXPIRATION);
      const token = jwt.sign({ role: role }, JWT_SECRET, { expiresIn: JWT_EXPIRATION });
      res.cookie('token', token, {
        httpOnly: true,
        secure: true, //set to false for local dev
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

  app.get('/playlists', async (req, res) => {
    // add caching here
    try {
      const playlists = await collection.find({}).toArray();
      console.log(`Fetched ${playlists.length} playlists`);
      res.status(200).json(playlists);
    } catch (err) {
      console.error('Error fetching playlists:', err);
      res.status(500).json({ error: 'Failed to fetch playlists' });
    }
  });

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

    //need to query DB first to see if playlist already exists for the given date
    try {
      const existingPlaylist = await collection.findOne({ playlistDate: parseResult.playlistDate });
      if (existingPlaylist) {
        console.log(`Playlist for date ${parseResult.playlistDate} already exists. Not inserting.`);
        return res.status(400).json({ error: 'Playlist for this date already exists.' });
      }
    }
    catch (err) {
      console.error(`Something went wrong trying to find existing playlist: ${err}\n`);
      return res.status(500).json({ error: 'Internal server error' });
    }

    try {
      const insertResult = await collection.insertOne(parseResult.data);
      return res.status(201).json({ message: `Playlist ${insertResult.name} saved successfully` });
    } catch (err) {
      console.error(`Something went wrong trying to insert the new document: ${err}\n`);
      return res.status(500).json({ error: 'Failed to save playlist' });
    }
  });

  app.listen(port, '0.0.0.0', () => {
    console.log(`Server listening on port ${port}`);
  });


})();

process.on('SIGINT', async () => {
  console.log('\nClosing MongoDB connection...');
  await getMongoClient().close();
  process.exit(0);
});

