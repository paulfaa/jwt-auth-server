import { MongoClient, ServerApiVersion } from 'mongodb';
import { getSecret } from './secrets.js';

let db;
let mongoClient;

async function connectToDb() {
  const uri = getSecret('mongodb-uri');
  mongoClient = new MongoClient(uri, {
    serverApi: {
      version: ServerApiVersion.v1,
      strict: true,
      deprecationErrors: true,
    }
  });
  console.log('URI:', uri);
  if (!db) {
    await mongoClient.connect();
    db = mongoClient.db('seasonStats');
    console.log('Connected to MongoDB');
  }
  return db;
}

function getMongoClient() {
  if (!mongoClient) {
    throw new Error('MongoClient not initialized. Call connectToDb() first.');
  }
  return mongoClient;
}

export { connectToDb, getMongoClient };
