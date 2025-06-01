const { MongoClient } = require('mongodb');
require('dotenv').config();

// Get MongoDB URI from environment variable with fallback
const uri = process.env.MONGO_URI || 'mongodb://localhost:27017/excellentInstitute';

if (!uri) {
  console.error('❌ MongoDB URI is not defined in environment variables');
  process.exit(1);
}

const client = new MongoClient(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Function to connect to MongoDB
async function connectToDatabase() {
  try {
    await client.connect();
    console.log('✅ Connected to MongoDB Atlas');
    return client;
  } catch (err) {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  }
}

// Connect to database
connectToDatabase();

module.exports = client;
