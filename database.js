const { MongoClient } = require('mongodb');
require('dotenv').config();

const uri = process.env.MONGO_URI;

const client = new MongoClient(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

client.connect()
  .then(() => console.log('✅ Connected to MongoDB Atlas'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

module.exports = client;
