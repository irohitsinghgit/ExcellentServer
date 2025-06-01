const express = require('express');
require('dotenv').config();
const client = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json()); // Parse incoming JSON

// Test route
app.get('/', (req, res) => {
  res.send('Server running');
});

// Add a student
app.post('/add-student', async (req, res) => {
    try {
      const db = client.db('excellentInstitute');
      const students = db.collection('students');
  
      const { name, email, password, course, role, enrolled } = req.body;
  
      if (!name || !email || !password || !role) {
        return res.status(400).send({ error: 'Missing required fields' });
      }
  
      const newStudent = {
        name,
        email,
        password,
        course,
        role,
        enrolled: enrolled || false
      };
  
      const result = await students.insertOne(newStudent);
  
      res.send({ message: 'Student added', id: result.insertedId });
    } catch (err) {
      console.error(err);
      res.status(500).send('Error adding student');
    }
  });

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
