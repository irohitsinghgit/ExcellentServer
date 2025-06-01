const express = require('express');
require('dotenv').config();
const client = require('./database');
const jwt = require('jsonwebtoken');
const { ObjectId } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 3000;

// JWT Secret Key - In production, this should be in .env file
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    return res.status(401).send({
      error: 'Authentication required',
      message: 'No token provided'
    });
  }

  // Get token from Bearer token
  const token = authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).send({
      error: 'Authentication required',
      message: 'No token provided'
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // Add user info to request object
    next();
  } catch (err) {
    return res.status(401).send({
      error: 'Invalid token',
      message: 'Token is invalid or expired'
    });
  }
};

app.use(express.json()); // Parse incoming JSON

// Health check endpoint
app.get('/', (req, res) => {
  res.status(200).json({ status: 'ok', message: 'Server is running' });
});

// Test route
app.get('/', (req, res) => {
  res.send('Server running');
});

// Add a student
app.post('/register', async (req, res) => {
    try {
      const db = client.db('excellentInstitute');
      const students = db.collection('students');
  
      const {
        name,
        email,
        password,
        course,
        role,
        phoneNumber,
        dateOfBirth,
        gender,
        address,
        emergencyContact,
        education,
        enrolled,
        securityCode,
        registrationDate = new Date(),
        status = 'active'
      } = req.body;

      // Required fields validation with proper nesting
      const requiredFields = {
        basic: ['name', 'email', 'password', 'role', 'phoneNumber', 'dateOfBirth', 'gender', 'securityCode'],
        address: ['street', 'city', 'state', 'zipCode', 'country'],
        emergencyContact: ['name', 'relationship', 'phoneNumber'],
        education: ['lastInstitution', 'qualification']
      };

      const missingFields = [];

      // Check basic fields
      requiredFields.basic.forEach(field => {
        if (!req.body[field]) {
          missingFields.push(field);
        }
      });

      // Check address fields
      if (!address) {
        missingFields.push('address');
      } else {
        requiredFields.address.forEach(field => {
          if (!address[field]) {
            missingFields.push(`address.${field}`);
          }
        });
      }

      // Check emergency contact fields
      if (!emergencyContact) {
        missingFields.push('emergencyContact');
      } else {
        requiredFields.emergencyContact.forEach(field => {
          if (!emergencyContact[field]) {
            missingFields.push(`emergencyContact.${field}`);
          }
        });
      }

      // Check education fields
      if (!education) {
        missingFields.push('education');
      } else {
        requiredFields.education.forEach(field => {
          if (!education[field]) {
            missingFields.push(`education.${field}`);
          }
        });
      }

      if (missingFields.length > 0) {
        return res.status(400).send({ 
          error: 'Missing required fields', 
          missingFields 
        });
      }

      // Validate security code format
      if (!/^\d{6}$/.test(securityCode)) {
        return res.status(400).send({
          error: 'Invalid security code',
          message: 'Security code must be 6 digits'
        });
      }

      // Check if email already exists
      const existingUser = await students.findOne({ email });
      if (existingUser) {
        return res.status(400).send({ error: 'Email already registered' });
      }
  
      const newStudent = {
        name,
        email,
        password,
        course,
        role,
        phoneNumber,
        dateOfBirth,
        gender,
        address,
        emergencyContact,
        education,
        enrolled: enrolled || false,
        securityCode,
        registrationDate,
        status,
        createdAt: new Date(),
        updatedAt: new Date()
      };
  
      const result = await students.insertOne(newStudent);
  
      res.status(201).send({ 
        message: 'Registered successfully', 
        id: result.insertedId,
        student: {
          name,
          email,
          role,
          course,
          status
        }
      });
    } catch (err) {
      console.error(err);
      res.status(500).send({ error: 'Error adding student', details: err.message });
    }
  });

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate required fields
    if (!email || !password) {
      return res.status(400).send({
        error: 'Missing required fields',
        missingFields: !email ? ['email'] : ['password']
      });
    }

    const db = client.db('excellentInstitute');
    const students = db.collection('students');

    // Find user by email
    const user = await students.findOne({ email });

    // Check if user exists
    if (!user) {
      return res.status(401).send({
        error: 'Invalid credentials',
        message: 'No user found with this email'
      });
    }

    // In a real application, you should hash passwords and compare hashed values
    if (password !== user.password) {
      return res.status(401).send({
        error: 'Invalid credentials',
        message: 'Incorrect password'
      });
    }

    // Generate JWT token with string ID
    const token = jwt.sign(
      {
        userId: user._id.toString(), // Convert ObjectId to string
        email: user.email,
        role: user.role
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Send success response with token and user info
    res.status(200).send({
      message: 'Login successful',
      token,
      user: {
        id: user._id.toString(), // Convert ObjectId to string
        name: user.name,
        email: user.email,
        role: user.role,
        course: user.course
      }
    });

  } catch (err) {
    console.error('Login error:', err);
    res.status(500).send({
      error: 'Login failed',
      message: 'An error occurred during login'
    });
  }
});

// Get user data endpoint
app.get('/user/profile', verifyToken, async (req, res) => {
  try {
    const { userId, email } = req.user; // Get from token

    const db = client.db('excellentInstitute');
    const students = db.collection('students');

    // Convert string ID back to ObjectId
    const user = await students.findOne({
      _id: new ObjectId(userId),
      email: email
    });

    if (!user) {
      return res.status(404).send({
        error: 'User not found',
        message: 'No user found with the provided credentials'
      });
    }

    // Remove sensitive information before sending
    const userData = {
      id: user._id.toString(), // Convert ObjectId to string
      name: user.name,
      email: user.email,
      phoneNumber: user.phoneNumber,
      dateOfBirth: user.dateOfBirth,
      gender: user.gender,
      role: user.role,
      course: user.course,
      address: user.address,
      emergencyContact: user.emergencyContact,
      education: user.education,
      enrolled: user.enrolled,
      status: user.status,
      registrationDate: user.registrationDate,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    };

    res.status(200).send({
      message: 'User data retrieved successfully',
      user: userData
    });

  } catch (err) {
    console.error('Error fetching user data:', err);
    res.status(500).send({
      error: 'Failed to fetch user data',
      message: 'An error occurred while retrieving user information'
    });
  }
});

// Reset Password endpoint (modified to use security code)
app.post('/user/reset-password', verifyToken, async (req, res) => {
  try {
    const { userId, email } = req.user; // Get from token
    const { securityCode, newPassword } = req.body;

    // Validate required fields
    if (!securityCode || !newPassword) {
      return res.status(400).send({
        error: 'Missing required fields',
        missingFields: !securityCode ? ['securityCode'] : ['newPassword']
      });
    }

    // Validate security code format
    if (!/^\d{6}$/.test(securityCode)) {
      return res.status(400).send({
        error: 'Invalid security code',
        message: 'Security code must be 6 digits'
      });
    }

    // Validate new password
    if (newPassword.length < 8) {
      return res.status(400).send({
        error: 'Invalid password',
        message: 'New password must be at least 8 characters long'
      });
    }

    const db = client.db('excellentInstitute');
    const students = db.collection('students');

    // Find user by ID and email
    const user = await students.findOne({
      _id: new ObjectId(userId),
      email: email
    });

    if (!user) {
      return res.status(404).send({
        error: 'User not found',
        message: 'No user found with the provided credentials'
      });
    }

    // Verify security code
    if (securityCode !== user.securityCode) {
      return res.status(401).send({
        error: 'Invalid security code',
        message: 'Security code is incorrect'
      });
    }

    // Update password
    const result = await students.updateOne(
      { _id: new ObjectId(userId) },
      { 
        $set: { 
          password: newPassword,
          updatedAt: new Date()
        }
      }
    );

    if (result.modifiedCount === 0) {
      return res.status(500).send({
        error: 'Password update failed',
        message: 'Failed to update password'
      });
    }

    res.status(200).send({
      message: 'Password updated successfully',
      user: {
        id: user._id.toString(),
        email: user.email,
        name: user.name
      }
    });

  } catch (err) {
    console.error('Password reset error:', err);
    res.status(500).send({
      error: 'Password reset failed',
      message: 'An error occurred while resetting password'
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'production' ? 'Something went wrong' : err.message
  });
});

// Start server
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

// Handle server errors
server.on('error', (error) => {
  console.error('Server error:', error);
  if (error.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use`);
    process.exit(1);
  }
});

// Handle process termination
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
    process.exit(0);
  });
});
