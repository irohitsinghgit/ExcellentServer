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
        batchId,
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
        batchId,
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
          batchId,
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
        batchId: user.batchId
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
      batchId: user.batchId,
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

// Check security code availability endpoint
app.post('/check-security-code', async (req, res) => {
  try {
    const { securityCode } = req.body;

    // Validate if security code is provided
    if (!securityCode) {
      return res.status(400).send({
        error: 'Missing required field',
        message: 'Security code is required'
      });
    }

    // Validate security code format
    if (!/^\d{6}$/.test(securityCode)) {
      return res.status(400).send({
        error: 'Invalid security code',
        message: 'Security code must be 6 digits'
      });
    }

    const db = client.db('excellentInstitute');
    const students = db.collection('students');

    // Check if security code exists
    const existingUser = await students.findOne({ securityCode });

    if (existingUser) {
      return res.status(400).send({
        error: 'Security code already exists',
        message: 'This security code is already in use',
        available: false
      });
    }

    // If we get here, the security code is available
    res.status(200).send({
      message: 'Security code is available',
      available: true
    });

  } catch (err) {
    console.error('Security code check error:', err);
    res.status(500).send({
      error: 'Failed to check security code',
      message: 'An error occurred while checking security code availability'
    });
  }
});

// Create Quiz Question endpoint (Admin only)
app.post('/admin/create-quiz', verifyToken, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== 'admin') {
      return res.status(403).send({
        error: 'Access denied',
        message: 'Only admins can create quiz questions'
      });
    }

    const {
      question,
      options,
      correctOption,
      quizDate,
      startTime,
      endTime,
      marks = 1, // Default marks per question
      category,
      difficulty = 'medium', // Default difficulty
      status = 'draft', // Default status
      courseId // Course ID (1, 2, 3, or 4)
    } = req.body;

    // Validate required fields
    const requiredFields = {
      question: 'Question text',
      options: 'Question options',
      correctOption: 'Correct option',
      quizDate: 'Quiz date',
      startTime: 'Start time',
      endTime: 'End time',
      courseId: 'Course ID'
    };

    const missingFields = [];
    for (const [field, label] of Object.entries(requiredFields)) {
      if (!req.body[field]) {
        missingFields.push(label);
      }
    }

    if (missingFields.length > 0) {
      return res.status(400).send({
        error: 'Missing required fields',
        missingFields
      });
    }

    // Validate course ID
    const validCourseIds = [1, 2, 3, 4];
    if (!validCourseIds.includes(Number(courseId))) {
      return res.status(400).send({
        error: 'Invalid course ID',
        message: 'Course ID must be one of: 1, 2, 3, 4'
      });
    }

    // Validate options
    if (!Array.isArray(options) || options.length !== 4) {
      return res.status(400).send({
        error: 'Invalid options',
        message: 'Exactly 4 options (A, B, C, D) are required'
      });
    }

    // Validate correct option
    if (!['A', 'B', 'C', 'D'].includes(correctOption)) {
      return res.status(400).send({
        error: 'Invalid correct option',
        message: 'Correct option must be one of: A, B, C, D'
      });
    }

    // Validate date and time format
    const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
    const timeRegex = /^([01]?[0-9]|2[0-3]):[0-5][0-9]$/;

    if (!dateRegex.test(quizDate)) {
      return res.status(400).send({
        error: 'Invalid date format',
        message: 'Quiz date must be in YYYY-MM-DD format'
      });
    }

    if (!timeRegex.test(startTime) || !timeRegex.test(endTime)) {
      return res.status(400).send({
        error: 'Invalid time format',
        message: 'Time must be in HH:MM format (24-hour)'
      });
    }

    // Validate that end time is after start time
    const startDateTime = new Date(`${quizDate}T${startTime}`);
    const endDateTime = new Date(`${quizDate}T${endTime}`);
    
    if (endDateTime <= startDateTime) {
      return res.status(400).send({
        error: 'Invalid time range',
        message: 'End time must be after start time'
      });
    }

    // Validate that quiz date is not in the past
    const currentDate = new Date();
    currentDate.setHours(0, 0, 0, 0);
    const quizDateObj = new Date(quizDate);
    quizDateObj.setHours(0, 0, 0, 0);

    if (quizDateObj < currentDate) {
      return res.status(400).send({
        error: 'Invalid quiz date',
        message: 'Quiz date cannot be in the past'
      });
    }

    const db = client.db('excellentInstitute');
    const quizQuestions = db.collection('quizQuestions');

    // Create the quiz question document
    const newQuizQuestion = {
      question,
      options: {
        A: options[0],
        B: options[1],
        C: options[2],
        D: options[3]
      },
      correctOption,
      quizDate,
      startTime,
      endTime,
      marks,
      category,
      difficulty,
      status,
      courseId: Number(courseId), // Store as number (1, 2, 3, or 4)
      createdBy: req.user.userId,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const result = await quizQuestions.insertOne(newQuizQuestion);

    res.status(201).send({
      message: 'Quiz question created successfully',
      quizId: result.insertedId,
      quiz: {
        question,
        options: newQuizQuestion.options,
        quizDate,
        startTime,
        endTime,
        category,
        difficulty,
        status,
        courseId: Number(courseId)
      }
    });

  } catch (err) {
    console.error('Create quiz question error:', err);
    res.status(500).send({
      error: 'Failed to create quiz question',
      message: 'An error occurred while creating the quiz question'
    });
  }
});

// Get questions for a specific course
app.get('/quiz/questions/:courseId', verifyToken, async (req, res) => {
  try {
    const { courseId } = req.params;
    const courseIdNum = Number(courseId);

    // Validate course ID
    const validCourseIds = [1, 2, 3, 4];
    if (!validCourseIds.includes(courseIdNum)) {
      return res.status(400).send({
        error: 'Invalid course ID',
        message: 'Course ID must be one of: 1, 2, 3, 4'
      });
    }

    const db = client.db('excellentInstitute');
    const quizQuestions = db.collection('quizQuestions');

    // Get current date and time
    const now = new Date();
    const currentDate = now.toISOString().split('T')[0];
    const currentTime = now.toTimeString().slice(0, 5);

    // Find all published questions for the course
    const questions = await quizQuestions.find({
      courseId: courseIdNum,
      status: 'published' // Changed from 'active' to 'published'
    }).sort({
      quizDate: 1,  // Sort by date
      startTime: 1  // Then by start time
    }).toArray();

    // Format and categorize questions
    const formattedQuestions = questions.map(q => {
      const questionDate = new Date(q.quizDate);
      const startDateTime = new Date(`${q.quizDate}T${q.startTime}`);
      const endDateTime = new Date(`${q.quizDate}T${q.endTime}`);
      
      let status = 'upcoming';
      if (now >= startDateTime && now <= endDateTime) {
        status = 'active';
      } else if (now > endDateTime) {
        status = 'completed';
      }

      return {
        quizId: q._id,
        question: q.question,
        options: q.options,
        quizDate: q.quizDate,
        startTime: q.startTime,
        endTime: q.endTime,
        marks: q.marks,
        category: q.category,
        difficulty: q.difficulty,
        courseId: q.courseId,
        status: status,
        timeRemaining: status === 'upcoming' ? 
          Math.floor((startDateTime - now) / 1000 / 60) : // minutes until start
          status === 'active' ? 
          Math.floor((endDateTime - now) / 1000 / 60) : // minutes until end
          null
      };
    });

    // Group questions by status
    const groupedQuestions = {
      active: formattedQuestions.filter(q => q.status === 'active'),
      upcoming: formattedQuestions.filter(q => q.status === 'upcoming'),
      completed: formattedQuestions.filter(q => q.status === 'completed')
    };

    res.status(200).send({
      message: 'Questions retrieved successfully',
      courseId: courseIdNum,
      totalQuestions: questions.length,
      currentDate: currentDate,
      currentTime: currentTime,
      questions: groupedQuestions
    });

  } catch (err) {
    console.error('Get questions error:', err);
    res.status(500).send({
      error: 'Failed to get questions',
      message: 'An error occurred while retrieving questions'
    });
  }
});

// Debug endpoint to check quiz questions (temporary)
app.get('/debug/quiz-questions/:courseId', verifyToken, async (req, res) => {
  try {
    const { courseId } = req.params;
    const courseIdNum = Number(courseId);
    const db = client.db('excellentInstitute');
    const quizQuestions = db.collection('quizQuestions');

    // Get today's date
    const today = new Date();
    const todayStr = today.toISOString().split('T')[0];
    const currentTime = today.toTimeString().slice(0, 5);

    // Get all questions for this course without any filters first
    const allQuestions = await quizQuestions.find({
      courseId: courseIdNum
    }).toArray();

    // Get questions with today's date filter
    const todayQuestions = await quizQuestions.find({
      courseId: courseIdNum,
      quizDate: todayStr
    }).toArray();

    // Get questions with status filter
    const activeQuestions = await quizQuestions.find({
      courseId: courseIdNum,
      quizDate: todayStr,
      status: 'active'
    }).toArray();

    // Get the final filtered questions
    const finalQuestions = await quizQuestions.find({
      courseId: courseIdNum,
      quizDate: todayStr,
      status: 'active',
      $or: [
        {
          startTime: { $lte: currentTime },
          endTime: { $gt: currentTime }
        },
        {
          startTime: { $gt: currentTime }
        }
      ]
    }).toArray();

    res.status(200).send({
      debug: {
        currentDate: todayStr,
        currentTime: currentTime,
        courseId: courseIdNum,
        totalQuestionsInCollection: allQuestions.length,
        questionsWithTodayDate: todayQuestions.length,
        questionsWithActiveStatus: activeQuestions.length,
        finalFilteredQuestions: finalQuestions.length,
        sampleQuestions: allQuestions.slice(0, 2) // Show first 2 questions for debugging
      }
    });

  } catch (err) {
    console.error('Debug error:', err);
    res.status(500).send({
      error: 'Debug failed',
      message: err.message
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
