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
        address,
        securityCode
      } = req.body;

      // Required fields validation
      const requiredFields = {
        name: 'Name',
        email: 'Email',
        password: 'Password',
        batchId: 'Batch ID',
        role: 'Role',
        address: 'Address',
        securityCode: 'Security Code'
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

      // Validate email format
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).send({
          error: 'Invalid email format',
          message: 'Please provide a valid email address'
        });
      }

      // Validate password
      if (password.length < 6) {
        return res.status(400).send({
          error: 'Invalid password',
          message: 'Password must be at least 6 characters long'
        });
      }

      // Validate batchId is a number
      const batchIdNum = Number(batchId);
      if (isNaN(batchIdNum) || !Number.isInteger(batchIdNum) || batchIdNum <= 0) {
        return res.status(400).send({
          error: 'Invalid batch ID',
          message: 'Batch ID must be a positive number (e.g., 1, 2, 3)'
        });
      }

      // Validate security code format
      if (!/^\d{6}$/.test(securityCode)) {
        return res.status(400).send({
          error: 'Invalid security code',
          message: 'Security code must be 6 digits'
        });
      }

      // Validate role
      const validRoles = ['student', 'admin'];
      if (!validRoles.includes(role)) {
        return res.status(400).send({
          error: 'Invalid role',
          message: 'Role must be either "student" or "admin"'
        });
      }

      // Check if email already exists
      const existingUser = await students.findOne({ email });
      if (existingUser) {
        return res.status(400).send({ 
          error: 'Email already registered',
          message: 'This email is already in use'
        });
      }

      // Check if security code already exists
      const existingSecurityCode = await students.findOne({ securityCode });
      if (existingSecurityCode) {
        return res.status(400).send({
          error: 'Security code already exists',
          message: 'This security code is already in use'
        });
      }
  
      const newStudent = {
        name: name.trim(),
        email: email.trim(),
        password: password.trim(),
        batchId: batchIdNum,
        role,
        address: address.trim(), // Store as simple string
        securityCode,
        status: 'active',
        createdAt: new Date(),
        updatedAt: new Date()
      };
  
      const result = await students.insertOne(newStudent);
  
      res.status(201).send({ 
        message: 'Registered successfully', 
        id: result.insertedId,
        user: {
          name: newStudent.name,
          email: newStudent.email,
          role: newStudent.role,
          batchId: newStudent.batchId,
          status: newStudent.status
        }
      });
    } catch (err) {
      console.error(err);
      res.status(500).send({ 
        error: 'Error adding user', 
        message: 'An error occurred during registration',
        details: err.message 
      });
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

// Create Quiz endpoint (Admin only)
app.post('/admin/create-quiz', verifyToken, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== 'admin') {
      return res.status(403).send({
        error: 'Access denied',
        message: 'Only admins can create quizzes'
      });
    }

    const { 
      batchId,
      quizTitle,
      quizDescription,
      quizDate,
      startTime,
      endTime,
      questions,
      totalMarks = 100,
      passingMarks = 40
    } = req.body;

    // Validate batchId and convert to number
    const batchIdNum = Number(batchId);
    if (isNaN(batchIdNum) || !Number.isInteger(batchIdNum) || batchIdNum <= 0) {
      return res.status(400).send({
        error: 'Invalid batch ID',
        message: 'Batch ID must be a positive number (e.g., 1, 2, 3)'
      });
    }

    // Validate required fields
    const requiredFields = {
      quizTitle: 'Quiz Title',
      quizDescription: 'Quiz Description',
      quizDate: 'Quiz Date',
      startTime: 'Start Time',
      endTime: 'End Time',
      questions: 'Questions'
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
        message: 'The following fields are required',
        missingFields
      });
    }

    // Validate questions array
    if (!Array.isArray(questions)) {
      return res.status(400).send({
        error: 'Invalid questions format',
        message: 'Questions must be provided as an array'
      });
    }

    // Validate number of questions
    if (questions.length < 1 || questions.length > 100) {
      return res.status(400).send({
        error: 'Invalid number of questions',
        message: 'Quiz must contain between 1 and 100 questions'
      });
    }

    // Validate date and time formats
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
    const quizzes = db.collection('quizzes');
    const quizQuestions = db.collection('quizQuestions');

    // Generate a single quiz ID for all questions
    const quizId = new ObjectId();

    // Validate each question
    const validatedQuestions = [];
    const errors = [];

    for (let i = 0; i < questions.length; i++) {
      const q = questions[i];
      const questionNumber = i + 1;

      // Required fields validation for each question
      const questionRequiredFields = {
        question: 'Question text',
        options: 'Question options',
        correctOption: 'Correct option',
        marks: 'Question marks'
      };

      const questionMissingFields = [];
      for (const [field, label] of Object.entries(questionRequiredFields)) {
        if (!q[field]) {
          questionMissingFields.push(`${label} (Question ${questionNumber})`);
        }
      }

      if (questionMissingFields.length > 0) {
        errors.push({
          questionNumber,
          error: 'Missing required fields',
          missingFields: questionMissingFields
        });
        continue;
      }

      // Validate options
      if (!Array.isArray(q.options) || q.options.length !== 4) {
        errors.push({
          questionNumber,
          error: 'Invalid options',
          message: 'Exactly 4 options (A, B, C, D) are required'
        });
        continue;
      }

      // Validate correct option
      if (!['A', 'B', 'C', 'D'].includes(q.correctOption)) {
        errors.push({
          questionNumber,
          error: 'Invalid correct option',
          message: 'Correct option must be one of: A, B, C, D'
        });
        continue;
      }

      // Validate marks
      const marks = Number(q.marks);
      if (isNaN(marks) || marks <= 0) {
        errors.push({
          questionNumber,
          error: 'Invalid marks',
          message: 'Marks must be a positive number'
        });
        continue;
      }

      // If all validations pass, add to validated questions
      validatedQuestions.push({
        quizId: quizId,
        question: q.question.trim(),
        options: {
          A: q.options[0].trim(),
          B: q.options[1].trim(),
          C: q.options[2].trim(),
          D: q.options[3].trim()
        },
        correctOption: q.correctOption,
        marks: marks,
        questionNumber: questionNumber,
        createdAt: new Date(),
        updatedAt: new Date()
      });
    }

    // If there are any validation errors, return them
    if (errors.length > 0) {
      return res.status(400).send({
        error: 'Validation failed',
        message: 'Some questions failed validation',
        errors,
        validatedCount: validatedQuestions.length,
        totalQuestions: questions.length
      });
    }

    // Calculate total marks from questions
    const calculatedTotalMarks = validatedQuestions.reduce((sum, q) => sum + q.marks, 0);

    // Create the quiz document
    const quiz = {
      _id: quizId,
      batchId: batchIdNum,
      quizTitle: quizTitle.trim(),
      quizDescription: quizDescription.trim(),
      quizDate,
      startTime,
      endTime,
      totalMarks: calculatedTotalMarks,
      passingMarks: Number(passingMarks),
      totalQuestions: validatedQuestions.length,
      status: 'scheduled',
      createdBy: req.user.userId,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    // Start a session for transaction
    const session = client.startSession();

    try {
      await session.withTransaction(async () => {
        // Insert the quiz document
        await quizzes.insertOne(quiz, { session });

        // Insert all questions
        await quizQuestions.insertMany(validatedQuestions, { session });
      });

      res.status(201).send({
        message: 'Quiz created successfully',
        quiz: {
          id: quizId.toString(),
          batchId: batchIdNum,
          quizTitle: quiz.quizTitle,
          quizDescription: quiz.quizDescription,
          quizDate,
          startTime,
          endTime,
          totalMarks: calculatedTotalMarks,
          passingMarks: quiz.passingMarks,
          totalQuestions: validatedQuestions.length,
          status: quiz.status,
          createdBy: req.user.userId,
          createdAt: quiz.createdAt
        }
      });

    } catch (transactionError) {
      console.error('Transaction error:', transactionError);
      throw transactionError;
    } finally {
      await session.endSession();
    }

  } catch (err) {
    console.error('Create quiz error:', err);
    res.status(500).send({
      error: 'Failed to create quiz',
      message: 'An error occurred while creating the quiz',
      details: err.message
    });
  }
});

// Get quizzes by batch ID
app.get('/quizzes/batch/:batchId', verifyToken, async (req, res) => {
  try {
    const { batchId } = req.params;
    const { userId, role } = req.user;

    // Convert batchId to number for consistent comparison
    const batchIdNum = Number(batchId);
    if (isNaN(batchIdNum)) {
      return res.status(400).send({
        error: 'Invalid batch ID',
        message: 'Batch ID must be a number'
      });
    }

    const db = client.db('excellentInstitute');
    const quizzes = db.collection('quizzes');
    const quizQuestions = db.collection('quizQuestions');
    const students = db.collection('students');

    // Debug: Log the query parameters
    console.log('Querying quizzes with batchId:', batchIdNum, 'type:', typeof batchIdNum);

    // Debug: First, let's see what quizzes exist in the database
    const allQuizzesInDB = await quizzes.find({}).toArray();
    console.log('All quizzes in database:', JSON.stringify(allQuizzesInDB, null, 2));

    // If user is not admin, verify they belong to the batch
    if (role !== 'admin') {
      const student = await students.findOne({
        _id: new ObjectId(userId),
        batchId: batchIdNum
      });

      if (!student) {
        return res.status(403).send({
          error: 'Access denied',
          message: 'You do not have access to this batch\'s quizzes'
        });
      }
    }

    // Get current date and time
    const now = new Date();
    const currentDate = now.toISOString().split('T')[0];
    const currentTime = now.toTimeString().slice(0, 5);

    // Find all quizzes for this batch
    const allQuizzes = await quizzes.find({
      batchId: batchIdNum
    }).sort({
      quizDate: 1,
      startTime: 1
    }).toArray();

    // Debug: Log the found quizzes
    console.log('Found quizzes for batchId', batchIdNum, ':', JSON.stringify(allQuizzes, null, 2));

    // Format and categorize quizzes
    const formattedQuizzes = await Promise.all(allQuizzes.map(async (quiz) => {
      const quizDate = new Date(quiz.quizDate);
      const startDateTime = new Date(`${quiz.quizDate}T${quiz.startTime}`);
      const endDateTime = new Date(`${quiz.quizDate}T${quiz.endTime}`);
      
      let status = 'upcoming';
      if (now >= startDateTime && now <= endDateTime) {
        status = 'active';
      } else if (now > endDateTime) {
        status = 'completed';
      }

      // Get questions for this quiz
      const questions = await quizQuestions.find({
        quizId: quiz._id
      }).sort({
        questionNumber: 1
      }).toArray();

      // Format questions (remove correct answers if quiz is upcoming)
      const formattedQuestions = questions.map(q => ({
        questionId: q._id.toString(),
        questionNumber: q.questionNumber,
        question: q.question,
        options: q.options,
        marks: q.marks,
        // Only include correct option if quiz is completed or user is admin
        ...(status === 'completed' || role === 'admin' ? { correctOption: q.correctOption } : {})
      }));

      return {
        quizId: quiz._id.toString(),
        batchId: quiz.batchId,
        quizTitle: quiz.quizTitle,
        quizDescription: quiz.quizDescription,
        quizDate: quiz.quizDate,
        startTime: quiz.startTime,
        endTime: quiz.endTime,
        totalMarks: quiz.totalMarks,
        passingMarks: quiz.passingMarks,
        totalQuestions: quiz.totalQuestions,
        status: status,
        timeRemaining: status === 'upcoming' ? 
          Math.floor((startDateTime - now) / 1000 / 60) : // minutes until start
          status === 'active' ? 
          Math.floor((endDateTime - now) / 1000 / 60) : // minutes until end
          null,
        questions: formattedQuestions,
        createdBy: quiz.createdBy,
        createdAt: quiz.createdAt
      };
    }));

    // Group quizzes by status
    const groupedQuizzes = {
      active: formattedQuizzes.filter(q => q.status === 'active'),
      upcoming: formattedQuizzes.filter(q => q.status === 'upcoming'),
      completed: formattedQuizzes.filter(q => q.status === 'completed')
    };

    res.status(200).send({
      message: 'Quizzes retrieved successfully',
      batchId: batchId,
      totalQuizzes: allQuizzes.length,
      currentDate: currentDate,
      currentTime: currentTime,
      quizzes: groupedQuizzes
    });

  } catch (err) {
    console.error('Get quizzes error:', err);
    res.status(500).send({
      error: 'Failed to get quizzes',
      message: 'An error occurred while retrieving quizzes',
      details: err.message
    });
  }
});

// Submit Quiz API
app.post('/quiz/submit', verifyToken, async (req, res) => {
  try {
    const { quizId, answers } = req.body;
    const { userId } = req.user;

    // Validate required fields
    if (!quizId || !answers) {
      return res.status(400).send({
        error: 'Missing required fields',
        message: 'Quiz ID and answers are required'
      });
    }

    // Validate answers is an array
    if (!Array.isArray(answers)) {
      return res.status(400).send({
        error: 'Invalid answers format',
        message: 'Answers must be provided as an array'
      });
    }

    const db = client.db('excellentInstitute');
    const quizzes = db.collection('quizzes');
    const quizQuestions = db.collection('quizQuestions');
    const quizAttempts = db.collection('quizAttempts');

    // Get quiz details
    const quiz = await quizzes.findOne({ _id: new ObjectId(quizId) });
    if (!quiz) {
      return res.status(404).send({
        error: 'Quiz not found',
        message: 'No quiz found with the provided ID'
      });
    }

    // Check if user has already attempted this quiz
    const existingAttempt = await quizAttempts.findOne({
      quizId: new ObjectId(quizId),
      userId: new ObjectId(userId)
    });

    if (existingAttempt) {
      return res.status(400).send({
        error: 'Quiz already attempted',
        message: 'You have already submitted this quiz'
      });
    }

    // Get all questions for this quiz
    const questions = await quizQuestions.find({
      quizId: new ObjectId(quizId)
    }).toArray();

    // Process answers and calculate score
    let totalScore = 0;
    const processedAnswers = answers.map(answer => {
      const question = questions.find(q => q._id.toString() === answer.questionId);
      if (!question) return null;

      const isCorrect = answer.selectedOption === question.correctOption;
      const score = isCorrect ? question.marks : 0;
      totalScore += score;

      return {
        questionId: question._id,
        questionNumber: question.questionNumber,
        selectedOption: answer.selectedOption || null, // null if skipped
        correctOption: question.correctOption,
        marks: question.marks,
        score: score,
        isCorrect: isCorrect
      };
    }).filter(Boolean); // Remove any null entries

    // Calculate percentage
    const percentage = (totalScore / quiz.totalMarks) * 100;
    const isPassed = percentage >= quiz.passingMarks;

    // Create attempt record
    const attempt = {
      quizId: new ObjectId(quizId),
      userId: new ObjectId(userId),
      batchId: quiz.batchId,
      answers: processedAnswers,
      totalScore,
      totalMarks: quiz.totalMarks,
      percentage,
      isPassed,
      submittedAt: new Date(),
      status: 'completed'
    };

    // Save attempt
    await quizAttempts.insertOne(attempt);

    res.status(200).send({
      message: 'Quiz submitted successfully',
      result: {
        quizId: quizId,
        totalScore,
        totalMarks: quiz.totalMarks,
        percentage: percentage.toFixed(2),
        isPassed,
        submittedAt: attempt.submittedAt
      }
    });

  } catch (err) {
    console.error('Submit quiz error:', err);
    res.status(500).send({
      error: 'Failed to submit quiz',
      message: 'An error occurred while submitting the quiz',
      details: err.message
    });
  }
});

// Get Quiz Status API
app.get('/quiz/status/:quizId', verifyToken, async (req, res) => {
  try {
    const { quizId } = req.params;
    const { userId } = req.user;

    const db = client.db('excellentInstitute');
    const quizzes = db.collection('quizzes');
    const quizAttempts = db.collection('quizAttempts');

    // Get quiz details
    const quiz = await quizzes.findOne({ _id: new ObjectId(quizId) });
    if (!quiz) {
      return res.status(404).send({
        error: 'Quiz not found',
        message: 'No quiz found with the provided ID'
      });
    }

    // Check if user has attempted this quiz
    const attempt = await quizAttempts.findOne({
      quizId: new ObjectId(quizId),
      userId: new ObjectId(userId)
    });

    // Get current time for status
    const now = new Date();
    const startDateTime = new Date(`${quiz.quizDate}T${quiz.startTime}`);
    const endDateTime = new Date(`${quiz.quizDate}T${quiz.endTime}`);

    let status = 'not_started';
    if (now >= startDateTime && now <= endDateTime) {
      status = 'active';
    } else if (now > endDateTime) {
      status = 'ended';
    }

    res.status(200).send({
      quizId: quizId,
      quizTitle: quiz.quizTitle,
      status: status,
      attemptStatus: attempt ? 'completed' : 'not_attempted',
      attemptDetails: attempt ? {
        submittedAt: attempt.submittedAt,
        totalScore: attempt.totalScore,
        totalMarks: attempt.totalMarks,
        percentage: attempt.percentage,
        isPassed: attempt.isPassed
      } : null
    });

  } catch (err) {
    console.error('Get quiz status error:', err);
    res.status(500).send({
      error: 'Failed to get quiz status',
      message: 'An error occurred while getting quiz status',
      details: err.message
    });
  }
});

// Get User's Quiz Attempts API
app.get('/quiz/attempts', verifyToken, async (req, res) => {
  try {
    const { userId } = req.user;
    const { batchId } = req.query;

    const db = client.db('excellentInstitute');
    const quizzes = db.collection('quizzes');
    const quizAttempts = db.collection('quizAttempts');

    // Build query based on batchId
    let query = { userId: new ObjectId(userId) };
    if (batchId) {
      query.batchId = Number(batchId);
    }

    // Get all attempts
    const attempts = await quizAttempts.find(query)
      .sort({ submittedAt: -1 })
      .toArray();

    // Get all quizzes for this batch
    const batchQuizzes = await quizzes.find(
      batchId ? { batchId: Number(batchId) } : {}
    ).toArray();

    // Create a map of attempted quizzes
    const attemptedQuizIds = new Set(attempts.map(a => a.quizId.toString()));

    // Categorize quizzes
    const categorizedQuizzes = {
      attempted: [],
      notAttempted: []
    };

    batchQuizzes.forEach(quiz => {
      const attempt = attempts.find(a => a.quizId.toString() === quiz._id.toString());
      const quizData = {
        quizId: quiz._id.toString(),
        quizTitle: quiz.quizTitle,
        quizDate: quiz.quizDate,
        startTime: quiz.startTime,
        endTime: quiz.endTime,
        totalMarks: quiz.totalMarks,
        passingMarks: quiz.passingMarks
      };

      if (attempt) {
        categorizedQuizzes.attempted.push({
          ...quizData,
          attemptDetails: {
            submittedAt: attempt.submittedAt,
            totalScore: attempt.totalScore,
            percentage: attempt.percentage,
            isPassed: attempt.isPassed
          }
        });
      } else {
        // Check if quiz is still available for attempt
        const now = new Date();
        const endDateTime = new Date(`${quiz.quizDate}T${quiz.endTime}`);
        const isAvailable = now <= endDateTime;

        categorizedQuizzes.notAttempted.push({
          ...quizData,
          isAvailable
        });
      }
    });

    res.status(200).send({
      message: 'Quiz attempts retrieved successfully',
      totalAttempts: attempts.length,
      totalQuizzes: batchQuizzes.length,
      quizzes: categorizedQuizzes
    });

  } catch (err) {
    console.error('Get quiz attempts error:', err);
    res.status(500).send({
      error: 'Failed to get quiz attempts',
      message: 'An error occurred while retrieving quiz attempts',
      details: err.message
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
