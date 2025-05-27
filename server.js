// --- Imports & Setup ---
const express = require('express');
const cors = require('cors');
const { OAuth2Client } = require('google-auth-library');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const crypto = require('crypto'); 
const nodemailer = require('nodemailer'); 
const jwt = require('jsonwebtoken');
const axios = require('axios');
require('dotenv').config();

const app = express();
const DEPLOYED_FRONTEND_URL = process.env.DEPLOYED_FRONTEND_URL || 'http://localhost:5173';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET
const JWT_SECRET = process.env.JWT_SECRET;

// CORS configuration to allow requests from your frontend
app.use(cors({
  origin: [
    'http://localhost:5173',
    DEPLOYED_FRONTEND_URL
  ].filter(Boolean), // Filter out any empty strings if DEPLOYED_FRONTEND_URL is not set
  methods: 'GET,HEAD,PUT,POST,DELETE,PATCH',
  credentials: true,
}));
app.use(express.json());

app.use((req, res, next) => {
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
  next();
});

const client = new OAuth2Client(GOOGLE_CLIENT_ID); // Initialize Google OAuth client

// In-memory store for activation codes (consider a database for production)
const activationCodes = ['12345678']; 
const usedActivationCodes = new Set();

// --- Database Initialization ---
const db = new sqlite3.Database('./users.db', (err) => {
  if (err) {
    console.error('Could not connect to database', err);
  } else {
    console.log('Connected to SQLite database');
    // Create 'users' table if it doesn't exist
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT,
        username TEXT UNIQUE NOT NULL,
        googleId TEXT UNIQUE,
        createdAt TEXT DEFAULT CURRENT_TIMESTAMP NOT NULL
      )
    `, (err) => {
      if (err) {
        console.error('Error creating users table:', err.message);
      } else {
        console.log('Users table checked/created.');
        // Add googleId column if it doesn't exist (for older databases)
        db.all("PRAGMA table_info(users)", (err, columns) => {
          if (err) {
            console.error("Error checking table info for users:", err.message);
            return; 
          }
          if (!Array.isArray(columns)){
            console.error('PRAGMA table_info(users) did not return an array for columns. Received:', columns);
            return; 
          }
          const hasGoogleId = columns.some(col => col.name === 'googleId');
          if (!hasGoogleId) {
            db.run("ALTER TABLE users ADD COLUMN googleId TEXT UNIQUE", (alterErr) => {
              if (alterErr) {
                console.error("Error adding googleId column to users table:", alterErr);
              } else {
                console.log("Added googleId column to users table.");
              }
            });
          }
        });
        // Create 'password_reset_tokens' table if it doesn't exist
        db.run(`
          CREATE TABLE IF NOT EXISTS password_reset_tokens (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
          )
        `, (resetTableErr) => {
          if (resetTableErr) {
            console.error('Error creating password_reset_tokens table:', resetTableErr);
          } else {
            console.log('Password reset tokens table checked/created.');
          }
        });
      }
    });
  }
});

// --- Utility Functions ---

// Function to generate JWT for authentication
function generateAuthToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, username: user.username, googleId: user.googleId }, 
    JWT_SECRET, 
    { expiresIn: '1h' } // Token expires in 1 hour
  ); 
}

// Middleware function
const verifyToken = (req, res, next) => {
    // 1. Get the token from the header
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Expected format: "Bearer TOKEN"

    if (!token) {
        console.warn('verifyToken: No token provided in Authorization header.');
        return res.status(401).json({ message: 'Access Denied: No token provided' });
    }

    // 2. Verify the token
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('verifyToken: Token verification failed:', err.message);
            // Specific errors for debugging:
            if (err.name === 'TokenExpiredError') {
                return res.status(403).json({ message: 'Access Denied: Token expired' });
            }
            if (err.name === 'JsonWebTokenError') {
                return res.status(403).json({ message: 'Access Denied: Invalid token' });
            }
            // Generic error
            return res.status(403).json({ message: 'Access Denied: Failed to authenticate token' });
        }
        // 3. If valid, attach user payload to request
        req.user = user; // The 'user' here is the decoded payload from the token
        console.log('verifyToken: Token successfully verified for user:', user.email || user.username);
        next(); // Proceed to the next middleware/route handler
    });
};

// --- Nodemailer Transporter Setup ---
let transporter; 
if (process.env.EMAIL_SERVICE && process.env.EMAIL_USER && process.env.EMAIL_PASS) {
  // Scenario 1: Using a known email service (like Gmail)
  transporter = nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    },
  });
  console.log("Email transporter configured using service:", process.env.EMAIL_SERVICE);
} else if (process.env.EMAIL_HOST && process.env.EMAIL_PORT && process.env.EMAIL_USER && process.env.EMAIL_PASS) {
  // Scenario 2: Using a custom SMTP server
  transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT, 10),
    secure: process.env.EMAIL_SECURE === 'true',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    },
  });
  console.log("Email transporter configured using custom SMTP (host:", process.env.EMAIL_HOST + ":" + process.env.EMAIL_PORT + ")");
} else {
  // Scenario 3: Email configuration is missing or incomplete (dummy transporter to prevent crashes)
  console.error("ERROR: Email transporter NOT configured. Please set EMAIL_SERVICE (or EMAIL_HOST/PORT) AND EMAIL_USER/EMAIL_PASS in your .env file.");
  transporter = {
    name: 'DummyTransporter', 
    sendMail: (options, callback) => {
      const errMsg = `WARNING: Email sending attempted, but transporter is NOT configured. Email to ${options.to} for subject "${options.subject}" was NOT sent.`;
      console.warn(errMsg);
      callback(new Error(errMsg));
    }
  };
}

// --- Authentication Routes ---

// User Sign-up
app.post('/api/signup', async (req, res) => {
  console.log('*** /api/signup route hit! ***'); 
  console.log('*** /api/signup request body:', req.body); 

  const { email, password, username } = req.body; 

  if (!email || !password || !username) { 
    return res.status(400).json({ error: 'Please provide email, password, and username.' });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Invalid email format.' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
  }

  try {
    // Check if email or username already exists
    db.get('SELECT * FROM users WHERE email = ? OR username = ?', [email, username], async (err, row) => {
      if (err) {
        console.error('Error checking existing email/username', err);
        return res.status(500).json({ error: 'Database error.' });
      }
      if (row) {
        if (row.email === email){
          return res.status(409).json({ error: 'Email already exists.' });
        } else {
          return res.status(409).json({ error: 'Username already exists.' });
        }
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      // Insert new user into the database
      db.run('INSERT INTO users (email, password, username) VALUES (?, ?, ?)', [email, hashedPassword, username], function (err) {
        if (err) {
          console.error('Error creating user', err);
          if (err.message.includes('UNIQUE constraint failed: users.username')) {
            return res.status(409).json({ error: 'Username already taken.' });
          }
          return res.status(500).json({ error: 'Could not create user.' });
        }
        const userId = this.lastID; // Get the ID of the newly inserted row
        const userData = { id: userId, email: email, username: username }; 
        console.log(`User created with ID: ${userId}`);
        const token = generateAuthToken(userData);
        return res.status(201).json({ message: 'Signup successful!', token, user: userData });
      });
    });
  } catch (error) {
    console.error('Signup error:', error);
    return res.status(500).json({ error: 'Signup failed.' });
  }
});

// User Login
app.post('/api/login', async (req, res) => {
  console.log('*** /api/login route hit! ***');
  const { identifier, password } = req.body; // 'identifier' can be email or username

  if (!identifier || !password) {
    return res.status(400).json({ error: 'Please provide both email/username and password.' });
  }

  try {
    // Try to find user by email or username
    db.get('SELECT id, email, password, username, googleId FROM users WHERE email = ? OR username = ?', [identifier, identifier], async (err, user) => {
      if (err) {
        console.error('Error during login:', err);
        return res.status(500).json({ error: 'Database error during login.' });
      }

      if (!user) {
        return res.status(401).json({ error: 'Invalid email/username or password.' });
      }

      // Check if it's a Google-registered account without a password
      if (user.password === null || user.password === 'google_login_no_password') {
        return res.status(401).json({ error: 'This account was registered with Google. Please "Sign in with Google".' });
      }

      // Compare provided password with hashed password
      const passwordMatch = await bcrypt.compare(password, user.password);

      if (passwordMatch) {
        console.log(`User ${user.email} (username: ${user.username}) logged in successfully.`);
        const token = generateAuthToken(user);
        // Exclude sensitive info (password) from user data sent to frontend
        const userData = { id: user.id, email: user.email, username: user.username, googleId: user.googleId }; 
        return res.status(200).json({ message: 'Login successful!', token, user: userData });
      } else {
        return res.status(401).json({ error: 'Invalid email/username or password.' });
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'Login failed.' });
  }
});

// Google Login/Sign-up
app.post('/api/google-login', async (req, res) => {
  const { token: googleCredential } = req.body; // This 'token' is the Google ID token from the frontend
  
  console.log('Backend /api/google-login received request.');
  console.log('Received token (first 30 chars):', googleCredential ? googleCredential.substring(0, 30) + '...' : 'No token received in body');

  if (!googleCredential) {
    console.error('Backend: Google credential not provided in request body.');
    return res.status(400).json({ message: 'Google credential not provided' });
  }try {
    let payload = null;
    let verificationMethod = 'unknown';
    try {
        console.log('Backend: Attempting to verify Google credential as ID Token...');
        console.log('Backend: Using GOOGLE_CLIENT_ID for audience:', GOOGLE_CLIENT_ID); // LOG THE CLIENT ID
          const ticket = await client.verifyIdToken({
          idToken: googleCredential,
          audience: GOOGLE_CLIENT_ID, // Ensure the audience matches your Client ID
        });
        payload = ticket.getPayload();
        verificationMethod = 'ID Token';
        console.log('Backend: ID Token verification successful. Payload email:', payload?.email);
    } catch (idTokenError) {
        console.warn('Backend: ID Token verification failed. Error details:', idTokenError.message);
        console.warn('Backend: Possible reasons for ID Token failure: Incorrect GOOGLE_CLIENT_ID, expired token, or token is an Access Token.');
        // If ID token verification fails, try to use it as an Access Token
        // This is your original logic, kept as a fallback for robustness.
        console.log('Backend: Falling back to Access Token validation...');
        try {
            const userInfoResponse = await axios.get(
              `https://www.googleapis.com/oauth2/v3/userinfo?access_token=${googleCredential}`
            );
            payload = userInfoResponse.data;
            verificationMethod = 'Access Token';
            console.log('Backend: Access Token validation successful. Payload email:', payload?.email);
          } catch (accessTokenError) {
            console.error('Backend: Access Token validation also failed. Details:', accessTokenError.response?.data || accessTokenError.message);
            console.error('Backend: Complete Access Token error object:', accessTokenError);
            throw new Error('Invalid Google credential provided.');
          }
      }

      if (!payload) {
        // This case should ideally not be hit with the current logic, but good for safety.
        console.error('Backend: Payload is null after both ID Token and Access Token verification attempts.');
        throw new Error('Failed to retrieve user information from Google credential.');
      }

    const googleName = payload?.name;
    const googleEmail = payload?.email;
    const googleId = payload?.sub; // 'sub' is the unique Google ID

    if (!googleName || !googleEmail || !googleId) {
      console.error('Backend: Could not retrieve complete user information from Google payload.');
      return res.status(400).json({ message: 'Could not retrieve user information from Google' });
    }

    // Check if user exists by email or googleId
    db.get('SELECT id, email, username, googleId FROM users WHERE email = ? OR googleId = ?', [googleEmail, googleId], async (err, existingUser) => {
      if (err) {
        console.error('Database error during Google login:', err);
        return res.status(500).json({ message: 'Database error during Google login' });
      }

      let userRecord;
      if (existingUser) {
        // User found
        userRecord = existingUser;
        // If user exists by email but googleId isn't linked, link it
        if (!userRecord.googleId) {
          db.run('UPDATE users SET googleId = ? WHERE id = ?', [googleId, userRecord.id], (updateErr) => {
            if (updateErr) console.error('Error linking googleId to existing user:', updateErr);
            else console.log(`Linked Google ID for user ${userRecord.email}`);
          });
          userRecord.googleId = googleId; // Update the in-memory record for the current response
        }
        console.log(`Google user ${googleEmail} found and logged in.`);
        const authToken = generateAuthToken(userRecord);
        return res.json({ token: authToken, user: userRecord });
      } else {
        // User does not exist, create a new one
        const generatedUsername = googleEmail.split('@')[0];
        // Check if generated username already exists, append random string if it does
        db.get('SELECT id FROM users WHERE username = ?', [generatedUsername], async (err, usernameExists) => {
          if(err) {
            console.error('Database error checking username existence:', err)
            return res.status(500).json({ message: 'Database error creating Google user' });
          } 
          let finalUsername = generatedUsername;
          if (usernameExists) {
            finalUsername = `${generatedUsername}_${Math.random().toString(36).substring(2,7)}`;
          }

          // Insert new user with Google details
          db.run('INSERT INTO users (email, password, username, googleId) VALUES (?, ?, ?, ?)', [googleEmail, 'google_login_no_password', finalUsername, googleId], function(err) {
            if (err) {
              console.error('Error creating new Google user:', err);
              return res.status(500).json({ message: 'Could not create Google user' });
            }
            userRecord = { id: this.lastID, email: googleEmail, username: finalUsername, googleId: googleId };
            console.log(`New Google User created with ID: ${userRecord.id}`);
            
            const authToken = generateAuthToken(userRecord);
            return res.json({ token: authToken, user: userRecord });
          });
        });
        return; // Ensure no further execution after handling user creation
      }
    });

  } catch (error) {
    console.error('Backend: Google login/signup processing failed:', error);
    return res.status(401).json({ message: 'Google login failed', error: error.message });
  }
});

// User Logout
app.post('/api/logout', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1]; 
  if (token) {
    console.log(`User logged out with token: ${token.substring(0, 10)}...`);
  }
  res.status(200).json({ message: 'Logout successful' });
});

// Forgot Password - Request Reset Link
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Please provide your email address.' });
  }

  try {
    db.get('SELECT id, email FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) {
        console.error('Database error during forgot password:', err);
        return res.status(500).json({ error: 'Database error.' });
      }

      if (!user) {
        // Always send a generic success message for security reasons
        return res.status(200).json({ message: 'If an account with that email exists, a reset link has been sent.' });
      }

      const resetToken = crypto.randomBytes(32).toString('hex');
      const expiresAt = Date.now() + 3600000; // 1 hour expiration

      db.run('INSERT INTO password_reset_tokens (token, user_id, expires_at) VALUES (?, ?, ?)', [resetToken, user.id, expiresAt], (err) => {
        if (err) {
          console.error('Error saving reset token:', err);
          return res.status(500).json({ error: 'Could not save reset token.' });
        }

        const resetLink = `${DEPLOYED_FRONTEND_URL}/reset-password/${resetToken}`;

        const mailOptions = {
          from: process.env.EMAIL_FROM_ADDRESS || process.env.EMAIL_USER,
          to: user.email,
          subject: 'Password Reset Request',
          html: `<p>You have requested a password reset for your account.</p><p>Click the following link to reset your password:</p><a href="${resetLink}">${resetLink}</a><p>This link will expire in 1 hour.</p><p>If you did not request this, please ignore this email.</p>`,
        };

        if (transporter && typeof transporter.sendMail === 'function' && transporter.name !== 'DummyTransporter') {
          transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
              console.error('Error sending reset email:', error);
              return res.status(200).json({ message: 'If an account with that email exists, a reset link has been sent.' });
            }
            console.log('Reset email sent:', info.response);
            res.status(200).json({ message: 'If an account with that email exists, a reset link has been sent.' });
          });
        } else {
          console.error("CRITICAL ERROR: Email transporter not properly configured or is dummy. Cannot send password reset email for user:", user.email);
          res.status(200).json({ message: 'If an account with that email exists, a reset link has been sent.' });
        }
      });
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

// Verify Reset Token
app.post('/api/verify-reset-token', (req, res) => {
  const { token } = req.body;
  if (!token) {
    return res.status(400).json({ error: 'No reset token provided.' });
  }
  db.get('SELECT token FROM password_reset_tokens WHERE token = ? AND expires_at > ?', [token, Date.now()], (err, row) => {
    if (err) {
      console.error('Error verifying reset token:', err);
      return res.status(500).json({ error: 'Database error.' });
    }
    if (row) {
      res.status(200).json({ valid: true });
    } else {
      res.status(400).json({ valid: false, error: 'Invalid or expired reset link.' });
    }
  });
});

// Reset Password
app.post('/api/reset-password', async (req, res) => {
  const { token, password } = req.body;

  if (!token || !password) {
    return res.status(400).json({ error: 'Please provide the reset token and the new password.' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
  }

  try {
    db.get('SELECT user_id FROM password_reset_tokens WHERE token = ? AND expires_at > ?', [token, Date.now()], async (err, row) => {
      if (err) {
        console.error('Error finding reset token:', err);
        return res.status(500).json({ error: 'Database error.' });
      }

      if (!row) {
        return res.status(400).json({ error: 'Invalid or expired reset link.' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const userId = row.user_id;

      db.run('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, userId], (err) => {
        if (err) {
          console.error('Error updating password:', err);
          return res.status(500).json({ error: 'Could not update password.' });
        }

        db.run('DELETE FROM password_reset_tokens WHERE token = ?', [token], (err) => {
          if (err) {
            console.error('Error deleting reset token:', err);
          }
          res.status(200).json({ message: 'Password reset successfully!' });
        });
      });
    });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

// --- Other API Routes ---

// Verify Activation Code (consider moving this to a more relevant section if it's for signup)
app.post('/api/verify-activation-code', (req, res) => {
  const { code } = req.body;
  if (!code) {
    return res.status(400).json({ error: 'No activation code provided.' });
  }

  if (activationCodes.includes(code) && !usedActivationCodes.has(code)) {
    usedActivationCodes.add(code);
    res.status(200).json({ message: 'Activation code verified successfully.' });
  } else {
    res.status(400).json({ error: 'Invalid or used activation code.' });
  }
});

// Calculate Order Value (example route for your risk manager)
app.post('/api/calculate-order-value', (req, res) => {
  const { riskAmount, entryPrice, stopLossPrice } = req.body;

  if (!riskAmount || !entryPrice || !stopLossPrice) {
    return res.status(400).json({ error: 'Missing required parameters.' });
  }

  if (isNaN(riskAmount) || isNaN(entryPrice) || isNaN(stopLossPrice)) {
    return res.status(400).json({ error: 'Invalid input: Parameters must be numbers.' });
  }

  if (entryPrice <= 0 || stopLossPrice <= 0) {
    return res.status(400).json({ error: 'Invalid input: Prices must be greater than zero.' });
  }

  if (entryPrice === stopLossPrice) {
    return res.status(400).json({ error: 'Invalid input: Entry price and stop loss price cannot be the same.' });
  }

  const percentageDifference = ((entryPrice - stopLossPrice) / stopLossPrice) * 100;
  const orderValue = riskAmount / Math.abs((entryPrice - stopLossPrice) / entryPrice); // Use Math.abs for difference

  res.status(200).json({
    orderValue: orderValue.toFixed(2),
    percentageDifference: percentageDifference.toFixed(2),
  });
});

// --- Server Start ---
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});