const express = require('express');
const cors = require('cors');
const { OAuth2Client } = require('google-auth-library');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const crypto = require('crypto'); 
const nodemailer = require('nodemailer'); 
const jwt = require('jsonwebtoken');
require('dotenv').config();


const app = express();
const DEPLOYED_FRONTEND_URL = process.env.DEPLOYED_FRONTEND_URL || 'http://localhost:5173';

app.use(cors({
  origin:[
     'http://localhost:5173',
     DEPLOYED_FRONTEND_URL
  ].filter(Boolean),
  methods: 'GET,HEAD,PUT,POST,DELETE,PATCH',
  credentials: true,
}));
app.use(express.json());

const client = new OAuth2Client();
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const JWT_SECRET = process.env.JWT_SECRET;


const activationCodes = ['12345678'];
const usedActivationCodes = new Set();

const db = new sqlite3.Database('./users.db', (err) => {
    if (err) {
        console.error('Could not connect to database', err);
    } else {
        console.log('Connected to database');
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              email TEXT UNIQUE NOT NULL,
              password TEXT NOT NULL,
              username TEXT UNIQUE NOT NULL
            )
        `, (createTableErr) => {
            if (createTableErr) {
                console.error('Error creating users table:', createTableErr);
            } else {
                console.log('Users table checked/created.');
                db.run(`
                    CREATE TABLE IF NOT EXISTS password_reset_tokens (
                      token TEXT PRIMARY KEY,
                      user_id INTEGER NOT NULL,
                      expires_at INTEGER NOT NULL,
                      FOREIGN KEY (user_id) REFERENCES users(id)
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

async function verifyGoogleToken(token) {
  try {
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: CLIENT_ID
    });
    const payload = ticket.getPayload();
    const userid = payload['sub'];
    return payload;
  } catch (error) {
    console.error('Error verifying Google ID token:', error);
    return null;
  }
}

const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

function generateAuthToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '1h' }); 
}

app.post('/api/verify-google-token', async (req, res) => {
  const { token } = req.body;
  if (!token) {
    return res.status(400).json({ error: 'No Google ID token provided.' });
  }

  const payload = await verifyGoogleToken(token);
  if (payload) {
    console.log('Google ID token verified:', payload);
    res.status(200).json({ message: 'Google ID token verified successfully.', payload });
  } else {
    res.status(401).json({ error: 'Invalid Google ID token.' });
  }
});

app.post('/api/google-login', async (req, res) => {
  const { token } = req.body;
  if (!token) {
    return res.status(400).json({ message: 'Google ID token not provided' });
  }
  try {
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: CLIENT_ID 
    });
    const payload = ticket.getPayload();
    console.log('Google Payload:', payload);

    const googleName = payload?.name;
    const googleEmail = payload?.email;

    if (!googleName || !googleEmail) {
      return res.status(400).json({ message: 'Could not retrieve user information from Google' });
    }

   db.get('SELECT id, email FROM users WHERE email = ?', [googleEmail], async (err, existingUser) => {
      if (err) {
        console.error('Database error during Google login:', err);
        return res.status(500).json({ message: 'Database error during Google login' });
      }

      let userId;
      if (existingUser) {
        userId = existingUser.id;
        console.log(`Google user ${googleEmail} found.`);
        const authToken = generateAuthToken(userId);
        const userData = { id: userId, email: googleEmail, name: googleName };
        return res.json({ token: authToken, user: userData });
      } else {
          const generatedUsername = googleEmail.split('@')[0];
        db.run('INSERT INTO users (email, password, username) VALUES (?, ?, ?)', [googleEmail, 'google_login_no_password', generatedUsername], function(err) {
          if (err) {
            console.error('Error creating Google user:', err);
            if (err.message.includes('UNIQUE constraint failed: users.username')) {
              return res.status(409).json({ message: 'Username already taken. Please try with a different Google account or contact support.' });
            }
            return res.status(500).json({ message: 'Could not create Google user' });
          }
          userId = this.lastID;
          console.log(`New Google user created with ID: ${userId}`);
          const authToken = generateAuthToken(userId);
          const userData = { id: userId, email: googleEmail, name: googleName };
          return res.json({ token: authToken, user: userData });
        });
        return;
      }
    });

  } catch (error) {
    console.error('Google ID token verification failed:', error);
    return res.status(401).json({ message: 'Google login failed', error: error.message });
  }
});

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
  const orderValue = riskAmount / ((entryPrice - stopLossPrice) / entryPrice);

  res.status(200).json({
    orderValue: orderValue.toFixed(2),
    percentageDifference: percentageDifference.toFixed(2),
  });
});

function generateAuthToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '1h' });
}

app.post('/api/login', async (req, res) => {
  console.log('*** /api/login route hit! ***');
  const { identifier, password } = req.body; 

  if (!identifier || !password) {
    return res.status(400).json({ error: 'Please provide both email and password.' });
  }

  try {
    db.get('SELECT id, email, password, username FROM users WHERE email = ? OR username = ?', [identifier, identifier], async (err, user) => {

      if (err) {
        console.error('Error during login:', err);
        return res.status(500).json({ error: 'Database error during login.' });
      }

      if (!user) {
        return res.status(401).json({ error: 'Invalid email or password.' });
      }

      const passwordMatch = await bcrypt.compare(password, user.password);

      if (passwordMatch) {
        console.log(`User ${user.email} (username: ${user.username}) logged in successfully.`);
        const token = generateAuthToken(user.id);
        const userData = { id: user.id, email: user.email, username: user.username };
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


app.post('/api/logout', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1]; 

  if (token) {
    console.log(`User logged out with token: ${token.substring(0, 10)}...`);
  }

  res.status(200).json({ message: 'Logout successful' });
});

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
        return res.status(200).json({ message: 'If an account with that email exists, a reset link has been sent.' });
      }
      const resetToken = crypto.randomBytes(32).toString('hex');
      const expiresAt = Date.now() + 3600000;
      db.run('INSERT INTO password_reset_tokens (token, user_id, expires_at) VALUES (?, ?, ?)', [resetToken, user.id, expiresAt], (err) => {
        if (err) {
          console.error('Error saving reset token:', err);
          return res.status(500).json({ error: 'Could not save reset token.' });
        }

        const DEPLOYED_FRONTEND_URL = process.env.DEPLOYED_FRONTEND_URL || 'http://localhost:5173'; // Fallback for local
        const resetLink = `${DEPLOYED_FRONTEND_URL}/reset-password/${resetToken}`;

        const mailOptions = {
          from: process.env.EMAIL_FROM_ADDRESS || process.env.EMAIL_USER, // Use a specific env var, or fallback to user
          to: user.email,
          subject: 'Password Reset Request',
          html: `<p>You have requested a password reset for your account.</p><p>Click the following link to reset your password:</p><a href="${resetLink}">${resetLink}</a><p>This link will expire in 1 hour.</p><p>If you did not request this, please ignore this email.</p>`,
        };

        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            console.error('Error sending reset email:', error);
            return res.status(500).json({ error: 'Failed to send reset email.' });
          }
          console.log('Reset email sent:', info.response);
          res.status(200).json({ message: 'If an account with that email exists, a reset link has been sent.' });
        });
      });
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

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
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, row) => {
      if (err) {
        console.error('Error checking existing email', err);
        return res.status(500).json({ error: 'Database error.' });
      }
      if (row) {
        return res.status(409).json({ error: 'Email already exists.' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      db.run('INSERT INTO users (email, password, username) VALUES (?, ?, ?)', [email, hashedPassword, username], function (err) {
                if (err) {
                    console.error('Error creating user', err);
                    if (err.message.includes('UNIQUE constraint failed: users.username')) {
                      return res.status(409).json({ error: 'Username already taken.' });
                    }
                    return res.status(500).json({ error: 'Could not create user.' });
                }
                const userId = this.lastID;
                console.log(`User created with ID: ${userId}`);
                const token = generateAuthToken(userId);
                const userData = { id: userId, email: email, username: username }; 
                return res.status(201).json({ message: 'Signup successful!', token, user: userData });
            });
        });
    } catch (error) {
        console.error('Signup error:', error);
        return res.status(500).json({ error: 'Signup failed.' });
    }
});

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

const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE || 'Gmail', 
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
});

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
