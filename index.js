const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const nodemailer = require('nodemailer');
const otpStore = new Map(); // Temporarily store OTPs

const app = express();
const PORT = process.env.PORT || 5000;



require('dotenv').config();
const SECRET_KEY = process.env.SECRET_KEY;

app.use(cors());
app.use(bodyParser.json());


const db = new sqlite3.Database('./books.db', (err) => {
  if (err) {
    console.error('Could not open database', err);
  } else {
    console.log('Connected to SQLite database')
    db.run(`CREATE TABLE IF NOT EXISTS new_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  email TEXT UNIQUE,
  password TEXT,
  created_at TEXT
);
    // )`);



    // db.run(
    //   `CREATE TABLE IF NOT EXISTS users (
    //     id INTEGER PRIMARY KEY AUTOINCREMENT,
    //     username TEXT UNIQUE NOT NULL,
    //     password TEXT NOT NULL,
    //     email TEXT,
    //     created_at TEXT
    //   )`,

    //   (err) => {
    //     if (err) {
    //       console.error('Error creating users table:', err.message);
    //     } else {
    //       console.log('Users table is ready.');
    //     }
    //   }
    // );
  }
});

// Node.js (Express) Example
app.post('/api/verify-email', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  db.get('SELECT * FROM new_users WHERE email = ?', [email], (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (!row) {
      return res.status(404).json({ error: 'Email does not exist!!' });
    }

    res.status(200).json({ message: 'Email exists and is valid (:',success: true });
  });
});




app.post('/api/send-otp', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000);
    const timestamp = Date.now(); // Current timestamp in milliseconds
    

    // Prepare email data
    const templateParams = {
      to_email: email,
      subject: 'Password Reset OTP',
      message: `Your OTP is: ${otp}`,
    };

    // Send OTP email using EmailJS
    const result = await emailjs.send(
      'your_service_id', // Replace with your EmailJS service ID
      'your_template_id', // Replace with your EmailJS template ID
      templateParams,
      'your_user_id' // Replace with your EmailJS user ID
    );

    // Store OTP temporarily (you could save it in a database or memory)
    otpStore.set(email, { otp, timestamp }); // `otpStore` is an in-memory storage for OTP

    return res.status(200).json({ message: 'OTP sent successfully' });
  } catch (error) {
    console.error('Error sending OTP:', error);
    return res.status(500).json({ error: 'Failed to send OTP' });
  }
});



app.post('/api/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  const storedData = otpStore.get(email);

  if (!storedData) return res.status(400).json({ error: 'No OTP found for this email' });

  const { otp: storedOtp, timestamp } = storedData;
  const currentTime = Date.now();
  const timeDiff = (currentTime - timestamp) / 1000 / 60; // Difference in minutes

  if (timeDiff > 10) {
      otpStore.delete(email); // Delete expired OTP
      return res.status(400).json({ error: 'OTP has expired. Please request a new one.' });
  }

  if (otp !== storedOtp) return res.status(400).json({ error: 'Invalid OTP' });

  otpStore.delete(email); // Clear OTP after successful verification
  res.json({ message: 'OTP verified successfully' });
});


app.post('/api/update-password', async (req, res) => {
  const { email, newPassword } = req.body;

  const hashedPassword = await bcrypt.hash(newPassword, 10);

  db.run('UPDATE new_users SET password = ? WHERE email = ?', [hashedPassword, email], function (err) {
    if (err) {
      console.error('Error updating password:', err.message);
      return res.status(500).json({ error: 'Failed to update password' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'Email not found' });
    }

    res.json({ message: 'Password updated successfully' });
  });
});


app.post('/api/signup', async (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    // Check if the username or email already exists
    const userExists = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM new_users WHERE username = ? OR email = ?',
        [username, email],
        (err, row) => {
          if (err) return reject(err);
          resolve(row);
        }
      );
    });

    if (userExists) {
      if (userExists.username === username) {
        return res.status(400).json({ error: 'Username already exists' });
      }
      if (userExists.email === email) {
        return res.status(400).json({ error: 'Email already exists' });
      }
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Get the current date and time for the created_at field
    const createdAt = new Date().toISOString();

    // Insert the new user into the database
    await new Promise((resolve, reject) => {
      db.run(
        'INSERT INTO new_users (username, password, email, created_at) VALUES (?, ?, ?, ?)',
        [username, hashedPassword, email, createdAt],
        function (err) {
          if (err) return reject(err);
          resolve();
        }
      );
    });

    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error('Error during signup:', err.message);
    res.status(500).json({ error: 'An error occurred during registration' });
  }
});


// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization') && req.header('Authorization').split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Signup Route (POST /api/signup)
app.post('/api/signup', async (req, res) => {
  const { username, password, email } = req.body;

  // Check if the username already exists
  db.get('SELECT * FROM new_users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (user) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    // Hash the password before storing it
    const hashedPassword = await bcrypt.hash(password, 10);
    const createdAt = new Date().toISOString();

    // Insert the new user into the database
    db.run('INSERT INTO new_users (username, password, email, created_at) VALUES (?, ?, ?, ?)',
      [username, hashedPassword, email, createdAt],
      function (err) {
        if (err) {
          return res.status(500).json({ error: 'An error occurred during registration' });
        }
        res.status(201).json({ message: 'User registered successfully' });
      }
    );
  });
});

// Login Route (POST /api/login)
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  // Query the users table to find a user with the given username
  db.get('SELECT * FROM new_users WHERE username = ?', [username], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Compare the password with the hashed password stored in the database
    bcrypt.compare(password, user.password, (err, isPasswordValid) => {
      if (err || !isPasswordValid) {
        return res.status(401).json({ error: 'Invalid username or password' });
      }

      // Generate a JWT token if the password is correct
      const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '24h' });

      // Send the response with the token
      res.json({ message: 'Login successful', token });
    });
  });
});

// Protected Route: View Users (GET /api/users)
app.get('/api/users', authenticateToken, (req, res) => {
  // Only allow 'ravi' to view users
  if (req.user.username !== 'ravi') {
    return res.status(403).json({ error: 'Access denied. Only Ravi{admin} can view users.' });
  }

  db.all('SELECT id, username, email, created_at FROM new_users', (err, rows) => {
    if (err) {
      return res.status(500).json({ message: 'Error retrieving users' });
    }
    res.json({ users: rows });
  });

});

// Delete User (DELETE /api/users/:id)
app.delete('/api/users/:id', authenticateToken, (req, res) => {
  // Only allow 'ravi' to delete users
  if (req.user.username !== 'ravi') {
    return res.status(403).json({ error: 'Access denied. Only ravi can delete users.' });
  }

  const userId = req.params.id;

  // Deleting the user from the database
  db.run('DELETE FROM new_users WHERE id = ?', [userId], function (err) {
    if (err) {
      return res.status(500).json({ message: 'Error deleting user' });
    }
    if (this.changes === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(204).json({ message: 'User deleted successfully' }).end();
  });
});


// Books Routes
app.get('/books', (req, res) => {
  db.all('SELECT * FROM booksData', (err, rows) => {
    if (err) {
      return res.status(500).json({ message: 'Error retrieving books' });
    }
    res.json(rows);
  });
});

// Add a new book (POST /books)
app.post('/books', authenticateToken, (req, res) => {
  const { Title, Author, Genre, Pages, PublishedDate } = req.body;

  const sql = 'INSERT INTO booksData (Title, Author, Genre, Pages, PublishedDate) VALUES (?, ?, ?, ?, ?)';
  const params = [Title, Author, Genre, Pages, PublishedDate];

  db.run(sql, params, function (err) {
    if (err) {
      return res.status(500).json({ message: 'Error adding book' });
    }
    res.status(201).json({
      BookID: this.lastID,
      Title,
      Author,
      Genre,
      Pages,
      PublishedDate,
    });
  });
});

// Get a specific book by ID
app.get('/books/:id', (req, res) => {
  const bookId = req.params.id;
  db.get('SELECT * FROM booksData WHERE BookID = ?', [bookId], (err, row) => {
    if (err) {
      return res.status(500).json({ message: 'Error retrieving book' });
    }
    res.json(row || {});
  });
});

// Update a book (PUT /books/:id)
app.put('/books/:id', authenticateToken, (req, res) => {
  const bookId = req.params.id;
  const { Title, Author, Genre, Pages, PublishedDate } = req.body;

  const sql = `UPDATE booksData SET Title = ?, Author = ?, Genre = ?, Pages = ?, PublishedDate = ? WHERE BookID = ?`;
  const params = [Title, Author, Genre, Pages, PublishedDate, bookId];

  db.run(sql, params, function (err) {
    if (err) {
      return res.status(500).json({ message: 'Error updating book' });
    }
    if (this.changes === 0) {
      return res.status(404).json({ message: 'Book not found' });
    }
    res.json({ message: 'Book updated successfully' });
  });
});

// Delete a book (DELETE /books/:id)
app.delete('/books/:id', authenticateToken, (req, res) => {
  const bookId = req.params.id;
  db.run('DELETE FROM booksData WHERE BookID = ?', [bookId], function (err) {
    if (err) {
      return res.status(500).json({ message: 'Error deleting book' });
    }
    if (this.changes === 0) {
      return res.status(404).json({ message: 'Book not found' });
    }
    res.status(204).end();
  });
});


app.listen(PORT, () => console.log(`Server running on port ${PORT}`));