const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const argon2 = require('argon2');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const winston = require('winston');


const app = express();
const port = 3000;

// Connect to SQLite database
const path = "D:/Not your space#/Jai Allahabadi/Cybsersecurity/Secure web development/Programmes/mynodeproject/simple-login-page/Database/Node_Login.db"

const db = new sqlite3.Database(path, (err) => {
    if (err) {
        console.error('Error connecting to database:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
    }
});

// Set EJS as the view engine
app.set('view engine', 'ejs');

// Middleware to parse JSON and urlencoded request bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Include Express Validator Functions
const { check, validationResult, body } = require('express-validator');
const { Console } = require('winston/lib/winston/transports');

// Session middleware
app.use(session({
    name: 'mySessionCookie', // Custom cookie name
    secret: 'your-secret-key', 
    resave: false,
    saveUninitialized: true,
     // Set secure option to true for production environment
     cookie: {
        secure: false, // Ensure cookies are only sent over HTTPS
        httpOnly: true, // Prevent cookies from being accessed via JavaScript
        maxAge: 24 * 60 * 60 * 1000 // Set session expiry time (e.g., 1 day)
    } 
}));



// Routes
app.get('/', (req, res) => {
    res.render('login');
});

// Validation middleware for login form
const validateLoginForm = [
    // Sanitize username and password to remove special characters
    body('username').trim()
    .notEmpty().withMessage('Username is required')
    .matches(/^[a-zA-Z0-9_@]+$/).withMessage('Username must contain only alphanumeric characters, underscores, and "@" symbol'),
    body('password').trim()
    .notEmpty().withMessage('Password is required')
    .matches(/^[a-zA-Z0-9_@]+$/).withMessage('Password must contain valid characters'),
];


app.post('/login', validateLoginForm, async (req, res) => {
    console.log("hii user pre process",req.body);

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // console.log("Hi inside 81", errors);
        return res.status(400).json({ errors: errors.array() });
    }

    const username = req.body.username;
    const password = req.body.password;
    try {
        // Retrieve hashed password from database
        db.get('SELECT * FROM users WHERE username = ?', [username], async (err, row) => {
            if (err) {
                console.error('Database error:', err.message);
                return res.status(500).send('Error occurred. Please try again.');
            }
            if (!row) {
                console.log("Hi inside 88");
                return res.status(400).send('Incorrect username or password.'); // User not found
            }
            // Verify password using Argon2
            const passwordMatch = await argon2.verify(row.password, password);
            if (!passwordMatch) {
                console.log("Hi inside password hashing");
                return res.status(400).send('Incorrect username or password.'); // Incorrect password
            }
            // Set user session data
            req.session.user = { username };
            // Redirect to dashboard upon successful login
            res.redirect('/dashboard');
        });
    } catch (error) {
        console.error('Error verifying password:', error);
        res.status(500).send('Error occurred while verifying password. Please try again.');
    }
});



// Authentication middleware to check if user is logged in
const authenticateUser = (req, res, next) => {
    if (req.session.user) {
        // User is logged in
        next(); // Continue to the next middleware or route handler
    } else {
        // User is not logged in
        res.redirect('/login'); // Redirect to the login page
    }
};

// Authorization middleware to check if user is admin
const authorizeAdmin = (req, res, next) => {
    if (req.session.user && req.session.user.username === 'admin') {
        // User is admin
        next(); // Continue to the next middleware or route handler
    } else {
        // User is not admin
        res.status(403).send('Access Forbidden'); // Return 403 Forbidden status
    }
};

// Define routes for admin functionalities
app.get('/admin/program', authenticateUser, authorizeAdmin, (req, res) => {
    // Fetch all courses from the database
    let subjects = []; 
    db.all('SELECT * FROM subjects;', (err, rows) => {
        if (err) {
            console.error('Error fetching subjects:', err.message);
            return res.status(500).send('Internal server error');
        }
        
        subjects = rows; // Assign retrieved subjects to the subjects variable
        
        res.render('admin/program.ejs', { subjects: subjects });
    });
});

app.get('/admin/faculty', authenticateUser, authorizeAdmin, (req, res) => {
    // Fetch all subjects from the database
    db.all('SELECT * FROM faculty;', (err, rows) => {
        if (err) {
            console.error('Error fetching subjects:', err.message);
            return res.status(500).send('Internal server error');
        }
        res.render('admin/faculty', { faculty: rows });
    });
});

//  routes for research topics

app.get('/admin/research', authenticateUser, authorizeAdmin, (req, res) => {
    // Fetch all subjects from the database
    db.all('SELECT * FROM research_choices;', (err, rows) => {
        if (err) {
            console.error('Error fetching research choices:', err.message);
            return res.status(500).send('Internal server error');
        }
        
        const researchChoices = rows;
        res.render('admin/research', { researchChoices });
    });
});


app.get('/dashboard', (req, res) => {
    // Check if user is logged in
    if (!req.session.user) {
        return res.redirect('/');
    }
    // Fetch user details from session
    const user = req.session.user;
    res.render('dashboard', { user });
});



app.get('/dashboard', (req, res) => {
    
    // For simplicity, assuming the user is logged in and the user object is available in the session
    const user = users[0]; 
    res.render('dashboard', { user });
});

app.get('/logout', (req, res) => {
    // Destroy user session to log out
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err.message);
            return res.send('Error occurred while logging out. Please try again.');
        }
        res.redirect('/');
    });
});

app.post('/profile', async (req, res) => {
    if (!req.session.user) {
        return res.redirect('/');
    }

    const { name, mobileNumber, location, address, email, summary } = req.body;
    const username = req.session.user.username;

    try {
        const userProfile = await getUserProfile(username);
        if (userProfile) {
            await updateProfile(username, name, mobileNumber, location, address, email, summary);
        } else {
            await addProfile(username, name, mobileNumber, location, address, email, summary);
        }
        res.redirect('/dashboard');
    } catch (err) {
        console.error('Error updating/adding user profile:', err.message);
        res.send('Error occurred while updating profile. Please try again.');
    }
});

const getUserProfile = (username) => {
    return new Promise((resolve, reject) => {
        const query = 'SELECT * FROM profile WHERE username = ?';
        db.get(query, [username], (err, row) => {
            if (err) {
                reject(err);
            } else {
                resolve(row);
            }
        });
    });
};

const updateProfile = (username, name, mobileNumber, location, address, email, summary) => {
    return new Promise((resolve, reject) => {
        const query = `UPDATE profile 
                       SET name = ?, mobileNumber = ?, location = ?, address = ?, email = ?, summary = ? 
                       WHERE username = ?`;
        const params = [name, mobileNumber, location, address, email, summary, username];
        db.run(query, params, (err) => {
            if (err) {
                reject(err);
            } else {
                resolve();
            }
        });
    });
};

const addProfile = (username, name, mobileNumber, location, address, email, summary) => {
    return new Promise((resolve, reject) => {
        const query = `INSERT INTO profile (username, name, mobileNumber, location, address, email, summary) 
                       VALUES (?, ?, ?, ?, ?, ?, ?)`;
        const params = [username, name, mobileNumber, location, address, email, summary];
        db.run(query, params, (err) => {
            if (err) {
                reject(err);
            } else {
                resolve();
            }
        });
    });
};


//  route handler for the profile page
app.get('/profile', (req, res) => {
    // Check if user is logged in
    if (!req.session.user) {
        return res.redirect('/');
    }
    // Fetch user details from session
    const user = req.session.user;
    // Render the update profile page and pass the user data to it
    res.render('profile', { user });
});



//  route handler for the contact page
app.get('/contact', (req, res) => {
    res.render('contact'); // Render the contact page template
});

app.post('/contact', (req, res) => {
    const { name, email, phone, address, message } = req.body;

    db.run('BEGIN TRANSACTION', () => {
        db.run('INSERT INTO contact_info (name, email, phone, address, message) VALUES (?, ?, ?, ?, ?)', [name, email, phone, address, message], (err) => {
            if (err) {
                console.error('Error inserting into database:', err.message);
                db.run('ROLLBACK');
                return res.send('Error occurred. Please try again.');
            }
            db.run('COMMIT', () => {
                res.render('thankyou', { message: 'Thank you, our team will respond to your request shortly.' });
            });
        });
    });
});



//  route handler for program page
app.get('/program', (req, res) => {
    // Check if user is logged in
    if (!req.session.user) {
        return res.redirect('/');
    }
    if (req.session.user.username === 'admin') {
        // If user is admin, redirect to admin program page
        return res.redirect('/admin/program');
    }
    
    let subjects = []; 

    db.all('SELECT * FROM subjects WHERE course = (select course from users where username= ?);', req.session.user['username'], (err, rows) => {
        if (err) {
            console.error('Error fetching subjects:', err.message);
            return res.status(500).send('Internal server error');
        }
        
        subjects = rows; // Assign retrieved subjects to the subjects variable
        
        res.render('program.ejs', { subjects: subjects });
    });
});

//  route handler for the faculty page
app.get('/faculty', (req, res) => {
    // Check if user is logged in
    if (!req.session.user) {
        return res.redirect('/');
    }
    if (req.session.user.username === 'admin') {
        // If user is admin, redirect to admin program page
        return res.redirect('/admin/faculty');
    }
    
    db.all('SELECT * FROM faculty WHERE course = (SELECT course FROM users WHERE username = ?)', [req.session.user.username], (err, rows) => {
        if (err) {
            console.error('Error fetching faculty:', err.message);
            return res.status(500).send('Internal server error');
        }
        res.render('faculty', { faculty: rows });
    });
});

//  route handler for research page
app.get('/research', (req, res) => {
    // Check if user is logged in
    if (!req.session.user) {
        return res.redirect('/');
    }
    if (req.session.user.username === 'admin') {
        // If user is admin, redirect to admin program page
        return res.redirect('/admin/research');
    }
        db.all('SELECT * FROM research_choices WHERE course = (SELECT course FROM users WHERE username = ?);', req.session.user['username'], (err, rows) => {
            if (err) {
                console.error('Error fetching research choices:', err.message);
                return res.status(500).send('Internal server error');
            }
            
            const researchChoices = rows;
            res.render('research', { researchChoices });
        });
});

    


//  route handler for delete profile page
app.get('/delete_profile', (req, res) => {
    db.run('DELETE FROM users WHERE username = ?', [req.session.user.username], (err) => {
        if (err) {
            console.error('Error deleting profile:', err.message);
            return res.status(500).send('Internal server error');
        }
        res.render('thankyou', { message: 'Account has been deleted.' });
    });
});




// Create a Winston logger
const logger = winston.createLogger({
    level: 'info', // Set the minimum logging level
    format: winston.format.combine(
        winston.format.timestamp(), // Add timestamp to log entries
        winston.format.json() // Log entries in JSON format
    ),
    transports: [
        new winston.transports.File({ filename: 'logfile.log' }) // Log to a file
    ]
});

// Middleware to log login and logout events
const logEvents = (req, res, next) => {
    if (req.path === '/login' && req.method === 'POST') {
        logger.info('User logged in', { username: req.body.username, timestamp: new Date() });
    } else if (req.path === '/logout' && req.method === 'GET') {
        logger.info('User logged out', { username: req.session.user.username, timestamp: new Date() });
    }
    next();
};

// Use the logEvents middleware
app.use(logEvents);

// Set up csurf middleware
const csrfProtection = csrf({ cookie: true });
app.use(cookieParser());
app.use(csrfProtection);


app.get('/signup', csrfProtection, (req, res) => {
    console.log(req.csrfToken());
    res.render('signup', { csrfToken: req.csrfToken() });
});


// Validation middleware for sign-up form
const validateSignupForm = [
    // Sanitize username, password, name, and course to remove special characters
    body('username').trim().escape(),
    body('password').trim(),
    body('name').trim().escape(),
    body('course').trim().escape(),

    // Validate username, password, name, and course
    body('username')
        .notEmpty().withMessage('Username is required')
        .matches(/^[a-zA-Z0-9_]+$/).withMessage('Username must contain only alphanumeric characters and underscores'),

    body('password')
        .notEmpty().withMessage('Password is required')
        .matches(/^[^\*\s<>;=]+$/).withMessage('Password must not contain *<>;= characters'),

    body('name')
        .notEmpty().withMessage('Name is required')
        .matches(/^[a-zA-Z\s]+$/).withMessage('Name must contain only alphabet characters'),

    body('course')
        .notEmpty().withMessage('Course is required')
];


app.post('/signup', validateSignupForm, csrfProtection, async (req, res) => {
    if (!req.csrfToken()) {
        return res.status(403).send('CSRF token invalid');
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password, name, course } = req.body;

    try {
        // Hash the password
        const hashedPassword = await argon2.hash(password);
        
        // Insert user into database with hashed password
        db.run('BEGIN TRANSACTION', () => {
            db.run('INSERT INTO users (username, password, name, course) VALUES (?, ?, ?, ?)', [username, hashedPassword, name, course], (err) => {
                if (err) {
                    console.error('Error inserting into database:', err.message);
                    db.run('ROLLBACK');
                    return res.status(500).send('Error occurred. Please try again.');
                }
                db.run('COMMIT', () => {
                    res.redirect('/');
                });
            });
        });
    } catch (error) {
        console.error('Error hashing password:', error);
        res.status(500).send('Error occurred while hashing password. Please try again.');
    }
});

app.use(express.static('public'));

// Start the server
app.listen(port, () => {
    console.log(`Server is listening on port ${port}`);
});