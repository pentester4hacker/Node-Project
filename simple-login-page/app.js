const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');


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

// Session middleware
app.use(session({
    name: 'mySessionCookie', // Custom cookie name
    secret: 'your-secret-key', // Change this to a secret key for session encryption
    resave: false,
    saveUninitialized: true,
    httpOnly: true,
     // Set secure option to true for production environment
     secure: process.env.NODE_ENV === 'production' // Checks if the application is running in production
}));




// Routes
app.get('/', (req, res) => {
    res.render('login');
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    // Query the database for user credentials
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
        if (err) {
            console.error(err.message);
            return res.send('Error occurred. Please try again.');
        }
        if (!row) {
            return res.send('User not found.');
        }
        if (row.password !== password) {
            return res.send('Invalid password.');
        }
        // Set user session data
        req.session.user = { username };
        // Redirect to dashboard upon successful login
        res.redirect('/dashboard');
    });
});

app.get('/signup', (req, res) => {
    res.render('signup');
});

app.post('/signup', (req, res) => {
    const { username, password } = req.body;
    // Insert user credentials into the database within a transaction
    db.run('BEGIN TRANSACTION', () => {
        db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, password], (err) => {
            if (err) {
                console.error('Error inserting into database:', err.message);
                db.run('ROLLBACK');
                return res.send('Error occurred. Please try again.');
            }
            db.run('COMMIT');
            res.redirect('/');
        });
    });
});

app.get('/dashboard', (req, res) => {
    // For simplicity, assuming the user is logged in and the user object is available in the session
    const user = { username: 'test_user' }; // Dummy user for now
    res.render('dashboard', { user });
});

app.post('/update-profile', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/');
    }
    const { name, mobileNumber, location, address, email, summary } = req.body;
    const username = 'test_user'; // Dummy user for now
    // Update the user's profile in the database
    db.run(
        'UPDATE profile SET name = ?, mobileNumber = ?, location = ?, address = ?, email = ?, summary = ? WHERE username = ?',
        [name, mobileNumber, location, address, email, summary, username],
        (err) => {
            if (err) {
                console.error('Error updating user profile:', err.message);
                return res.send('Error occurred while updating profile. Please try again.');
            }
            // Redirect to the dashboard after successful profile update
            res.redirect('/dashboard');
        }
    );
});



app.get('/dashboard', (req, res) => {
    // In a real application, you would check if the user is logged in
    // For simplicity, assuming the user is logged in and the user object is available in the session
    const user = users[0]; // Assuming the first user in the array
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

// Start the server
app.listen(port, () => {
    console.log(`Server is listening on port ${port}`);
});