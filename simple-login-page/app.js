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
    secret: 'your-secret-key', 
    resave: false,
    saveUninitialized: true,
    httpOnly: true,
     // Set secure option to true for production environment
     secure: process.env.NODE_ENV === 'production' 
}));



// Routes
app.get('/', (req, res) => {
    res.render('login');
});

app.post('/login', (req, res) => {
    console.log('inside body login',req.body); 
    const { username, password } = req.body;
   
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
        if (err) {
            console.error('Database error:',err.message);
            return res.status(500).send('Error occurred. Please try again.');
        }
        if (!row) {
            return res.send('Incorrect username or password.'); // User not found or incorrect credentials
        }
        // Check if the password matches
        if (row.password !== password) {
            return res.send('Incorrect username or password.'); // Incorrect password
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
    const { username, password, name,course } = req.body; // Extract form data

    
    db.run('BEGIN TRANSACTION', () => {
        db.run('INSERT INTO users (username, password,name, course) VALUES (?, ?, ?, ?)', [username, password,name, course], (err) => {
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
    const { course } = req.session.user['username'];
    
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
    
    // Fetch faculty data based on the logged-in user's course
    const username = req.session.user.username;
    db.all('SELECT * FROM faculty WHERE course = (SELECT course FROM users WHERE username = ?)', username, (err, rows) => {
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


app.use(express.static('public'));

// Start the server
app.listen(port, () => {
    console.log(`Server is listening on port ${port}`);
});