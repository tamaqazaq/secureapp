const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const path = require('path');
const ejs = require('ejs');
const multer = require('multer');
const fs = require('fs');

dotenv.config();
const app = express();

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: process.env.SESSION_SECRET || 'secret',
    resave: false,
    saveUninitialized: false
}));

mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.log('MongoDB Connection Error:', err));

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    failedAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date, default: null }
});
const User = mongoose.model('User', userSchema);

const uploadDir = path.join(__dirname, 'public/uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'public/uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

const uploadedPhotos = [];

app.get('/', async (req, res) => {
    try {
        const users = await User.find(); // Fetch users from database
        res.render('index', { user: req.session.user, photos: uploadedPhotos, users }); // Pass users
    } catch (err) {
        console.error('Error fetching users:', err);
        res.status(500).send('Server Error');
    }
});

app.get('/login', (req, res) => res.render('login', { error: null, remainingAttempts: 5 }));
app.get('/register', (req, res) => res.render('register', { error: null }));

app.get('/users', async (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const users = await User.find();
    res.render('users', { users, user: req.session.user });
});

function validateForm(username, password) {
    if (!username || !password) return 'All fields are required';
    if (password.length < 6) return 'Password must be at least 6 characters';
    return null;
}

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const error = validateForm(username, password);
    if (error) return res.render('register', { error });

    if (await User.findOne({ username })) {
        return res.render('register', { error: 'Username already taken' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ username, password: hashedPassword });
    res.redirect('/login');
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user) {
        return res.render('login', { error: 'Invalid username or password', remainingAttempts: 5 });
    }

    const now = new Date();

    if (user.lockUntil && user.lockUntil <= now) {
        user.failedAttempts = 0;
        user.lockUntil = null;
        await user.save();
    }

    if (user.lockUntil && user.lockUntil > now) {
        const minutesLeft = Math.ceil((user.lockUntil - now) / 60000);
        return res.render('login', {
            error: `Account locked. Try again in ${minutesLeft} minute(s).`,
            remainingAttempts: 0
        });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
        user.failedAttempts = (user.failedAttempts || 0) + 1;

        if (user.failedAttempts >= 5) {
            user.lockUntil = new Date(now.getTime() + 15 * 60000); // Lock for 15 minutes
            await user.save();
            return res.render('login', {
                error: 'Too many failed attempts. Your account is locked for 15 minutes.',
                remainingAttempts: 0
            });
        }

        await user.save();
        return res.render('login', {
            error: 'Invalid username or password',
            remainingAttempts: 5 - user.failedAttempts
        });
    }

    user.failedAttempts = 0;
    user.lockUntil = null;
    await user.save();

    req.session.user = user;
    res.redirect('/');
});


app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/')));

app.post('/users/delete/:id', async (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    await User.findByIdAndDelete(req.params.id);
    res.redirect('/users');
});

app.post('/upload', upload.single('image'), (req, res) => {
    if (!req.file) return res.status(400).send('No file uploaded.');
    const filePath = '/uploads/' + req.file.filename;
    uploadedPhotos.push(filePath);
    res.redirect('/');
});

app.post('/delete-image', (req, res) => {
    const { image_path } = req.body;
    const filePath = path.join(__dirname, 'public', image_path);
    fs.unlink(filePath, err => {
        if (err) return res.status(500).send('Error deleting photo');
        const index = uploadedPhotos.indexOf(image_path);
        if (index !== -1) uploadedPhotos.splice(index, 1);
        res.redirect('/');
    });
});
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.redirect('/');
        }
        res.redirect('/login'); // Redirect to login after logout
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
