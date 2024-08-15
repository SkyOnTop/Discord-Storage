const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const axios = require('axios');
const crypto = require('crypto');
const zlib = require('zlib');
const mongoose = require('mongoose');
const FormData = require('form-data');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    files: [
        {
            id: Number,
            originalName: String,
            discordAttachments: [String],
        },
    ],
});

const User = mongoose.model('User', userSchema);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: true,
}));

app.use(express.static('public'));

function authMiddleware(req, res, next) {
    if (req.session.loggedIn) {
        next();
    } else {
        res.redirect('/login');
    }
}

app.get('/dashboard', (req, res) => {
    return res.redirect('/dashboard/home');
});

app.post('/dashboard', (req, res) => {
    return res.redirect('/login');
});

app.get('/', (req, res) => {
    res.redirect('/dashboard');
});

app.get('/login', (req, res) => {
    if (req.session.loggedIn) {
        return res.redirect('/dashboard/home');
    }
    res.sendFile(__dirname + '/public/login.html');
});

app.get('/signup', (req, res) => {
    res.sendFile(__dirname + '/public/signup.html');
});

app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    const existingUser = await User.findOne({ username });

    if (existingUser) {
        return res.send('User already exists!');
    }

    const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(password)) {
        return res.send('Password must be at least 8 characters long, include one uppercase letter, one number, and one special character.');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword, files: [] });
    await newUser.save();

    res.redirect('/login');
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.send('Invalid credentials');
    }

    req.session.loggedIn = true;
    req.session.username = username;
    res.redirect('/dashboard/home');
});

app.get('/dashboard/home', authMiddleware, async (req, res) => {
    res.sendFile(__dirname + '/public/dashboard.html');
});


const upload = multer({ storage: multer.memoryStorage() });

app.get('/api/files', authMiddleware, async (req, res) => {
    const user = await User.findOne({ username: req.session.username });
    const files = user.files.map(file => ({
        id: file.id,
        originalName: file.originalName,
    }));

    res.json({ files });
});


async function chunkFile(file) {
    const fileBuffer = file.buffer;
    const chunkSize = 8 * 1024 * 1024;
    const chunks = [];

    for (let i = 0; i < fileBuffer.length; i += chunkSize) {
        const chunk = fileBuffer.slice(i, i + chunkSize);
        chunks.push(chunk);
    }

    return chunks;
}

app.post('/upload', authMiddleware, upload.single('file'), async (req, res) => {
    const file = req.file;
    const username = req.session.username;
    const user = await User.findOne({ username });

    if (!file) {
        return res.status(400).send('No file uploaded');
    }

    try {
        const fileChunks = await chunkFile(file);
        const discordAttachments = [];

        for (const chunk of fileChunks) {
            const attachmentUrl = await sendToDiscordWebhook(chunk, file.originalname);
            discordAttachments.push(attachmentUrl);
        }

        user.files.push({
            id: Date.now(),
            originalName: file.originalname,
            discordAttachments: discordAttachments,
        });

        await user.save();
        res.redirect('/dashboard/home');
    } catch (error) {
        console.error(error);
        res.status(500).send('Error processing the file');
    }
});

app.get('/download/:id', authMiddleware, async (req, res) => {
    const username = req.session.username;
    const fileId = parseInt(req.params.id, 10);
    const user = await User.findOne({ username });
    const fileData = user.files.find(f => f.id === fileId);

    if (!fileData) {
        return res.status(404).send('File not found');
    }

    try {
        const fileChunks = [];

        for (const attachmentUrl of fileData.discordAttachments) {
            const chunk = await downloadFromDiscord(attachmentUrl);
            fileChunks.push(chunk);
        }

        const fileBuffer = Buffer.concat(fileChunks);

        res.setHeader('Content-Disposition', `attachment; filename="${fileData.originalName}"`);
        res.setHeader('Content-Type', 'application/octet-stream');
        res.send(fileBuffer);

    } catch (error) {
        console.error(error);
        res.status(500).send('Error downloading the file');
    }
});


app.post('/delete/:id', authMiddleware, async (req, res) => {
    const username = req.session.username;
    const fileId = parseInt(req.params.id, 10);
    const user = await User.findOne({ username });

    const fileIndex = user.files.findIndex(f => f.id === fileId);

    if (fileIndex === -1) {
        return res.status(404).send('File not found');
    }

    const fileData = user.files[fileIndex];
    for (const attachmentUrl of fileData.discordAttachments) {
        await deleteFromDiscord(attachmentUrl);
    }

    user.files.splice(fileIndex, 1);
    await user.save();

    res.send('File deleted successfully');
});

async function chunkAndCompressFile(file) {
    const fileBuffer = file.buffer;

    const chunkSize = 8 * 1024 * 1024;
    const chunks = [];

    for (let i = 0; i < fileBuffer.length; i += chunkSize) {
        const chunk = fileBuffer.slice(i, i + chunkSize);
        const compressedChunk = zlib.gzipSync(chunk);
        chunks.push(compressedChunk);
    }

    return chunks;
}


function obfuscateData(data) {
    const iv = crypto.randomBytes(16);
    const key = crypto.createHash('sha256').update(String(process.env.OBFUSCATION_KEY || 'default_key')).digest('base64').substr(0, 32);
    const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
    let encrypted = cipher.update(data);
    encrypted = Buffer.concat([iv, encrypted, cipher.final()]);
    return encrypted;
}

function deobfuscateData(data) {
    const iv = data.slice(0, 16);
    const encryptedData = data.slice(16);
    const key = crypto.createHash('sha256').update(String(process.env.OBFUSCATION_KEY || 'default_key')).digest('base64').substr(0, 32);
    const decipher = crypto.createDecipheriv('aes-256-ctr', key, iv);
    let decrypted = decipher.update(encryptedData);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted;
}

async function sendToDiscordWebhook(chunk, filename) {
    const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
    const formData = new FormData();
    formData.append('file', chunk, filename);

    try {
        const response = await axios.post(webhookUrl, formData, {
            headers: formData.getHeaders(),
            maxBodyLength: Infinity,
        });

        if (response.status === 200 && response.data.attachments && response.data.attachments.length > 0) {
            return response.data.attachments[0].url;
        } else {
            throw new Error('Failed to upload chunk to Discord');
        }
    } catch (error) {
        console.error(`Failed to upload chunk: ${error.message}`);
        throw error;
    }
}


async function downloadFromDiscord(attachmentUrl) {
    const response = await axios.get(attachmentUrl, { responseType: 'arraybuffer' });
    return Buffer.from(response.data);
}

async function deleteFromDiscord(attachmentUrl) {
    // Not finished
}

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});