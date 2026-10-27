require('dotenv').config();

const crypto = require('node:crypto');
const path = require('node:path');
const bcrypt = require('bcryptjs');
const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const multer = require('multer');

const app = express();
const port = Number(process.env.PORT || 3000);
const mongoUri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/campusshare';
const jwtSecret = process.env.JWT_SECRET || (
  process.env.NODE_ENV === 'production'
    ? ''
    : crypto.randomBytes(32).toString('hex')
);
const collegeEmailPattern = /@.*\.(edu|ac\.in|college)$/i;
const resourceCategories = new Set(['notes', 'papers', 'projects', 'books']);
const allowedFileTypes = new Map([
  ['.pdf', 'application/pdf'],
  ['.txt', 'text/plain'],
  ['.doc', 'application/msword'],
  ['.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
  ['.ppt', 'application/vnd.ms-powerpoint'],
  ['.pptx', 'application/vnd.openxmlformats-officedocument.presentationml.presentation']
]);

if (!jwtSecret || jwtSecret.length < 32) {
  throw new Error('JWT_SECRET must be set to a secret at least 32 characters long.');
}

if (!process.env.JWT_SECRET && process.env.NODE_ENV !== 'production') {
  console.warn('JWT_SECRET is not set; using a temporary development secret. Set it in .env to preserve sessions across restarts.');
}

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true }
}, { timestamps: true });

const resourceSchema = new mongoose.Schema({
  title: { type: String, required: true, maxlength: 160, trim: true },
  course: { type: String, required: true, maxlength: 100, trim: true },
  description: { type: String, required: true, maxlength: 2000, trim: true },
  category: { type: String, required: true, enum: [...resourceCategories] },
  fileName: { type: String, maxlength: 255 },
  fileType: { type: String },
  fileData: { type: Buffer },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Resource = mongoose.model('Resource', resourceSchema);

app.use(express.json({ limit: '10kb' }));
const uploadResourceFile = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, callback) => {
    const extension = path.extname(file.originalname).toLowerCase();
    if (!allowedFileTypes.has(extension)) {
      const error = new Error('Choose a PDF, TXT, DOC, DOCX, PPT, or PPTX file.');
      error.code = 'UNSUPPORTED_RESOURCE_FILE';
      return callback(error);
    }
    return callback(null, true);
  }
});

app.use((req, res, next) => {
  const origin = req.get('origin');
  const isLocalOrigin = origin === 'null' || /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(origin || '');

  if (isLocalOrigin) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.vary('Origin');
  }

  if (req.method === 'OPTIONS' && req.path.startsWith('/api/')) {
    return res.sendStatus(isLocalOrigin ? 204 : 403);
  }

  return next();
});

function createToken(user) {
  return jwt.sign({ sub: user.id }, jwtSecret, { expiresIn: '7d' });
}

function requireAuthentication(req, res, next) {
  const authorization = req.get('authorization') || '';
  const [scheme, token] = authorization.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Please log in to continue.' });
  }

  try {
    req.userId = jwt.verify(token, jwtSecret).sub;
    return next();
  } catch {
    return res.status(401).json({ error: 'Your session has expired. Please log in again.' });
  }
}

app.post('/api/auth/signup', async (req, res, next) => {
  try {
    const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';

    if (!collegeEmailPattern.test(email)) {
      return res.status(400).json({ error: 'Use a valid college email address to continue.' });
    }

    if (password.length < 8 || Buffer.byteLength(password, 'utf8') > 72) {
      return res.status(400).json({ error: 'Password must be between 8 characters and 72 bytes long.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ email, passwordHash });

    return res.status(201).json({
      token: createToken(user),
      user: { email: user.email }
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }
    return next(error);
  }
});

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';

    if (!email || !password) {
      return res.status(400).json({ error: 'Please enter both your email and password.' });
    }

    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    return res.json({
      token: createToken(user),
      user: { email: user.email }
    });
  } catch (error) {
    return next(error);
  }
});

app.get('/api/auth/me', requireAuthentication, async (req, res, next) => {
  try {
    const user = await User.findById(req.userId).select('email');
    if (!user) {
      return res.status(401).json({ error: 'Your account could not be found. Please log in again.' });
    }
    return res.json({ user: { email: user.email } });
  } catch (error) {
    return next(error);
  }
});

app.get('/api/resources', async (req, res, next) => {
  try {
    const resources = await Resource.find()
      .select('-fileData')
      .sort({ createdAt: -1 })
      .limit(100)
      .lean();

    return res.json({
      resources: resources.map((resource) => ({
        ...resource,
        category: resource.category || 'notes',
        hasFile: Boolean(resource.fileName)
      }))
    });
  } catch (error) {
    return next(error);
  }
});

app.post('/api/resources', requireAuthentication, uploadResourceFile.single('file'), async (req, res, next) => {
  try {
    const { title, course, description, category } = req.body;

    if (![title, course, description].every((value) => typeof value === 'string' && value.trim())) {
      return res.status(400).json({ error: 'Please fill in the title, course, and description.' });
    }

    if (title.length > 160 || course.length > 100 || description.length > 2000) {
      return res.status(400).json({ error: 'The resource details exceed the allowed length.' });
    }

    if (!resourceCategories.has(category)) {
      return res.status(400).json({ error: 'Choose a valid resource category.' });
    }

    const file = req.file;
    const fileType = file ? allowedFileTypes.get(path.extname(file.originalname).toLowerCase()) : undefined;
    const resource = await Resource.create({
      title: title.trim(),
      course: course.trim(),
      description: description.trim(),
      category,
      fileName: file ? path.basename(file.originalname).slice(0, 255) : undefined,
      fileType,
      fileData: file ? file.buffer : undefined,
      owner: req.userId
    });

    return res.status(201).json({
      resource: {
        ...resource.toObject(),
        fileData: undefined,
        hasFile: Boolean(resource.fileName)
      }
    });
  } catch (error) {
    return next(error);
  }
});

app.get('/api/resources/:id/file', async (req, res, next) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(404).json({ error: 'Resource not found.' });
    }

    const resource = await Resource.findById(req.params.id).select('fileName fileType fileData');
    if (!resource || !resource.fileData || !resource.fileName) {
      return res.status(404).json({ error: 'This resource does not have an uploaded document.' });
    }

    const safeFileName = resource.fileName.replace(/[^a-zA-Z0-9._-]/g, '_');
    const canPreviewInline = resource.fileType === 'application/pdf' || resource.fileType === 'text/plain';
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Content-Disposition', `${canPreviewInline ? 'inline' : 'attachment'}; filename="${safeFileName}"`);
    return res.type(resource.fileType).send(resource.fileData);
  } catch (error) {
    return next(error);
  }
});

app.use('/api', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found.' });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'aat1.html'));
});

app.use(express.static(__dirname));

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  if (error instanceof multer.MulterError && error.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ error: 'The document must be 8 MB or smaller.' });
  }
  if (error.code === 'UNSUPPORTED_RESOURCE_FILE') {
    return res.status(400).json({ error: error.message });
  }
  console.error(error);
  return res.status(500).json({ error: 'The server could not complete the request.' });
});

async function startServer() {
  await mongoose.connect(mongoUri);
  app.listen(port, () => {
    console.log(`CampusShare is running at http://localhost:${port}`);
  });
}

startServer().catch((error) => {
  console.error('Unable to connect to MongoDB or start the server:', error.message);
  process.exitCode = 1;
});
