const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Ensure upload directories exist
const createDir = (dir) => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
};

createDir('uploads/profile');
createDir('uploads/posts');

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (file.fieldname === 'profileImage') {
      cb(null, 'uploads/profile');
    } else {
      cb(null, 'uploads/posts');
    }
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    // Use userId if available (from auth middleware), otherwise timestamp
    const userId = req.user ? req.user.userId : 'unknown';
    cb(null, `${Date.now()}_${userId}${ext}`);
  }
});

const fileFilter = (req, file, cb) => {
  // Accept images and videos
  if (
    !file.mimetype.startsWith('image/') &&
    !file.mimetype.startsWith('video/')
  ) {
    return cb(new Error('Only image or video files allowed'), false);
  }
  cb(null, true);
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 100 * 1024 * 1024 // 100MB max limit
  }
});

module.exports = upload;