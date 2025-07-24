const express = require('express');
const multer = require('multer');
const fs = require('fs');
const cloudinary = require('../utils/Cloudinary');

const router = express.Router();
const upload = multer({ dest: 'uploads/' });

router.post('/', upload.single('image'), async (req, res) => {
  try {
    const result = await cloudinary.uploader.upload(req.file.path, {
      folder: 'blog_banners',
    });

    fs.unlinkSync(req.file.path); // delete temp image
    res.json({ url: result.secure_url });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

module.exports = router;
