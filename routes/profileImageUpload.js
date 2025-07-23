import express from 'express';
import { uploadProfileImg } from '../utils/cloudinary.js';

const router = express.Router();

router.post('/', uploadProfileImg.single('image'), async (req, res) => {
  try {
    res.status(200).json({ url: req.file.path });
  } catch (err) {
    console.error('Upload failed:', err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

export default router;

