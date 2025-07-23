import dotenv from 'dotenv';
import { v2 as cloudinary } from 'cloudinary';
import { CloudinaryStorage } from 'multer-storage-cloudinary';
import multer from 'multer';

dotenv.config();

// Cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// For banner uploads
const bannerStorage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: 'blog_banners',
    allowed_formats: ['jpg', 'png', 'jpeg'],
  },
});

// For profile image uploads
const profileStorage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: 'profile_images',
    allowed_formats: ['jpg', 'png', 'jpeg'],
  },
});

const uploadBanner = multer({ storage: bannerStorage });
const uploadProfileImg = multer({ storage: profileStorage });

export { cloudinary, uploadBanner, uploadProfileImg };

