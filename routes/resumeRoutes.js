import express from "express";
import multer from "multer";
import fs from "fs";
import path from "path";
import {
    signup,
    login,
    analyzeResume,
    mockInterview,
    jobSuggestions,
    evaluateAnswers,
    storeScore,
    protectedRoute,
    getDashboardData,
    getAccountInfo,
    updateAccountInfo,
    updateBasicInfo,
    getBasicInfo,
    uploadProfilePicture,
    health
} from "../controllers/resumeController.js";
import { verifyToken } from "../middlewares/authMiddleware.js";
import cors from "cors";
const router = express.Router();
router
.use(
    cors({
      origin: "http://localhost:3000", // Your React app
      methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      allowedHeaders: ["Content-Type", "Authorization"],
      credentials: true,
    })
  );
  
  // Explicitly handle OPTIONS preflight
  router.options("*", cors());
// Ensure 'uploads' directory exists
const uploadDir = path.join(process.cwd(), 'public', 'uploads', 'profile-pictures');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure Multer storage for profile pictures
const profilePictureStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

// File filter for images only
const imageFilter = (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
        cb(null, true);
    } else {
        cb(new Error('Only image files are allowed!'), false);
    }
};

const uploadProfilePic = multer({ 
    storage: profilePictureStorage,
    fileFilter: imageFilter,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    }
});

// Configure Multer for resume uploads
const resumeStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const resumeDir = path.resolve("uploads/resumes");
        if (!fs.existsSync(resumeDir)) {
            fs.mkdirSync(resumeDir, { recursive: true });
        }
        cb(null, resumeDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const uploadResume = multer({ 
    storage: resumeStorage,
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB limit
    }
});

// Public routes
router.post("/signup", signup);  
router.post("/login", login);
router.get("/health", health);

// Protected routes (require authentication)
router.post("/analyze", uploadResume.single("resume"), analyzeResume);
router.post("/mockinterview", verifyToken, mockInterview);
router.post("/job-suggestions", verifyToken, jobSuggestions);
router.post("/evaluate-answers", verifyToken, evaluateAnswers);
router.post("/store-score", verifyToken, storeScore);
router.get("/protected", verifyToken, protectedRoute);
router.get("/dashboard", verifyToken, getDashboardData);

// Account management routes
router.get("/account-info", verifyToken, getAccountInfo);
router.put("/update-account-info", verifyToken, updateAccountInfo);

// Basic info routes
router.post("/upload-profile-picture", verifyToken, uploadProfilePic.single('profilePicture'), uploadProfilePicture);
router.put("/basic-info", verifyToken, updateBasicInfo);
router.get("/basic-info", verifyToken, getBasicInfo);

export default router;