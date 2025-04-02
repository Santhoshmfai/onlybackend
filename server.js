import express from "express";
import cors from "cors"; // Import CORS
import dotenv from "dotenv";
import mongoose from "mongoose";
import resumeRoutes from "./routes/resumeRoutes.js";
import { setupSwagger } from './config/db.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
setupSwagger(app); 

// Enable CORS
app.use(cors());

app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("Connected to MongoDB"))
    .catch(err => console.error("MongoDB connection error:", err));

app.use("/api", resumeRoutes);

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));