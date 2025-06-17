import mongoose from "mongoose";
import swaggerUi from 'swagger-ui-express';
import YAML from 'yamljs';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

// Configure environment variables
dotenv.config();

// Get directory name in ES module
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Database connection function
export const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log("✅ MongoDB Connected Successfully");
    } catch (error) {
        console.error("❌ MongoDB Connection Failed", error);
        process.exit(1);
    }
};

// Load the YAML file
const swaggerDocument = YAML.load(path.join(__dirname, '../utils/swagger.yaml'));

// Swagger setup function
export const setupSwagger = (app) => {
    app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));
    app.get('/api-docs.json', (req, res) => {
        res.json(swaggerDocument);
    });
};

// For backward compatibility (if needed)
export default connectDB;