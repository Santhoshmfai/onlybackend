import express from "express";
import Resume from "../models/Resume.js";
import fs from "fs";
import fetch from "node-fetch";
import pdfParse from "pdf-parse";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import mongoose from "mongoose"; 

dotenv.config();
const router = express.Router();
const GROQ_API_KEY = process.env.GROQ_API_KEY;
const GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions";
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware
router.use(express.json());
router.use(cors({ origin: "http://localhost:3000", credentials: true }));

export const signup = async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ error: "All fields are required." });
        }

        const existingUser = await Resume.findOne({ $or: [{ username }, { email }] });
        if (existingUser) {
            return res.status(400).json({ error: "Username or Email already exists." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new Resume({ username, email, password: hashedPassword });
        await newUser.save();

        const token = jwt.sign(
            { id: newUser._id, username: newUser.username, email: newUser.email }, // Include email
            JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.status(201).json({ message: "User registered successfully!", token });
    } catch (error) {
        console.error("Signup Error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
};



export const login = async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await Resume.findOne({ email });

        if (!user) {
            return res.status(400).json({ error: "Email not found" });
        }

        const isPasswordMatch = await bcrypt.compare(password, user.password);
        if (!isPasswordMatch) {
            return res.status(400).json({ error: "Wrong password" });
        }

        // Generate JWT token
        const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: "1h" });

        res.status(200).json({ message: "Login successful", token, email: user.email });
    } catch (error) {
        res.status(500).json({ error: "Server error", details: error.message });
    }
};

// Protect this route with JWT
export const protectedRoute = (req, res) => {
    res.json({ message: "You have access to this protected route", user: req.user });
};

export const storeScore = async (req, res) => {
    const { score } = req.body;
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return res.status(401).json({ message: "Unauthorized: No token provided." });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        console.log("Decoded token:", decoded);

        const user = await Resume.findById(decoded.id);
        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }

        if (!score) {
            return res.status(400).json({ message: "Score is required." });
        }

        user.score = score;
        await user.save();

        res.status(200).json({ message: "Score stored successfully." });
    } catch (error) {
        console.error("Error storing score:", error);
        res.status(500).json({ message: "Error storing score.", details: error.message });
    }
};

export const analyzeResume = async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: "No file uploaded." });

        const token = req.headers.authorization?.split(" ")[1];
        if (!token) return res.status(401).json({ error: "Unauthorized: No token provided." });

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await Resume.findById(decoded.id);
        if (!user) return res.status(404).json({ message: "User not found." });

        const filePath = req.file.path;
        const pdfBuffer = fs.readFileSync(filePath);
        const parsedPdf = await pdfParse(pdfBuffer);
        const resumeText = parsedPdf.text.trim();

        const response = await fetch(GROQ_API_URL, {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${GROQ_API_KEY.trim()}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                model: "gemma2-9b-it",
                messages: [
                    { 
                        role: "system", 
                        content: `You analyze resumes and provide structured feedback. 
                        **Strictly** follow this response format without adding extra text.
                        
                        Return the output **exactly** in this structure:
                        
                        Resume Analysis Score: [Overall Score]%
                    
                        Content:
                         Issues:
                         
                         Suggested Fixes:
                         
                        Score: [Score]/20
                    
                        Format:
                         Issues:

                         Suggested Fixes:
                          
                        Score: [Score]/20
                    
                        Sections:
                         Issues:
                          
                        Suggested Fixes:
                          
                        Score: [Score]/20
                    
                        Skills:
                         Issues:
                          
                        Suggested Fixes:
                         
                        Score: [Score]/20
                    
                        Style:
                         Issues:
                         
                        Suggested Fixes:
                          
                        Score: [Score]/20
                    
                        Any response that deviates from this format will be considered incorrect.`
                    },
                    { 
                        role: "user", 
                        content: `Analyze this resume and provide feedback in the exact format above:
                        
                        Resume Text: ${resumeText}`
                    }
                    
                ]
            })
        });

        const data = await response.json();
        console.log(data)
        if (!data.choices || !data.choices[0]?.message?.content) {
            throw new Error("Invalid Groq API response format");
        }

        const extractedText = data.choices[0].message.content;
        console.log(extractedText);

        // Extract overall resume score
        const scoreMatch = extractedText.match(/Resume Analysis Score: (\d+)%/);
        const score = scoreMatch ? parseInt(scoreMatch[1]) : null;

        const extractCategoryData = (category) => {
            const regex = new RegExp(
                `${category}:\\s*\\n?-?\\s*Issues:(.*?)\\n?-?\\s*Suggested Fixes:(.*?)\\n?-?\\s*Score:\\s*(\\d+)/20`,
                "is"
            );
            
            const match = extractedText.match(regex);
            return match
                ? {
                    score: parseInt(match[3], 10),
                    issues: match[1].trim().replace(/\n/g, " "),
                    suggestions: match[2].trim().replace(/\n/g, " ")
                }
                : { score: 0, issues: "No data found", suggestions: "No data found" };
        };
        

        const content = extractCategoryData("Content");
        const format = extractCategoryData("Format");
        const sections = extractCategoryData("Sections");
        const skills = extractCategoryData("Skills");
        const style = extractCategoryData("Style");
        console.log("san",content)
        fs.unlinkSync(filePath);

        // Push new resume analysis data
        user.resumeAnalysis.push({ score, feedback: extractedText });
        await user.save();

        res.json({
            success: true,
            data: {
                overallScore: score,
                content,
                format,
                sections,
                skills,
                style
            }
        });

    } catch (error) {
        console.error("Error:", error);
        res.status(500).json({ error: "Server error", details: error.message });
    }
};
export const jobSuggestions = async (req, res) => {
    try {
        const { resumeText } = req.body;
        if (!resumeText) return res.status(400).json({ error: "No resume text provided." });

        // Call Groq API for job role suggestions
        const response = await fetch(GROQ_API_URL, {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${GROQ_API_KEY.trim()}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                model: "gemma2-9b-it",
                messages: [
                    { role: "system", content: "You analyze resumes and suggest the best job roles." },
                    { role: "user", content: `Based on the following resume text, suggest **only the job titles** (one per line) with no extra text  :
                        ${resumeText}` }
                ]
            })
        });

        const data = await response.json();
        const jobRoles = data.choices?.[0]?.message?.content.split("\n").map(role => role.trim()).filter(role => role !== "");
        console.log(jobRoles)
        if (!jobRoles) {
            return res.status(500).json({ error: "Invalid Groq API response format" });
        }

        res.json({ success: true, suggestions: jobRoles }); // Ensure the response matches the client expectation

    } catch (error) {
        console.error("Error:", error);
        res.status(500).json({ error: "Server error", details: error.message });
    }
};

export const mockInterview = async (req, res) => {
    try {
        const { resumeText, jobRole, difficulty } = req.body;

        if (!resumeText || !jobRole || !difficulty) {
            return res.status(400).json({ error: "Missing required fields: resumeText, jobRole, or difficulty." });
        }

        const response = await fetch(GROQ_API_URL, {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${GROQ_API_KEY?.trim()}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                model: "gemma2-9b-it",
                messages: [
                    { 
                        role: "system", 
                        content: `You are an AI that generates mock interview questions and their correct answers for job candidates. 
                        **STRICTLY follow this output format without any extra words:**  
                        Q1: [Question 1]  
                        A1: [Answer 1]  
                        Q2: [Question 2]  
                        A2: [Answer 2]  
                        ...  
                        Q15: [Question 15]  
                        A15: [Answer 15]`
                    },
                    { 
                        role: "user", 
                        content: `Generate exactly **15** mock interview questions for a **${jobRole}** at **${difficulty} difficulty level** based on the resume below. 
                        **Do not include any additional explanations or comments. Strictly follow the requested format.**  

                        Resume Text:  
                        ${resumeText}`
                    }
                ]
            })
        });

        const responseBody = await response.text();
        console.log("Groq API Raw Response:", responseBody);

        if (!response.ok) {
            console.error("API Error Response:", responseBody);
            return res.status(response.status).json({ error: "Groq API error", details: responseBody });
        }

        const data = JSON.parse(responseBody);
        const content = data.choices?.[0]?.message?.content;

        if (!content) {
            console.error("Invalid Groq API response format:", data);
            return res.status(500).json({ error: "Invalid response format", details: data });
        }

        // Parse QA pairs more robustly
        const qaPairs = content.split("\n").filter(line => line.trim() !== "");
        const questions = [];
        const expectedAnswers = [];

        for (let i = 0; i < qaPairs.length; i++) {
            const line = qaPairs[i].trim();
            if (line.startsWith("Q")) {
                const question = line.replace(/^Q\d+: /, "").trim();
                questions.push(question);
            } else if (line.startsWith("A")) {
                const answer = line.replace(/^A\d+: /, "").trim();
                expectedAnswers.push(answer);
            }
        }

        // Ensure exactly 15 Q&A pairs
        if (questions.length !== 15 || expectedAnswers.length !== 15) {
            console.error("Unexpected number of QA pairs:", { questions, expectedAnswers });
            return res.status(500).json({ error: "Malformed response format", details: { questions, expectedAnswers } });
        }

        res.json({ success: true, questions, expectedAnswers });

    } catch (error) {
        console.error("Error:", error);
        res.status(500).json({ error: "Server error", details: error.message });
    }
};

export const evaluateAnswers = async (req, res) => {
    try {
        console.log("Request Body:", req.body); // Log the request body

        const { email, questions, answers, expectedAnswers, jobRole, skippedCount } = req.body;

        // Validate request body
        if (!questions || !answers || !expectedAnswers || !email || !jobRole) {
            console.error("Missing required fields in request body.");
            return res.status(400).json({ error: "Missing required fields." });
        }

        // Log the data being sent to Groq API
        console.log("Sending data to Groq API:", {
            email,
            questions,
            answers,
            expectedAnswers,
            jobRole,
            skippedCount
        });

        // Call Groq API to evaluate answers
        const response = await fetch(GROQ_API_URL, {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${GROQ_API_KEY.trim()}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                model: "gemma2-9b-it",
                messages: [
                    { role: "system", content: "You evaluate interview answers. Clearly label answers as 'Correct' or 'Wrong' and explain why." },
                    { role: "user", content: `Evaluate these answers. Clearly mention 'Correct' or 'Wrong' for each:
                        ${questions.map((q, i) => `Q: ${q}\nA: ${answers[i]}\nExpected: ${expectedAnswers[i]}`).join("\n\n")}
                    ` }
                ]
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            console.error("Groq API Error:", errorData);
            return res.status(500).json({ error: "Groq API error", details: errorData });
        }

        const data = await response.json();
        console.log("Groq API Response:", data); // Log the Groq API response

        const content = data.choices?.[0]?.message?.content;

        if (!content) {
            console.error("Invalid response format from Groq API.");
            return res.status(500).json({ error: "Invalid response format from Groq API" });
        }

        // Parse evaluations
        const evaluations = content.split("\n\n").map(line => line.trim()).filter(line => line !== "");
        console.log("Evaluations:", evaluations); // Log the parsed evaluations

        if (!evaluations || evaluations.length === 0) {
            console.error("No evaluations found in the response.");
            return res.status(500).json({ error: "No evaluations found in the response" });
        }

        // Count correct and wrong answers
        let correctCount = evaluations.filter((evalText) => evalText.includes("Correct")).length;
        let wrongCount = evaluations.length - correctCount;
        console.log("Correct Count:", correctCount, "Wrong Count:", wrongCount); // Log counts

        // Save results to the database
        const user = await Resume.findOne({ email });
        if (!user) {
            console.error("User not found in the database.");
            return res.status(404).json({ message: "User not found." });
        }

        // Remove previous mock interview data for the same job role
        user.mockInterviewData = user.mockInterviewData.filter(interview => interview.jobRole !== jobRole);

        const mockData = {
            jobRole,
            questions,
            answers,
            expectedAnswers,
            correctCount,
            wrongCount,
            skippedCount,
            date: new Date()
        };

        console.log("Mock Data to Save:", mockData); // Log the mock data

        user.mockInterviewData.push(mockData);
        await user.save();

        console.log("Results saved successfully."); // Log success

        res.json({
            success: true,
            evaluation: evaluations,
            correctCount,
            wrongCount
        });

    } catch (error) {
        console.error("Error in evaluateAnswers:", error); // Log the error
        res.status(500).json({ error: "Server error", details: error.message });
    }
};


export const getDashboardData = async (req, res) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) {
            return res.status(401).json({ error: "Unauthorized: No token provided." });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const user = await Resume.findById(decoded.id).select("mockInterviewData resumeAnalysis").lean();
        if (!user) {
            return res.status(404).json({ error: "User not found." });
        }

        const dashboardData = {};

        // Process mock interview data
        user.mockInterviewData.forEach(({ jobRole, correctCount }) => {
            if (!dashboardData[jobRole]) {
                dashboardData[jobRole] = {
                    jobRole,
                    correctAnswers: 0,
                    resumeAnalysisScore: null // Default null to indicate missing data
                };
            }
            dashboardData[jobRole].correctAnswers += correctCount;
        });

        // Process resume analysis data
        user.resumeAnalysis.forEach(({ score }) => {
            // Find the first available job role
            const jobRole = user.mockInterviewData.length > 0 ? user.mockInterviewData[0].jobRole : "Unknown";

            if (!dashboardData[jobRole]) {
                dashboardData[jobRole] = {
                    jobRole,
                    correctAnswers: 0,
                    resumeAnalysisScore: score || 0
                };
            } else {
                dashboardData[jobRole].resumeAnalysisScore = score || 0;
            }
        });

        // Convert object to array format
        const result = Object.values(dashboardData);

        res.json({ data: result });
    } catch (error) {
        console.error("Error fetching dashboard data:", error);
        res.status(500).json({ error: "Internal server error", details: error.message });
    }
};

// Fetch user account information
export const getAccountInfo = async (req, res) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) {
            return res.status(401).json({ error: "Unauthorized: No token provided." });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await Resume.findById(decoded.id).select("username email phoneNumber");

        if (!user) {
            return res.status(404).json({ error: "User not found." });
        }

        res.status(200).json({ user });
    } catch (error) {
        console.error("Error fetching account info:", error);
        res.status(500).json({ error: "Internal server error", details: error.message });
    }
};

// Update user account information
export const updateAccountInfo = async (req, res) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) {
            return res.status(401).json({ error: "Unauthorized: No token provided." });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await Resume.findById(decoded.id);

        if (!user) {
            return res.status(404).json({ error: "User not found." });
        }

        const { username, email, phoneNumber, newPassword } = req.body;

        // Update fields if provided
        if (username) user.username = username;
        if (email) user.email = email;
        if (phoneNumber) user.phoneNumber = phoneNumber;

        // Update password if provided
        if (newPassword) {
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            user.password = hashedPassword;
        }

        await user.save();

        res.status(200).json({ message: "Account updated successfully!", user });
    } catch (error) {
        console.error("Error updating account info:", error);
        res.status(500).json({ error: "Internal server error", details: error.message });
    }
};

// Store or update basic info
export const updateBasicInfo = async (req, res) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) {
            return res.status(401).json({ error: "Unauthorized: No token provided." });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await Resume.findById(decoded.id);

        if (!user) {
            return res.status(404).json({ error: "User not found." });
        }

        // Extract fields from the request body
        const { gender, location, birthday, summary, githubLink, linkedinLink } = req.body;

        // Update fields if provided
        if (gender) user.gender = gender;
        if (location) user.location = location;
        if (birthday) user.birthday = birthday;
        if (summary) user.summary = summary;
        if (githubLink) user.githubLink = githubLink;
        if (linkedinLink) user.linkedinLink = linkedinLink;

        await user.save();

        res.status(200).json({ message: "Basic info updated successfully!", user });
    } catch (error) {
        console.error("Error updating basic info:", error);
        res.status(500).json({ error: "Internal server error", details: error.message });
    }
};

// Get basic info
export const getBasicInfo = async (req, res) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) {
            return res.status(401).json({ error: "Unauthorized: No token provided." });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await Resume.findById(decoded.id).select("username gender location birthday summary githubLink linkedinLink");

        if (!user) {
            return res.status(404).json({ error: "User not found." });
        }

        res.status(200).json({ user });
    } catch (error) {
        console.error("Error fetching basic info:", error);
        res.status(500).json({ error: "Internal server error", details: error.message });
    }
};

export const health = async (req, res) => {
    res.json({
      message: "API is running",
      dbStatus: mongoose.connection.readyState === 1 ? "Connected" : "Not Connected"
    });
  };