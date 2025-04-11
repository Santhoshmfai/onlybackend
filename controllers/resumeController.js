import express from "express";
import Resume from "../models/Resume.js";
import fs from "fs";
import fetch from "node-fetch";
import pdfParse from "pdf-parse";
import dotenv from "dotenv";
import bcrypt from 'bcryptjs';
import jwt from "jsonwebtoken";
import cors from "cors";
import mongoose from "mongoose"; 
import path from 'path'; 
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
    let filePath;
    try {
        if (!req.file) return res.status(400).json({ error: "No file uploaded." });

        const token = req.headers.authorization?.split(" ")[1];
        if (!token) return res.status(401).json({ error: "Unauthorized: No token provided." });

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await Resume.findById(decoded.id);
        if (!user) return res.status(404).json({ message: "User not found." });

        filePath = req.file.path;
        const pdfBuffer = fs.readFileSync(filePath);
        const parsedPdf = await pdfParse(pdfBuffer);
        const resumeText = parsedPdf.text.trim();

        // Retry configuration
        const maxRetries = 3;
        let retryCount = 0;
        let success = false;
        let extractedText = '';
        let score = null;
        let lastError = null;

        while (retryCount < maxRetries && !success) {
            try {
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
                                content: "You analyze resumes and provide structured feedback. Each category (Content, Format, Sections, Skills, Style) should be scored out of 20, with suggestions for improvement. Your response MUST follow the exact format specified." 
                            },
                            { 
                                role: "user", 
                                content: `ANALYZE THIS RESUME STRICTLY FOLLOWING THIS FORMAT:

Resume Analysis Score: [percentage]%

Content:
Issues:
- [issue1]
- [issue2]
Suggested Fixes:
- [fix1]
- [fix2]
Score: [x]/20

Format:
Issues:
- [issue1]
Suggested Fixes:
- [fix1]
Score: [x]/20

Sections:
Issues:
- [issue1]
Suggested Fixes:
- [fix1]
Score: [x]/20

Skills:
Issues:
- [issue1]
Suggested Fixes:
- [fix1]
Score: [x]/20

Style:
Issues:
- [issue1]
Suggested Fixes:
- [fix1]
Score: [x]/20

DO NOT INCLUDE ANY OTHER TEXT OR EXPLANATIONS. JUST THE STRUCTURED ANALYSIS ABOVE.

Resume Text: ${resumeText}` 
                            }
                        ],
                        temperature: 0.3 // Lower temperature for more deterministic output
                    })
                });

                const data = await response.json();
                
                if (!data.choices || !data.choices[0]?.message?.content) {
                    throw new Error("Invalid Groq API response format - missing choices");
                }

                extractedText = data.choices[0].message.content;
                console.log(`API Response (Attempt ${retryCount + 1}):`, extractedText);
                
                // Enhanced validation
                const scoreMatch = extractedText.match(/Resume Analysis Score:\s*(\d+)%/);
                score = scoreMatch ? parseInt(scoreMatch[1]) : null;
                
                if (score === null || isNaN(score)) {
                    throw new Error("Missing or invalid score in response");
                }

                // Check all categories
                const requiredCategories = ["Content", "Format", "Sections", "Skills", "Style"];
                const categoryChecks = requiredCategories.map(cat => {
                    const categoryRegex = new RegExp(
                        `${cat}:\\s*\\nIssues:(.*?)\\nSuggested Fixes:(.*?)\\nScore:\\s*(\\d+)/20`,
                        "s"
                    );
                    return categoryRegex.test(extractedText);
                });

                if (categoryChecks.every(Boolean)) {
                    success = true;
                } else {
                    throw new Error(`Missing one or more required categories in response`);
                }
                
            } catch (error) {
                lastError = error;
                retryCount++;
                console.warn(`Attempt ${retryCount} failed:`, error.message);
                if (retryCount < maxRetries) {
                    await new Promise(resolve => setTimeout(resolve, 1000 * retryCount));
                }
            }
        }

        if (!success) {
            throw new Error(`Failed after ${maxRetries} attempts. Last error: ${lastError?.message || 'Unknown error'}`);
        }

        // Enhanced extraction with better error handling
        const extractCategoryData = (category) => {
            try {
                const regex = new RegExp(
                    `${category}:\\s*\\nIssues:(.*?)\\nSuggested Fixes:(.*?)\\nScore:\\s*(\\d+)/20`,
                    "s"
                );
                
                const match = extractedText.match(regex);
                if (!match || match.length < 4) {
                    console.warn(`Incomplete data for category: ${category}`);
                    return { score: 0, issues: "Analysis not available", suggestions: "Analysis not available" };
                }
                
                return {
                    score: parseInt(match[3], 10),
                    issues: match[1].trim().split('\n').filter(line => line.trim()).map(line => line.replace(/^- /, '').trim()).join('\n'),
                    suggestions: match[2].trim().split('\n').filter(line => line.trim()).map(line => line.replace(/^- /, '').trim()).join('\n')
                };
            } catch (error) {
                console.error(`Error processing category ${category}:`, error);
                return { score: 0, issues: "Error in analysis", suggestions: "Error in analysis" };
            }
        };

        const content = extractCategoryData("Content");
        const format = extractCategoryData("Format");
        const sections = extractCategoryData("Sections");
        const skills = extractCategoryData("Skills");
        const style = extractCategoryData("Style");

        // Push new resume analysis data
        user.resumeAnalysis.push({ 
            score, 
            feedback: extractedText,
            date: new Date() 
        });
        await user.save();

        // Clean up file
        if (filePath) {
            fs.unlinkSync(filePath);
        }

        return res.json({
            success: true,
            data: {
                overallScore: score,
                content,
                format,
                sections,
                skills,
                style,
                fullAnalysis: extractedText // For debugging
            }
        });

    } catch (error) {
        console.error("Error in analyzeResume:", error);
        
        // Clean up file if it exists
        if (filePath && fs.existsSync(filePath)) {
            try {
                fs.unlinkSync(filePath);
            } catch (fileError) {
                console.error("Error deleting file:", fileError);
            }
        }

        return res.status(500).json({ 
            error: "Failed to analyze resume",
            details: error.message,
            suggestion: "Please try again with a different resume or check the resume format"
        });
    }
};
export const jobSuggestions = async (req, res) => {
    try {
        const { resumeText } = req.body;
        if (!resumeText) return res.status(400).json({ error: "No resume text provided." });

        // Retry configuration
        const maxRetries = 3;
        let retryCount = 0;
        let success = false;
        let jobRoles = [];
        let lastError = null;

        while (retryCount < maxRetries && !success) {
            try {
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
                                content: `You suggest job roles based on resumes. Return ONLY job titles in this exact format:
                                
[Job Title 1]
[Job Title 2]
[Job Title 3]
                                
No numbers, bullets, or additional text.` 
                            },
                            { 
                                role: "user", 
                                content: `Suggest exactly 3 job titles (one per line) for this resume:
                                ${resumeText}`
                            }
                        ],
                        temperature: 0.3
                    })
                });

                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(`Groq API error: ${errorData.error?.message || 'Unknown error'}`);
                }

                const data = await response.json();
                const content = data.choices?.[0]?.message?.content;

                if (!content) {
                    throw new Error("Empty response from Groq API");
                }

                // Parse job titles
                jobRoles = content.split('\n')
                    .map(line => line.trim())
                    .filter(line => line.length > 0)
                    .filter(line => !line.match(/based on|suggest|resume/i))
                    .slice(0, 3);

                if (jobRoles.length >= 1) {
                    success = true;
                } else {
                    throw new Error("No valid job titles found in response");
                }

            } catch (error) {
                lastError = error;
                retryCount++;
                console.warn(`Attempt ${retryCount} failed:`, error.message);
                if (retryCount < maxRetries) {
                    await new Promise(resolve => setTimeout(resolve, 1000 * retryCount));
                }
            }
        }

        if (!success) {
            throw new Error(`Failed after ${maxRetries} attempts. Last error: ${lastError?.message}`);
        }

        res.json({ 
            success: true, 
            suggestions: jobRoles 
        });

    } catch (error) {
        console.error("Error in jobSuggestions:", error);
        res.status(500).json({ 
            error: "Failed to generate job suggestions",
            details: error.message,
            suggestion: "Please try again with different resume text"
        });
    }
};
export const mockInterview = async (req, res) => {
    try {
        const { resumeText, jobRole, difficulty } = req.body;

        if (!resumeText || !jobRole || !difficulty) {
            return res.status(400).json({ 
                error: "Missing required fields",
                details: {
                    resumeText: !resumeText ? "Missing" : "Provided",
                    jobRole: !jobRole ? "Missing" : "Provided",
                    difficulty: !difficulty ? "Missing" : "Provided"
                }
            });
        }

        // Validate resumeText length
        if (resumeText.length < 50) {
            return res.status(400).json({
                error: "Resume text too short",
                suggestion: "Please provide a more detailed resume"
            });
        }

        // Retry configuration
        const maxRetries = 3;
        let retryCount = 0;
        let success = false;
        let questions = [];
        let expectedAnswers = [];
        let lastError = null;

        while (retryCount < maxRetries && !success) {
            try {
                // Truncate resume text if too long (keep first 2000 chars)
                const truncatedResume = resumeText.length > 2000 
                    ? resumeText.substring(0, 2000) + "... [truncated]"
                    : resumeText;

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
                                content: `You are an interview question generator. Generate exactly 15 questions and answers in this strict format:
Q1: [Question text]
A1: [Answer text]
Q2: [Question text]
A2: [Answer text]
...
Q15: [Question text]
A15: [Answer text]

DO NOT include any other text, explanations, or commentary. ONLY generate the questions and answers.`
                            },
                            { 
                                role: "user", 
                                content: `Generate 15 ${difficulty} difficulty interview questions for a ${jobRole} position based on this resume:

${truncatedResume}`
                            }
                        ],
                        temperature: 0.3,
                        max_tokens: 2000
                    })
                });

                const responseBody = await response.text();
                console.log(`Attempt ${retryCount + 1} Raw Response:`, responseBody);

                if (!response.ok) {
                    throw new Error(`API Error: ${response.status} ${response.statusText}`);
                }

                const data = JSON.parse(responseBody);
                const content = data.choices?.[0]?.message?.content;

                if (!content) {
                    throw new Error("Empty content in response");
                }

                // Parse QA pairs more robustly
                const qaLines = content.split('\n')
                    .filter(line => line.trim().length > 0)
                    .map(line => line.trim());

                questions = [];
                expectedAnswers = [];
                
                for (let i = 0; i < qaLines.length; i++) {
                    const line = qaLines[i];
                    if (line.match(/^Q\d+:/i)) {
                        const question = line.replace(/^Q\d+:\s*/i, '').trim();
                        questions.push(question);
                        
                        // The next line should be the answer
                        if (i + 1 < qaLines.length && qaLines[i+1].match(/^A\d+:/i)) {
                            const answer = qaLines[i+1].replace(/^A\d+:\s*/i, '').trim();
                            expectedAnswers.push(answer);
                            i++; // Skip the answer line in next iteration
                        } else {
                            expectedAnswers.push("No answer provided");
                        }
                    }
                }

                if (questions.length === 15 && expectedAnswers.length === 15) {
                    success = true;
                } else {
                    throw new Error(`Got ${questions.length} questions and ${expectedAnswers.length} answers`);
                }

            } catch (error) {
                lastError = error;
                retryCount++;
                console.warn(`Attempt ${retryCount} failed:`, error.message);
                if (retryCount < maxRetries) {
                    await new Promise(resolve => setTimeout(resolve, 1000 * retryCount));
                }
            }
        }

        if (!success) {
            throw new Error(`Failed after ${maxRetries} attempts. Last error: ${lastError?.message}`);
        }

        res.json({ 
            success: true, 
            questions, 
            expectedAnswers 
        });

    } catch (error) {
        console.error("Error in mockInterview:", {
            error: error.message,
            stack: error.stack,
            timestamp: new Date().toISOString()
        });

        res.status(500).json({ 
            error: "Failed to generate mock interview",
            details: error.message,
            suggestion: "Please check your resume text and try again"
        });
    }
};

export const evaluateAnswers = async (req, res) => {
    try {
        console.log("Evaluation Request Received:", {
            body: req.body,
            timestamp: new Date().toISOString()
        });

        const { email, questions, answers, expectedAnswers, jobRole, skippedCount } = req.body;

        // Validation
        const missingFields = [];
        if (!email) missingFields.push("email");
        if (!questions) missingFields.push("questions");
        if (!expectedAnswers) missingFields.push("expectedAnswers");
        if (!jobRole) missingFields.push("jobRole");
        if (missingFields.length > 0) {
            return res.status(400).json({
                error: "Missing required fields",
                missingFields
            });
        }

        // Handle case where answers array might be empty or incomplete
        const processedAnswers = questions.map((_, index) => 
            answers[index] || "Not answered"
        );

        // Retry configuration
        const maxRetries = 3;
        let retryCount = 0;
        let success = false;
        let evaluations = [];
        let correctCount = 0;
        let wrongCount = 0;
        let lastError = null;

        while (retryCount < maxRetries && !success) {
            try {
                const qaPairs = questions.map((q, i) => 
                    `Q${i+1}: ${q}\nA${i+1}: ${processedAnswers[i]}\nExpected: ${expectedAnswers[i]}`
                ).join('\n\n');

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
                                content: `Evaluate interview answers. Format each response exactly like this:
Q1: [Question]
A1: [Candidate Answer]
Expected: [Expected Answer]
Evaluation: Correct/Wrong - [Brief Explanation (1-2 sentences)]

Always include the Evaluation line for every question, even if the answer is completely wrong or empty.`
                            },
                            {
                                role: "user",
                                content: `Evaluate these answers. For each question, clearly state whether the answer is Correct or Wrong:

${qaPairs}`
                            }
                        ],
                        temperature: 0.2
                    })
                });

                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(`API Error: ${errorData.error?.message || response.status}`);
                }

                const data = await response.json();
                const content = data.choices?.[0]?.message?.content;

                if (!content) {
                    throw new Error("Empty evaluation content");
                }

                // Parse evaluations
                evaluations = content.split('\n\n')
                    .filter(item => item.trim().length > 0)
                    .map(item => {
                        // Extract evaluation result
                        const evaluationMatch = item.match(/Evaluation:\s*(Correct|Wrong)/i);
                        const isCorrect = evaluationMatch && evaluationMatch[1].toLowerCase() === 'correct';
                        return {
                            text: item.trim(),
                            correct: isCorrect
                        };
                    });

                correctCount = evaluations.filter(e => e.correct).length;
                wrongCount = evaluations.length - correctCount;

                // Even if all answers are wrong, we consider it a success as long as we got evaluations
                if (evaluations.length === questions.length) {
                    success = true;
                } else {
                    throw new Error(`Got ${evaluations.length} evaluations for ${questions.length} questions`);
                }

            } catch (error) {
                lastError = error;
                retryCount++;
                console.warn(`Attempt ${retryCount} failed:`, error.message);
                if (retryCount < maxRetries) {
                    await new Promise(resolve => setTimeout(resolve, 1000 * retryCount));
                }
            }
        }

        if (!success) {
            // Fallback evaluation if API keeps failing
            evaluations = questions.map((q, i) => ({
                text: `Q${i+1}: ${q}\nA${i+1}: ${processedAnswers[i]}\nExpected: ${expectedAnswers[i]}\nEvaluation: Wrong - Answer did not match expected response`,
                correct: false
            }));
            correctCount = 0;
            wrongCount = questions.length;
            console.warn("Using fallback evaluation due to API failures");
        }

        // Save results
        const user = await Resume.findOne({ email });
        if (!user) {
            throw new Error("User not found");
        }

        user.mockInterviewData = user.mockInterviewData.filter(interview => 
            interview.jobRole !== jobRole
        );

        user.mockInterviewData.push({
            jobRole,
            questions,
            answers: processedAnswers,
            expectedAnswers,
            correctCount,
            wrongCount,
            skippedCount: skippedCount || 0,
            evaluations: evaluations.map(e => e.text),
            date: new Date()
        });

        await user.save();

        res.json({
            success: true,
            evaluations: evaluations.map(e => e.text),
            correctCount,
            wrongCount,
            skippedCount
        });

    } catch (error) {
        console.error("Error in evaluateAnswers:", {
            error: error.message,
            stack: error.stack,
            timestamp: new Date().toISOString()
        });

        res.status(500).json({ 
            success: false,
            error: "Evaluation failed",
            details: error.message,
            evaluations: questions.map((q, i) => 
                `Q${i+1}: ${q}\nA${i+1}: ${answers[i] || 'Not answered'}\nExpected: ${expectedAnswers[i]}\nEvaluation: Could not evaluate - System error`
            ),
            correctCount: 0,
            wrongCount: questions.length,
            skippedCount: skippedCount || 0
        });
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
export const getProfileImage = async (req, res) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) {
            return res.status(401).json({ error: "Unauthorized: No token provided." });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await Resume.findById(decoded.id).select("profilePicture");

        if (!user) {
            return res.status(404).json({ error: "User not found." });
        }

        if (!user.profilePicture) {
            return res.status(404).json({ error: "Profile picture not found." });
        }

        // Extract the Base64 data from the data URI
        const base64Data = user.profilePicture.replace(/^data:image\/\w+;base64,/, "");
        const imageBuffer = Buffer.from(base64Data, 'base64');

        // Determine content type from the data URI
        const matches = user.profilePicture.match(/^data:(image\/\w+);base64/);
        const contentType = matches ? matches[1] : 'image/jpeg';

        // Set headers and send the image
        res.set('Content-Type', contentType);
        res.send(imageBuffer);

    } catch (error) {
        console.error("Error fetching profile image:", error);
        res.status(500).json({ error: "Internal server error", details: error.message });
    }
};
export const uploadProfilePicture = async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            fs.unlinkSync(req.file.path);
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await Resume.findById(decoded.id);

        if (!user) {
            fs.unlinkSync(req.file.path);
            return res.status(404).json({ error: 'User not found' });
        }

        // Read the file and convert to Base64
        const fileData = fs.readFileSync(req.file.path);
        const base64Image = fileData.toString('base64');

        // Determine the MIME type
        const mimeType = req.file.mimetype;

        // Create data URI
        const profilePicture = `data:${mimeType};base64,${base64Image}`;

        // Update user with Base64 encoded image
        user.profilePicture = profilePicture;
        await user.save();

        // Delete the temporary file
        fs.unlinkSync(req.file.path);

        res.json({
            message: 'Profile picture uploaded successfully',
            profilePicture: profilePicture
        });
    } catch (error) {
        console.error('Error uploading profile picture:', error);
        if (req.file) {
            fs.unlinkSync(req.file.path);
        }
        res.status(500).json({ error: 'Server error' });
    }
};
// For basic info updates
export const updateBasicInfo = async (req, res) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await Resume.findById(decoded.id);

        if (!user) {
            return res.status(404).json({ error: "User not found." });
        }

        const { gender, location, birthday, summary, githubLink, linkedinLink, profilePicture } = req.body;

        if (gender !== undefined) user.gender = gender;
        if (location !== undefined) user.location = location;
        if (birthday !== undefined) user.birthday = birthday;
        if (summary !== undefined) user.summary = summary;
        if (githubLink !== undefined) user.githubLink = githubLink;
        if (linkedinLink !== undefined) user.linkedinLink = linkedinLink;
        
        // Handle profile picture if it's included in the request
        if (profilePicture !== undefined && profilePicture.startsWith('data:image')) {
            user.profilePicture = profilePicture;
        }

        await user.save();

        const userResponse = {
            username: user.username,
            email: user.email,
            gender: user.gender,
            location: user.location,
            birthday: user.birthday,
            summary: user.summary,
            githubLink: user.githubLink,
            linkedinLink: user.linkedinLink,
            profilePicture: user.profilePicture
        };

        res.status(200).json({ message: "Basic info updated successfully!", user: userResponse });
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
        const user = await Resume.findById(decoded.id).select("-password -resumeAnalysis -mockInterviewData -_id -__v");

        if (!user) {
            return res.status(404).json({ error: "User not found." });
        }

        // Format the response
        const userResponse = {
            username: user.username || "",
            email: user.email || "",
            phoneNumber: user.phoneNumber || "",
            gender: user.gender || "",
            location: user.location || "",
            birthday: user.birthday ? user.birthday.toISOString().split('T')[0] : "",
            summary: user.summary || "",
            githubLink: user.githubLink || "",
            linkedinLink: user.linkedinLink || "",
            profilePicture: user.profilePicture || "" // This will now be the Base64 string
        };

        res.status(200).json({ user: userResponse });
    } catch (error) {
        console.error("Error fetching basic info:", error);
        res.status(500).json({ error: "Internal server error", details: error.message });
    }
};
export const deleteAccount = async (req, res) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) {
            return res.status(401).json({ error: "Unauthorized: No token provided." });
        }

        // Verify token and get user ID
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Find and delete the user
        const deletedUser = await Resume.findByIdAndDelete(decoded.id);
        
        if (!deletedUser) {
            return res.status(404).json({ error: "User not found." });
        }

        // Optional: Clean up any related data (like uploaded files, etc.)
        // This would depend on your specific application requirements

        res.status(200).json({ 
            success: true,
            message: "Account and all associated data deleted successfully." 
        });

    } catch (error) {
        console.error("Error deleting account:", error);
        
        // Handle specific JWT errors
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ error: "Invalid token." });
        }
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: "Token expired." });
        }

        res.status(500).json({ 
            error: "Failed to delete account",
            details: error.message 
        });
    }
};
export const health = async (req, res) => {
    res.json({
      message: "API is running",
      dbStatus: mongoose.connection.readyState === 1 ? "Connected" : "Not Connected"
    });
  };
