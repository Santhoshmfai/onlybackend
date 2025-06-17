import express from "express";
import Resume from "../models/Resume.js";
import { promises as fs } from 'fs';
import fetch from "node-fetch";
import pdfParse from "pdf-parse";
import dotenv from "dotenv";
import bcrypt from 'bcryptjs';
import jwt from "jsonwebtoken";

import mongoose from "mongoose"; 
import * as mammoth from 'mammoth';


dotenv.config();
const router = express.Router();
const GROQ_API_KEY = process.env.GROQ_API_KEY;
const GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions";
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware
router.use(express.json());

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
export const home = (req, res) => {
    if (req.user) {
        res.send(`<h2>Welcome, ${req.user.displayName}</h2><img src="${req.user.profilePicture}" width="100"/><br><a href="/logout">Logout</a>`);
    } else {
        res.send(`<a href="/auth/google">Login with Google</a>`);
    }
};

export const logout = (req, res) => {
    req.logout(() => {
        res.redirect("/");
    });
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
        const fileExtension = req.file.originalname.split('.').pop().toLowerCase();
        let resumeText = '';

        // Process different file types
        switch (fileExtension) {
            case 'pdf':
                const pdfBuffer = await fs.readFile(filePath);
                const parsedPdf = await pdfParse(pdfBuffer);
                resumeText = parsedPdf.text.trim();
                break;

            case 'docx':
                const docxBuffer = await fs.readFile(filePath);
                const result = await mammoth.extractRawText({ buffer: docxBuffer });
                resumeText = result.value.trim();
                break;

            case 'txt':
                resumeText = (await fs.readFile(filePath, 'utf-8')).trim();
                break;

            default:
                return res.status(400).json({ 
                    error: "Unsupported file type",
                    supportedTypes: ["pdf", "docx", "jpg", "jpeg", "png", "txt"]
                });
        }

        if (!resumeText) {
            return res.status(400).json({ error: "Could not extract text from the file" });
        }

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
                console.log(data)
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
        // Clean up file
        if (filePath) {
            try {
                await fs.unlink(filePath);
            } catch (fileError) {
                console.error("Error deleting file:", fileError);
            }
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
                fullAnalysis: extractedText
            }
        });

    } catch (error) {
        console.error("Error in analyzeResume:", error);
        
        // Clean up file if it exists - use async version
        if (filePath) {
            try {
                await fs.unlink(filePath);
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
[Job Title 4]
[Job Title 5]
[Job Title 6]                                
No numbers, bullets, or additional text.` 
                            },
                            { 
                                role: "user", 
                                content: `Suggest exactly 6 job titles (one per line) for this resume:
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

        const { email, questions, answers, expectedAnswers, jobRole , score } = req.body;
        console.log("Received for:", email, "Initial score:", score);

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

        const processedAnswers = questions.map((_, index) =>
            answers[index] || "Not answered"
        );

        // Retry config
        const maxRetries = 10;
        let retryCount = 0;
        let success = false;
        let evaluations = [];
        let correctCount = 0;
        let wrongCount = 0;
        let lastError = null;

        while (retryCount < maxRetries && !success) {
            try {
                const qaPairs = questions.map((q, i) =>
                    `Q${i + 1}: ${q}\nA${i + 1}: ${processedAnswers[i]}\nExpected: ${expectedAnswers[i]}`
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
                                content: `Evaluate interview answers leniently. Mark answers as Correct if they:
1. Contain the same key concepts as expected answer
2. Have similar meaning even if wording differs
3. Cover the main points of the expected answer

Format responses like:
Q1: [Question]
A1: [Candidate Answer]
Expected: [Expected Answer]
Evaluation: Correct/Wrong - [Brief Explanation]

At the end, add:
Total Correct Answers: [number]

Be generous in marking as Correct when the essence is right.`
                            },
                            {
                                role: "user",
                                content: `Evaluate these answers leniently, focusing on meaning rather than exact wording:\n\n${qaPairs}`
                            }
                        ],
                        temperature: 0.3
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

                console.log("Raw AI evaluation:\n", content);

                // Validate evaluation format
                if (!/Evaluation: (Correct|Wrong)/i.test(content)) {
                    throw new Error('Invalid evaluation format - missing Correct/Wrong markers');
                }

                // Extract evaluation blocks (excluding final correct count line)
                const cleanedContent = content.replace(/Total Correct Answers:.*/i, '').trim();
                
                // Enhanced evaluation parsing
                evaluations = cleanedContent.split('\n\n')
                    .filter(item => item.trim().length > 0)
                    .map(item => {
                        const lines = item.split('\n');
                        const question = lines[0]?.replace(/^Q\d+:\s*/i, '') || '';
                        const answer = lines[1]?.replace(/^A\d+:\s*/i, '') || '';
                        const expected = lines[2]?.replace(/^Expected:\s*/i, '') || '';
                        const evaluation = lines[3]?.replace(/^Evaluation:\s*/i, '') || '';
                        
                        return {
                            question,
                            answer,
                            expected,
                            evaluation,
                            isCorrect: evaluation.includes('Correct') && 
                            !evaluation.includes('Wrong') && 
                            !evaluation.includes('No answer') &&
                            answer.trim().length > 0,
                        };
                    });
                 
                // Count correct answers based on evaluation text
                correctCount = evaluations.filter(e => e.isCorrect).length;
                console.log("✔️ Correct:Ans", correctCount);
                // Calculate wrong answers
                wrongCount = 15 - correctCount;
                console.log("❌ Wrong:Ans", wrongCount);
                // Validate counts
                if (correctCount + wrongCount !== 15) {
                    console.warn('Count mismatch:', {
                        questions: questions.length,
                        correct: correctCount,
                        wrong: wrongCount,
                    });
                }
                success = true;

                console.log("✅ Evaluation complete:");
                console.log("✔️ Correct:", correctCount);
                console.log("❌ Wrong:", wrongCount);
            

            } catch (error) {
                lastError = error;
                retryCount++;
                console.warn(`⚠️ Attempt ${retryCount} failed:`, error.message);
                if (retryCount < maxRetries) {
                    await new Promise(resolve => setTimeout(resolve, 1000 * retryCount));
                }
            }
        }

        if (!success) {
            throw lastError || new Error("Unknown evaluation error");
        }

        // Save to DB
        const user = await Resume.findOne({ email });
        if (!user) {
            throw new Error("User not found");
        }

        // Remove old entry for same jobRole
        user.mockInterviewData = user.mockInterviewData.filter(interview =>
            interview.jobRole !== jobRole
        );

        const numericScore = Number(score) || 0;
        user.score = numericScore;
        console.log(evaluations)
        user.mockInterviewData.push({
            score: numericScore,
            jobRole,
            questions,
            answers: processedAnswers,
            expectedAnswers,
            correctCount,
            wrongCount,
      
            evaluations: evaluations.map(e => ({
                question: e.question,
                answer: e.answer,
                expected: e.expected,
                evaluation: e.evaluation,
                isCorrect: e.isCorrect
            })),
            date: new Date()
        });

        await user.save();

        res.json({
            success: true,
            evaluations: evaluations.map(e => ({
                question: e.question,
                answer: e.answer,
                expected: e.expected,
                evaluation: e.evaluation,
                isCorrect: e.isCorrect
            })),
            correctCount,
            wrongCount
        });

    } catch (error) {
        console.error("❌ Error in evaluateAnswers:", {
            error: error.message,
            stack: error.stack,
            timestamp: new Date().toISOString()
        });

        res.status(500).json({
            success: false,
            error: "Evaluation failed",
            details: error.message
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

        const user = await Resume.findById(decoded.id).select("mockInterviewData score").lean();
        if (!user) {
            return res.status(404).json({ error: "User not found." });
        }

        // Process mock interview data by job role
        const dashboardData = {};
        user.mockInterviewData.forEach(({ jobRole, correctCount, score }) => {
            if (!dashboardData[jobRole]) {
                dashboardData[jobRole] = {
                    jobRole,
                    correctAnswers: 0,
                    resumeAnalysisScore: score || 0, // Changed from 'score' to 'resumeAnalysisScore'
                    interviewScore: 0 // Add interview score if needed
                };
            }
            dashboardData[jobRole].correctAnswers += correctCount;
            // Keep the highest score if multiple entries exist
            if (score && score > dashboardData[jobRole].resumeAnalysisScore) {
                dashboardData[jobRole].resumeAnalysisScore = score;
            }
        });

        // Also include the overall user score
        const result = {
            data: Object.values(dashboardData),
            overallScore: user.score || 0
        };

        res.json(result);
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
            await fs.unlink(req.file.path);
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await Resume.findById(decoded.id);

        if (!user) {
            await fs.unlink(req.file.path);
            return res.status(404).json({ error: 'User not found' });
        }

        // Read the file and convert to Base64
        const fileData = await fs.readFile(req.file.path);
        const base64Image = fileData.toString('base64');

        // Determine the MIME type
        const mimeType = req.file.mimetype;

        // Create data URI
        const profilePicture = `data:${mimeType};base64,${base64Image}`;

        // Update user with Base64 encoded image
        user.profilePicture = profilePicture;
        await user.save();

        // Delete the temporary file
        await fs.unlink(req.file.path);

        res.json({
            message: 'Profile picture uploaded successfully',
            profilePicture: profilePicture
        });
    } catch (error) {
        console.error('Error uploading profile picture:', error);
        if (req.file) {
            try {
                await fs.unlink(req.file.path);
            } catch (unlinkError) {
                console.error('Error deleting temp file:', unlinkError);
            }
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
