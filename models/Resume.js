import mongoose from "mongoose";

const ResumeSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    phoneNumber: {
        type: Number,
        trim: true,
        default: "",
    },
    password: { type: String, required: true },
    resumeAnalysis: [{
        score: { type: Number, default: null },  // Resume Analysis Score
        feedback: { type: String, default: "" },  // Detailed Feedback
        date: { type: Date, default: Date.now }   // Date of analysis
    }],
    mockInterviewData: [{
        jobRole: { type: String, required: true },
        questions: [{ type: String }],
        answers: [{ type: String }],
        expectedAnswers: [{ type: String }],
        correctCount: { type: Number, default: 0 },
        wrongCount: { type: Number, default: 0 },
        skippedCount: { type: Number, default: 0 },
        date: { type: Date, default: Date.now }
    }],
    gender: { type: String },
    location: { type: String },
    birthday: { type: Date },
    summary: { type: String },
    githubLink: { type: String },
    linkedinLink: { type: String }
});

export default mongoose.model("Resume", ResumeSchema);

