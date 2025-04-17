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
    mockInterviewData: [{
        score: { type: Number, default: null },
        jobRole: { type: String, default: 0 },
        questions: [{ type: String }],
        answers: [{ type: String }],
        expectedAnswers: [{ type: String }],
        correctCount: { type: Number, default: 0 },
        wrongCount: { type: Number, default: 0 },
        skippedCount: { type: Number, default: 0 },
        date: { type: Date, default: Date.now }
    }],
    gender: { type: String, default: "" },
    location: { type: String, default: "" },
    birthday: { type: Date, default: null },
    summary: { type: String, default: "" },
    githubLink: { type: String, default: "" },
    linkedinLink: { type: String, default: "" },
    profilePicture: { type: String, default: "" }
});

export default mongoose.model("Resume", ResumeSchema);