import mongoose from "mongoose";

const ResumeSchema = new mongoose.Schema({
    googleId: { type: String, default: null }, // 🔹 Google user ID
    displayName: { type: String, default: "" }, // 🔹 From Google profile
    profilePicture: { type: String, default: "" }, // already in your schema

    username: { type: String, required: true},
    email: { type: String, required: true, unique: true },
    phoneNumber: {
        type: Number,
        trim: true,
        default: "",
    },
    password: { type: String, default: null }, // 🔹 Optional if using Google login only

    mockInterviewData: [{
        score: { type: Number, default: null },
        jobRole: { type: String, default: "0" },
        questions: [{ type: String }],
        answers: [{ type: String }],
        expectedAnswers: [{ type: String }],
        correctCount: { type: Number, default: 0 },
        wrongCount: { type: Number, default: 0 },
        date: { type: Date, default: Date.now }
    }],

    gender: { type: String, default: "" },
    location: { type: String, default: "" },
    birthday: { type: Date, default: null },
    summary: { type: String, default: "" },
    githubLink: { type: String, default: "" },
    linkedinLink: { type: String, default: "" }
});

export default mongoose.model("Resume", ResumeSchema);
