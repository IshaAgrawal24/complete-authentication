import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    userName: {
        type: String,
        required: [true, "Username is required."],
        unique: true
    },
    email: {
        type: String,
        required: [true, "Email is required."],
        unique: true
    }, 
    password: {
        type: String,
        required: [true, "Password is required."],
        unique: true
    }
})

const userModel = mongoose.model("User", userSchema);

export default userModel;