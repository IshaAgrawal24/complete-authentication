import mongoose from "mongoose";

async function connectDB() {
    await mongoose.connect(process.env.MONGO_URL);
    console.log("Connected to DB")
}

export default connectDB