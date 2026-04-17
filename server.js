import dotenv from "dotenv";
import app from "./src/app.js";
import connectDB from "./src/db/db.js";

dotenv.config({ path: "./.env" });

const PORT = process.env.PORT;

connectDB()

app.listen(PORT, () => {
    console.log("Server has started")
})



