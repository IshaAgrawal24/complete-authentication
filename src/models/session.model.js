import mongoose from "mongoose";

const sessionSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "users",
      required: [true, "User is required"],
    },
    refreshTokenHash: {
      type: String,
      required: [true, "Refresh Token is required."],
    },
    ip: {
      type: String,
      required: [true, "IP is required"],
    },
    userAgent: {
      type: String,
      required: [true, "UserAgent is required"],
    },
    revoked: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true },
);

const sessionModel = mongoose.model("sessions", sessionSchema);

export default sessionModel;
