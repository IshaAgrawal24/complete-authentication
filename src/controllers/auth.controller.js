import bcrypt from "bcrypt";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import userModel from "../models/auth.model.js";
import sessionModel from "../models/session.model.js";

export const register = async (req, res) => {
  const { userName, email, password } = req.body;

  const isUserAlreadyExist = await userModel.findOne({
    $or: [{ userName }, { email }],
  });

  if (isUserAlreadyExist) {
    return res.status(401).json("Unauthorised");
  }

  const saltRounds = 10;
  const hashPassword = await bcrypt.hash(password, saltRounds);

  const newUser = await userModel.create({
    userName,
    email,
    password: hashPassword,
  });

  //   First we generate Refresh Token, and after that we create access token
  const refreshToken = jwt.sign(
    {
      id: newUser._id,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: "7d",
    },
  );

  const refreshTokenHash = crypto
    .createHash("sha256")
    .update(refreshToken)
    .digest("hex");

  //   Create Session
  const session = await sessionModel.create({
    user: newUser._id,
    refreshTokenHash,
    ip: req.ip,
    userAgent: req.headers["user-agent"],
  });

  const accessToken = jwt.sign(
    { id: newUser._id, sessionId: session._id },
    process.env.JWT_SECRET,
    {
      expiresIn: "15m",
    },
  );

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });

  res.status(201).json({
    status_code: 201,
    return_message: "User registered successfully.",
    user: {
      id: newUser._id,
      user_name: newUser.userName,
      email: newUser.email,
    },
    accessToken,
  });
};

export const getMe = async (req, res) => {
  const token = req.header("Authorization").split(" ")[1];

  if (!token) {
    return res.status(401).json({
      return_status: 401,
      return_message: "Token doesn't found.",
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await userModel.findById(decoded.id);

    res.status(200).json({
      return_status: 200,
      return_message: "User found successfully.",
      user_data: {
        user_name: user.userName,
        email: user.email,
      },
    });
  } catch (error) {
    console.log("GetMe Controller", error);
    return res.status(401).json({
      return_status: 401,
      return_message: "unauthorized",
    });
  }
};

export const getRefreshToken = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({
      return_status: 401,
      return_message: "Token not found.",
    });
  }

  try {
    const decoded = await jwt.verify(refreshToken, process.env.JWT_SECRET);

    const refreshTokenHash = crypto
      .createHash("sha256")
      .update(refreshToken)
      .digest("hex");

    const session = await sessionModel.findOne({
      refreshTokenHash,
      revoked: false,
    });

    if (!session) {
      return res.status(400).json({
        return_message: "Invalid refresh token.",
      });
    }

    const accessToken = jwt.sign({ id: decoded.id }, process.env.JWT_SECRET, {
      expiresIn: "15m",
    });

    const newRefreshToken = jwt.sign(
      {
        id: decoded.id,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d",
      },
    );

    const newRefreshTokenHash = crypto
      .createHash("sha256")
      .update(newRefreshToken)
      .digest("hex");

    session.refreshTokenHash = newRefreshTokenHash;

    await session.save();

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.status(200).json({
      status_code: 200,
      return_message: "Access Token Generated Successfully.",
      accessToken,
    });
  } catch (error) {
    console.log("Refresh token Controller:", error);
    return res.status(401).json({
      return_status: 401,
      return_message: "unauthorized",
    });
  }
};

export const logout = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(400).json({
      return_message: "Refresh token not found.",
    });
  }

  const refreshTokenHash = crypto
    .createHash("sha256")
    .update(refreshToken)
    .digest("hex");

  const session = await sessionModel.findOne({
    refreshTokenHash,
    revoked: false,
  });

  if (!session) {
    return res.status(400).json({
      return_message: "Invalid refresh token",
    });
  }

  session.revoked = true;
  await session.save();

  res.clearCookie(refreshToken);

  res.status(200).json({
    status_code: 200,
    return_message: "Logged out successfully.",
  });
};
