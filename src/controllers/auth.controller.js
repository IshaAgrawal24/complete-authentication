import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import userModel from "../models/auth.model.js";

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

  const accessToken = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, {
    expiresIn: "15m",
  });

  const refreshToken = jwt.sign(
    {
      id: newUser._id,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: "7d",
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
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);

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
    console.log("Refresh token Controller:", error)
    return res.status(401).json({
      return_status: 401,
      return_message: "unauthorized",
    });
  }
};
