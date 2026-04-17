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

  const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET);

  res.status(201).json({
    status_code: 201,
    return_message: "User registered successfully.",
    user: {
        id: newUser._id,
        user_name: newUser.userName,
        email: newUser.email,
    },
    token: token,
  });
};
