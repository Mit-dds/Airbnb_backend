const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("./models/Users");
const cookieParser = require("cookie-parser");

dotenv.config();

const app = express();

const bcryptSalt = bcrypt.genSaltSync(10);
const jwtSecret = process.env.JWT_SECRET;

app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    credentials: true,
    origin: "http://localhost:5173",
  }),
);

mongoose.connect(process.env.MONGO_URL);
// console.log(process.env.MONGO_URL);

app.get("/test", (req, res) => {
  res.json("test ok Mit");
});

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  // res.json({name, email, password});

  try {
    const userData = await User.create({
      name,
      email,
      password: bcrypt.hashSync(password, bcryptSalt),
    });

    res.json(userData);
  } catch (e) {
    res.status(422).json(e);
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const userData = await User.findOne({ email });
  // console.log(userData + "userData called");
  if (userData) {
    // const passOk = await bcrypt.compare(password, userData.password);
    const passOk = bcrypt.compare(password, userData.password);
    if (passOk) {
      jwt.sign(
        { email: userData.email, id: userData._id, name: userData.name },
        jwtSecret,
        {},
        (err, token) => {
          if (err) throw err;
          res.cookie("token", token).json(userData);
        },
      );
    } else {
      res.status(422).json("pass not ok");
    }
  } else {
    res.json("not found");
  }
});

app.get("/profile", (req, res) => {
  const { token } = req.cookies;

  if (!token) {
    return res.json(null);
  }

  if (token) {
    jwt.verify(token, jwtSecret, {}, async (err, user) => {
      if (err) throw err;
      const { name, email, _id } = await User.findById(user.id);
      res.json({ name, email, _id });
    });
    // const decoded = jwt.verify(token, jwtSecret);
    // const user = await User.findById(decoded.id);
  } else {
    res.json(null);
  }

  // jwt.verify(token, jwtSecret, {}, (err, user) => {
  //   if (err) return res.json(null);
  //   res.json(user);
  // });
});

app.post("/logout", (req, res) => {
  res.cookie('token', '').json(true);
});

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
