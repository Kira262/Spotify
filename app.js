const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const session = require("express-session");
const bcrypt = require("bcrypt");
const port = 3000;

const app = express();

mongoose.connect("mongodb://localhost/mongodb-auth", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  name: String,
  dob: Date,
  gender: String,
});

const User = mongoose.model("User", userSchema);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({ secret: "your-secret-key", resave: true, saveUninitialized: true })
);

app.use(express.static("public"));
app.get("/signup", (req, res) => {
  res.sendFile(__dirname + "/sign-up.html");
});

app.post("/signup", async (req, res) => {
  const { email, password, confirmPassword, name, dob, gender } = req.body;

  try {
    if (password !== confirmPassword) {
      return res.status(400).send("Passwords do not match");
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      email,
      password: hashedPassword,
      name,
      dob: new Date(dob),
      gender,
    });

    await user.save();

    res.send("User registered successfully");
  } catch (error) {
    res.status(500).send("Error registering user");
  }
});
app.get("/login", (req, res) => {
  res.sendFile(__dirname + "/login.html");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).send("User not found");
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).send("Incorrect password");
    }

    req.session.user = user;
    res.send("Login successful");
  } catch (error) {
    res.status(500).send("Error logging in");
  }
});

app.get("/profile", (req, res) => {
  if (!req.session.user) {
    return res.status(401).send("Unauthorized");
  }

  res.send(`Welcome, ${req.session.user.name}!`);
});

app.listen(port, () => {
  console.log(`Server is running on port http://localhost:${port}`);
});
