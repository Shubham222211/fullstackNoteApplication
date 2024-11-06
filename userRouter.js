const express=require('express')
const userRouter=express.Router()
const bcrypt=require('bcrypt')
const userModal = require('./userModal.js')
const jwt=require('jsonwebtoken')

userRouter.post("/register", async (req, res) => {
    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(req.body.password, 3);
        req.body.password = hashedPassword;

        // Attempt to create the user
        const signData = await userModal.create(req.body);
        res.status(200).json({ msg: 'User registered successfully' });
    } catch (error) {
        // Check for duplicate key error (error code 11000)
        if (error.code === 11000 && error.keyPattern.email) {
            res.status(400).json({ msg: 'Opps! Already in use..' });
        } else {
            res.status(500).json({ msg: 'Error in registration' });
        }
    }
});


userRouter.post('/login', async (req, res) => {
    try {
        const user = await userModal.findOne({ email: req.body.email });

        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }

        // Verify password with bcrypt
        const isPasswordValid = await bcrypt.compare(req.body.password, user.password);

        if (!isPasswordValid) {
            return res.status(401).json({ msg: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign({ userId: user._id }, process.env.SECRET_KEY, { expiresIn: '1h' });

        res.status(200).json({ msg: 'Login successful', token });
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ msg: 'Error during login' });
    }
});
module.exports=userRouter