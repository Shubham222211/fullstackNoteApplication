const express=require('express')
const userRouter=express.Router()
const bcrypt=require('bcrypt')
const userModal = require('./userModal.js')
const jwt=require('jsonwebtoken')


userRouter.post("/register",(req,res)=>{

    try {

        bcrypt.hash(req.body.password,3,async function(err,hash){

if(err){
    return res.status(400).json({msg:'error'})
}
req.body.password=hash

const signData=await userModal.create(req.body)

res.status(200).json({msg:'user register success'})
        })
        
    } catch (error) {
        res.status(400).json({msg:'error in register'})
    }
})


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