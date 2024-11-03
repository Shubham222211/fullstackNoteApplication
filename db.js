const dotenv=require('dotenv').config()
const mongoose=require('mongoose')

// dotenv.config()

const connection=mongoose.connect(process.env.MONGO_URL)


module.exports=connection