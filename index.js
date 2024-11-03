const express=require('express')
const cors=require('cors')
const connection = require('./db.js')
const app=express()
const dotenv=require('dotenv')
const userRouter = require('./userRouter.js')
const notesRouter = require('./notesRouter.js')
const Auth = require('./AuthMiddleware.js')
dotenv.config()


const PORT = process.env.PORT || 5000;

app.use(cors({
    origin:'*'
}))


app.use(express.json())
app.use('/user',userRouter)
app.use('/notes',Auth,notesRouter)



app.get("/",(req,res)=>{

    res.send('server is running fine for notes application..')
})



app.listen(PORT,async()=>{
    try {
        await connection
        console.log(`server running on port ${PORT}`)
    } catch (error) {
        console.log(error)
    }
})