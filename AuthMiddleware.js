const jwt=require('jsonwebtoken')

const Auth=(req,res,next)=>{


    try {


        const token=req.headers.authorization.split(" ")[1]

        if(!token){
         return res.status(400).json({mag:'token not found'})
        }
        

            jwt.verify(token,process.env.SECRET_KEY,function(err,decoded){

                if(err) return res.status(400).json({msg:'invalid or expired token'})

                    req.userId=decoded.userId
                    next()
            })


        
    } catch (error) {
        return res.status(500).json({ msg: "Error in authentication", error:error.message });
        console.log(error)
    }
}

module.exports=Auth