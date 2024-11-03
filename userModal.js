const mongoose=require('mongoose')

const userSchema=mongoose.Schema({
    name:{type:String,required:true},
    email:{type:String,required:true,unique:true},
    password:{type:String,required:true},
    gender:{type:String,enum:['male','female'],required:true},
    age:{type:String,required:true},
},{
    versionKey:false,
    timestamps:true
})

const userModal=mongoose.model('User',userSchema)


module.exports=userModal