const mongoose=require('mongoose')

const notesShema=mongoose.Schema({

    title:{type:String,required:true},
    content:{type:String,required:true},
    status:{type:Boolean},
    userId:{type:mongoose.Schema.Types.ObjectId,ref:'User',required:true}
},{
    versionKey:false,
    timestamps:true
})

const notesModel=mongoose.model('Note',notesShema)

module.exports=notesModel