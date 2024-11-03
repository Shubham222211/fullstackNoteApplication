const express=require('express')
const notesModel = require('./notesModal')

const notesRouter=express.Router()





notesRouter.post("/create",async(req,res)=>{

try {
    const data=await notesModel.create({...req.body,userId:req.userId})
    res.status(200).json({msg:"notes created success",data})
} catch (error) {
    res.status(500).json({ msg: 'Failed to create notes', error: error.message });
}
})



notesRouter.get("/get",async(req,res)=>{

    try {
        const data=await notesModel.find({userId:req.userId})
        res.status(200).json({ msg: 'Notes retrieved successfully', data });
    } catch (error) {
        res.status(500).json({ msg: 'Failed to retrieve notes', error: error.message });
    }
})


notesRouter.patch("/update/:id",async(req,res)=>{

    try {
        const updateField=req.body

        const data=await notesModel.findByIdAndUpdate(req.params.id,{userId:req.userId,...updateField},{new:true})
        res.status(200).json({ msg: 'Note updated successfully', data });
    } catch (error) {
        res.status(500).json({ msg: 'Failed to update note', error: error.message });
    }
})


notesRouter.delete("/delete/:id",async(req,res)=>{

    try {
        const data=await notesModel.findByIdAndDelete(req.params.id,{userId:req.userId})
        res.status(200).json({ msg: 'Note deleted successfully', data });
    } catch (error) {
        res.status(500).json({ msg: 'Failed to delete note', error: error.message });
    }
})












module.exports=notesRouter