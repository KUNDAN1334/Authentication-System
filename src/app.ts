import express, { Router } from 'express';
import cookieParser from 'cookie-parser';
import authRouter from './routes/auth.routes'
import userRouter from './routes/user.route'

const app=express();

app.use(express.json());
app.use(cookieParser());

app.get("/",(req,res)=>{
    res.json({msg: "ok"});
})

app.use("/auth",authRouter);
app.use("/user",userRouter);

export default app;

