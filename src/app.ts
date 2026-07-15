import express, { Router } from 'express';
import cookieParser from 'cookie-parser';
import authRouter from './routes/auth.routes'

const app=express();

app.use(express.json());
app.use(cookieParser());

app.get("/",(req,res)=>{
    res.json({msg: "ok"});
})

app.use("/auth",authRouter);

export default app;

