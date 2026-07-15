import { Router } from "express";
import { verifyEmailHandler,registerHandler,LoginHandler } from "../controllers/auth/auth.controller";

const router=Router();

router.post("/register",registerHandler);
router.post("/login",LoginHandler);
router.get("/verify-email",verifyEmailHandler);

export default router;