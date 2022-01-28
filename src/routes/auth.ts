import { Router } from "express";
import AuthController from "../controllers/AuthController";
import { checkJwt } from "../middlewares/checkJwt";
import { checkRole } from "../middlewares/checkRole";

const router = Router();
//Login route
router.post("/login", checkJwt, AuthController.login);

//Sign up route
router.post("/register", AuthController.register);

// Get profile
router.get("/profile/:id([0-9]+)", checkJwt,
    AuthController.profile
  );

export default router;