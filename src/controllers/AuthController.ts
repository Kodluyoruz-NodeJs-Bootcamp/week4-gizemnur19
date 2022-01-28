import { Request, Response } from "express";
import * as jwt from "jsonwebtoken";
import { getRepository } from "typeorm";
import { validate } from "class-validator";

import { User } from "../entity/User";
import config from "../config/config";

class AuthController {
  static login = async (req: Request, res: Response) => {
    //Check if username and password are set
    let { username, password } = req.body;
    if (!(username && password)) {
      res.status(400).send();
    }

    //Get user from database
    const userRepository = getRepository(User);
    let user: User;
    try {
      user = await userRepository.findOneOrFail({ where: { username } });
    } catch (error) {
      res.status(401).send();
    }

    //Check if encrypted password match
    if (!user.checkIfUnencryptedPasswordIsValid(password)) {
      res.status(401).send();
      return;
    }

    //Sing JWT, valid for 1 day
    const token = jwt.sign(
      { userId: user.id, username: user.username },
      config.jwtSecret,
      { expiresIn: "1d" }
    );

    res.header("auth", token).status(200).json({
      msg: "User is loggedin!",
    });
  };

  static register = async (req: Request, res: Response) => {
    //Get parameters from the body
    let { username, password, role } = req.body;
    let user = new User();
    user.username = username;
    user.password = password;
    user.role = "USER";
  
    //Validade if the parameters are ok
    const errors = await validate(user);
    if (errors.length > 0) {
      res.status(400).send(errors);
      return;
    }
  
    //Hash the password, to securely store on DB
    user.hashPassword();
  
    //Try to save. If fails, the username is already in use
    const userRepository = getRepository(User);
    try {
      await userRepository.save(user);
    } catch (e) {
      res.status(409).send("username already in use");
      return;
    }

    //Sing JWT, valid for 1 day
    const token = jwt.sign(
      { userId: user.id, username: user.username },
      config.jwtSecret,
      { expiresIn: "1d" }
    );

    //If all ok, send 200 response
    res.header("auth", token).status(200).json({
      msg: "User registered successfully!",
      user,
    });
  };

  static profile = async (req: Request, res: Response) => {
    //Get the ID from the url
    const id: string = req.params.id;
  
    //Get the user from database
    const userRepository = getRepository(User);
    try {
      const user = await userRepository.findOneOrFail(id, {
        select: ["id", "username", "role"] //We dont want to send the password on response
      });
      res.send(user);
    } catch (error) {
      res.status(404).send("User not found");
    }
  };
}
export default AuthController;
