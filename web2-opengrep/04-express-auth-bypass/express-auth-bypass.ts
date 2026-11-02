import express from "express";

const app = express();
const authMiddleware = (_req: express.Request, _res: express.Response, next: express.NextFunction) =>
  next();

class UserModel {
  static findById(id: string) {
    return { id, email: "a@example.com" };
  }
}

app.get("/users/:id", (req, res) => {
  // ruleid: express-auth-bypass
  const row = UserModel.findById(req.params.id);
  res.json(row);
});

app.delete("/account", (req, res) => {
  // ruleid: express-auth-bypass
  res.json({ ok: true, user: req.user });
});

app.get("/users/:id", authMiddleware, (req, res) => {
  // ok: express-auth-bypass
  res.json(UserModel.findById(req.params.id));
});

app.get("/profile", authMiddleware, (req, res) => {
  // ok: express-auth-bypass
  res.json(req.user);
});
