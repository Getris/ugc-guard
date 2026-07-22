import express from "express";
import { createCommunityGuard } from "@getris/ugc-guard/community";
import { createExpressMiddleware } from "@getris/ugc-guard/express";

const app = express();
const guard = createCommunityGuard({ enableRateLimit: true });

app.use(express.json({ limit: "32kb" }));
app.post(
  "/comments",
  createExpressMiddleware(guard, {
    field: "text",
    getUserId: (request) => request.user?.id,
    exposeFindings: false
  }),
  (request, response) => {
    response.status(201).json({ text: request.body.text });
  }
);
