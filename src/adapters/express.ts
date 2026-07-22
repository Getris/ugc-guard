import type { ContentGuard } from "../core/guard.js";

export interface ExpressLikeRequest {
  body?: unknown;
  user?: { id?: string };
}

export interface ExpressLikeResponse {
  status(code: number): ExpressLikeResponse;
  json(body: unknown): unknown;
}

export type ExpressLikeNext = (error?: unknown) => void;

export interface ExpressAdapterOptions {
  field?: string;
  rejectStatus?: number;
}

export function createExpressMiddleware(guard: ContentGuard, options: ExpressAdapterOptions = {}) {
  const field = options.field ?? "text";
  const rejectStatus = options.rejectStatus ?? 422;

  return async (request: ExpressLikeRequest, response: ExpressLikeResponse, next: ExpressLikeNext): Promise<unknown> => {
    try {
      const body = isRecord(request.body) ? request.body : {};
      const value = body[field];
      if (typeof value !== "string") {
        return response.status(400).json({ error: `Expected body.${field} to be a string.` });
      }

      const result = await guard.inspect({ text: value, ...(request.user?.id ? { userId: request.user.id } : {}) });
      if (!result.allowed) return response.status(rejectStatus).json({ error: "Content rejected.", guard: result });
      body[field] = result.normalizedText;
      return next();
    } catch (error) {
      return next(error);
    }
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
