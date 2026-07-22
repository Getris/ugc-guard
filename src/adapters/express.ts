import type { ContentGuard } from "../core/guard.js";
import type { GuardResult } from "../core/types.js";
import { isRecord } from "../core/utils.js";

export interface ExpressLikeRequest {
  body?: unknown;
  user?: { id?: string };
  ip?: string;
  ugcGuard?: GuardResult;
}

export interface ExpressLikeResponse {
  status(code: number): ExpressLikeResponse;
  json(body: unknown): unknown;
}

export type ExpressLikeNext = (error?: unknown) => void;

export interface ExpressAdapterOptions {
  field?: string;
  rejectStatus?: number;
  rejectOnReview?: boolean;
  exposeFindings?: boolean;
  replaceWithNormalized?: boolean;
  getUserId?: (request: ExpressLikeRequest) => string | undefined;
}

export function createExpressMiddleware(guard: ContentGuard, options: ExpressAdapterOptions = {}) {
  const field = options.field ?? "text";
  const rejectStatus = options.rejectStatus ?? 422;
  const rejectOnReview = options.rejectOnReview ?? false;
  const exposeFindings = options.exposeFindings ?? false;
  const replaceWithNormalized = options.replaceWithNormalized ?? true;
  const getUserId = options.getUserId ?? ((request: ExpressLikeRequest) => request.user?.id);

  return async (request: ExpressLikeRequest, response: ExpressLikeResponse, next: ExpressLikeNext): Promise<unknown> => {
    try {
      if (!isRecord(request.body)) {
        return response.status(400).json({
          error: "INVALID_REQUEST_BODY",
          message: "Expected a JSON object request body."
        });
      }

      const value = request.body[field];
      if (typeof value !== "string") {
        return response.status(400).json({
          error: "INVALID_CONTENT_FIELD",
          message: `Expected body.${field} to be a string.`
        });
      }

      const userId = getUserId(request);
      const result = await guard.inspect({
        text: value,
        ...(userId ? { userId } : {}),
        ...(request.ip ? { ip: request.ip } : {})
      });

      request.ugcGuard = result;
      const rejected = result.decision === "block" || (rejectOnReview && result.decision === "review");
      if (rejected) {
        return response.status(rejectStatus).json({
          error: "CONTENT_REJECTED",
          message: "Content did not pass the configured policy.",
          decision: result.decision,
          ...(exposeFindings ? { score: result.score, findings: result.findings } : {})
        });
      }

      if (replaceWithNormalized) request.body[field] = result.normalizedText;
      return next();
    } catch (error) {
      return next(error);
    }
  };
}
