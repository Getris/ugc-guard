import type { ContentGuard } from "../core/guard.js";
import type { GuardResult } from "../core/types.js";
import { isRecord } from "../core/utils.js";

export interface FastifyLikeRequest {
  body?: unknown;
  user?: { id?: string };
  ip?: string;
  ugcGuard?: GuardResult;
}

export interface FastifyLikeReply {
  code(statusCode: number): FastifyLikeReply;
  send(payload: unknown): unknown;
}

export interface FastifyAdapterOptions {
  field?: string;
  rejectStatus?: number;
  rejectOnReview?: boolean;
  exposeFindings?: boolean;
  replaceWithNormalized?: boolean;
  getUserId?: (request: FastifyLikeRequest) => string | undefined;
}

export function createFastifyPreHandler(guard: ContentGuard, options: FastifyAdapterOptions = {}) {
  const field = options.field ?? "text";
  const rejectStatus = options.rejectStatus ?? 422;
  const rejectOnReview = options.rejectOnReview ?? false;
  const exposeFindings = options.exposeFindings ?? false;
  const replaceWithNormalized = options.replaceWithNormalized ?? true;
  const getUserId = options.getUserId ?? ((request: FastifyLikeRequest) => request.user?.id);

  return async (request: FastifyLikeRequest, reply: FastifyLikeReply): Promise<unknown> => {
    if (!isRecord(request.body)) {
      return reply.code(400).send({
        error: "INVALID_REQUEST_BODY",
        message: "Expected a JSON object request body."
      });
    }

    const value = request.body[field];
    if (typeof value !== "string") {
      return reply.code(400).send({
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
      return reply.code(rejectStatus).send({
        error: "CONTENT_REJECTED",
        message: "Content did not pass the configured policy.",
        decision: result.decision,
        ...(exposeFindings ? { score: result.score, findings: result.findings } : {})
      });
    }

    if (replaceWithNormalized) request.body[field] = result.normalizedText;
    return undefined;
  };
}
