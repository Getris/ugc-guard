import type { ContentGuard } from "../core/guard.js";

export interface FastifyLikeRequest {
  body?: unknown;
  user?: { id?: string };
}

export interface FastifyLikeReply {
  code(statusCode: number): FastifyLikeReply;
  send(payload: unknown): unknown;
}

export interface FastifyAdapterOptions {
  field?: string;
  rejectStatus?: number;
}

export function createFastifyPreHandler(guard: ContentGuard, options: FastifyAdapterOptions = {}) {
  const field = options.field ?? "text";
  const rejectStatus = options.rejectStatus ?? 422;

  return async (request: FastifyLikeRequest, reply: FastifyLikeReply): Promise<unknown> => {
    const body = isRecord(request.body) ? request.body : {};
    const value = body[field];
    if (typeof value !== "string") return reply.code(400).send({ error: `Expected body.${field} to be a string.` });

    const result = await guard.inspect({ text: value, ...(request.user?.id ? { userId: request.user.id } : {}) });
    if (!result.allowed) return reply.code(rejectStatus).send({ error: "Content rejected.", guard: result });
    body[field] = result.normalizedText;
    return undefined;
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
