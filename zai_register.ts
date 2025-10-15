import { serve } from "https://deno.land/std@0.208.0/http/server.ts";

const FE_VERSION = "prod-fe-1.0.98";

const MODEL_MAPPING: Record<string, string> = {
  "GLM-4.5": "0727-360B-API",
  "GLM-4.6": "GLM-4-6-API-V1",
};

async function getToken(): Promise<string> {
  try {
    const response = await fetch("https://chat.z.ai/api/v1/auths/");
    const data = await response.json();
    return data.token;
  } catch (error) {
    console.error("[Token Error] Exception while getting token:", error);
    throw error;
  }
}

function decodeJwtPayload(token: string): any {
  const parts = token.split(".");
  let payload = parts[1];
  const padding = 4 - (payload.length % 4);
  if (padding !== 4) payload += "=".repeat(padding);
  
  const decoded = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
  return JSON.parse(decoded);
}

async function hmacSha256(key: string | Uint8Array, data: string): Promise<string> {
  const keyData = typeof key === "string" ? new TextEncoder().encode(key) : key;
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    new TextEncoder().encode(data)
  );
  return Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function zs(e: string, t: string, timestamp: number) {
  const i = timestamp.toString();
  const w = btoa(
    Array.from(new TextEncoder().encode(t))
      .map(byte => String.fromCharCode(byte))
      .join('')
  );
  const c = `${e}|${w}|${i}`;
  const E = Math.floor(timestamp / (5 * 60 * 1000));
  const A = await hmacSha256("junjie", E.toString());
  const signature = await hmacSha256(A, c);
  return { signature, timestamp };
}

function extractLatestUserContent(messages: any[]): string {
  for (let i = messages.length - 1; i >= 0; i--) {
    if (messages[i].role === "user") {
      return messages[i].content || "";
    }
  }
  return "";
}

async function makeUpstreamRequest(messages: any[], model: string) {
  const token = await getToken();
  const payload = decodeJwtPayload(token);
  const userId = payload.id;
  const chatId = crypto.randomUUID();
  const timestamp = Date.now();
  const requestId = crypto.randomUUID();

  const targetModel = MODEL_MAPPING[model] || model;
  const latestUserContent = extractLatestUserContent(messages);

  const e = `requestId,${requestId},timestamp,${timestamp},user_id,${userId}`;
  const { signature } = await zs(e, latestUserContent, timestamp);

  const url = new URL("https://chat.z.ai/api/chat/completions");
  url.searchParams.set("timestamp", timestamp.toString());
  url.searchParams.set("requestId", requestId);
  url.searchParams.set("user_id", userId);
  url.searchParams.set("token", token);
  url.searchParams.set("current_url", `https://chat.z.ai/c/${chatId}`);
  url.searchParams.set("pathname", `/c/${chatId}`);
  url.searchParams.set("signature_timestamp", timestamp.toString());

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`,
      "X-FE-Version": FE_VERSION,
      "X-Signature": signature,
      "Content-Type": "application/json",
      "Connection": "keep-alive",
      "Origin": "https://chat.z.ai",
      "Referer": `https://chat.z.ai/c/${crypto.randomUUID()}`,
    },
    body: JSON.stringify({
      stream: true,
      model: targetModel,
      messages,
      params: {},
      features: {
        image_generation: false,
        web_search: false,
        auto_web_search: false,
        preview_mode: true,
        enable_thinking: false,
      },
      chat_id: chatId,
      id: crypto.randomUUID(),
    }),
  });

  if (!response.ok) {
    console.error(`[Upstream Error] Non-200 response, status: ${response.status}, statusText: ${response.statusText}`);
    const errorText = await response.text();
    console.error(`[Upstream Error] Response body: ${errorText}`);
  }

  return { response, model: targetModel };
}

async function handleModels(): Promise<Response> {
  const models = [
    { id: "GLM-4.5", object: "model", owned_by: "z.ai" },
    { id: "GLM-4.6", object: "model", owned_by: "z.ai" },
  ];
  return new Response(JSON.stringify({ object: "list", data: models }), {
    headers: { "Content-Type": "application/json" },
  });
}

async function handleChatCompletions(req: Request): Promise<Response> {
  const data = await req.json();
  const messages = data.messages || [];
  const model = data.model || "GLM-4.6";
  const stream = data.stream || false;

  const { response, model: modelName } = await makeUpstreamRequest(messages, model);

  if (stream) {
    const reader = response.body?.getReader();
    const encoder = new TextEncoder();
    const completionId = `chatcmpl-${crypto.randomUUID().toString().slice(0, 29)}`;

    const readable = new ReadableStream({
      async start(controller) {
        let buffer = "";
        let hasContent = false;

        try {
          while (true) {
            const { done, value } = await reader!.read();
            if (done) break;

            buffer += new TextDecoder().decode(value);
            const lines = buffer.split("\n");
            buffer = lines.pop() || "";

            for (const line of lines) {
              if (!line.trim().startsWith("data: ")) continue;
              const payload = line.trim().slice(6);
              if (payload === "[DONE]") break;

              try {
                const parsed = JSON.parse(payload);
                const dataObj = parsed.data || {};
                const deltaContent = dataObj.delta_content || "";

                if (deltaContent) {
                  hasContent = true;
                  const chunk = {
                    id: completionId,
                    object: "chat.completion.chunk",
                    created: Math.floor(Date.now() / 1000),
                    model: modelName,
                    choices: [{ index: 0, delta: { content: deltaContent }, finish_reason: null }]
                  };
                  controller.enqueue(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));
                }
              } catch {}
            }
          }

          if (!hasContent) {
            console.error("[Stream Error] Response 200 but no content received");
          }

          const finalChunk = {
            id: completionId,
            object: "chat.completion.chunk",
            created: Math.floor(Date.now() / 1000),
            model: modelName,
            choices: [{ index: 0, delta: {}, finish_reason: "stop" }]
          };
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(finalChunk)}\n\n`));
          controller.enqueue(encoder.encode("data: [DONE]\n\n"));
        } finally {
          controller.close();
        }
      },
    });

    return new Response(readable, {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive"
      },
    });
  } else {
    const reader = response.body?.getReader();
    const chunks: string[] = [];
    let buffer = "";

    while (true) {
      const { done, value } = await reader!.read();
      if (done) break;

      buffer += new TextDecoder().decode(value);
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";

      for (const line of lines) {
        if (!line.trim().startsWith("data: ")) continue;
        const payload = line.trim().slice(6);
        if (payload === "[DONE]") break;

        try {
          const parsed = JSON.parse(payload);
          const dataObj = parsed.data || {};
          const deltaContent = dataObj.delta_content || "";

          if (deltaContent) {
            chunks.push(deltaContent);
          }
        } catch {}
      }
    }

    const fullContent = chunks.join("");
    
    if (!fullContent) {
      console.error("[Non-Stream Error] Response 200 but no content received");
    }

    return new Response(JSON.stringify({
      id: `chatcmpl-${crypto.randomUUID().toString().slice(0, 29)}`,
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model: modelName,
      choices: [{
        index: 0,
        message: { role: "assistant", content: fullContent },
        finish_reason: "stop"
      }],
    }), { headers: { "Content-Type": "application/json" } });
  }
}

async function handler(req: Request): Promise<Response> {
  const url = new URL(req.url);
  if (url.pathname === "/v1/models" && req.method === "GET") {
    return await handleModels();
  }
  if (url.pathname === "/v1/chat/completions" && req.method === "POST") {
    return await handleChatCompletions(req);
  }
  return new Response("Not Found", { status: 404 });
}

export default { fetch: handler };
