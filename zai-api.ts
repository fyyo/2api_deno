import { serve } from "https://deno.land/std@0.208.0/http/server.ts";
import { encode as base64Encode } from "https://deno.land/std@0.208.0/encoding/base64.ts";

const FE_VERSION = "prod-fe-1.0.103";
const SIGNING_SECRET = "junjie";

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

/**
 * 生成Z.AI API双层HMAC-SHA256签名
 * 完全对照Python版本 (zai-api/src/signature.py)
 * 
 * 算法流程：
 * 1. UTF-8编码消息 → Base64编码
 * 2. 构建canonical string: "requestId,{id},timestamp,{ts},user_id,{uid}|{base64}|{ts}"
 * 3. 计算时间窗口: window = timestamp // (5 * 60 * 1000)
 * 4. 第一层HMAC: hmac_sha256(secret, window) → hex字符串
 * 5. 第二层HMAC: hmac_sha256(hex_as_utf8, canonical) → signature
 */
async function generateSignature(
  messageText: string,
  requestId: string,
  timestamp: number,
  userId: string
): Promise<string> {
  // 1. Base64编码消息（使用Deno标准库，与Python的base64.b64encode一致）
  const message = messageText || "";
  const messageBytes = new TextEncoder().encode(message);
  const messageBase64 = base64Encode(messageBytes);

  // 2. 构建canonical string
  const a = `requestId,${requestId},timestamp,${timestamp},user_id,${userId}`;
  const canonicalString = `${a}|${messageBase64}|${timestamp}`;

  // 3. 计算时间窗口（5分钟为一个窗口）
  const windowIndex = Math.floor(timestamp / (5 * 60 * 1000));

  // 4. 第一层HMAC：生成派生密钥
  // Python: hmac.new(root_key, str(window_index).encode("utf-8"), hashlib.sha256).hexdigest()
  const derivedHex = await hmacSha256(SIGNING_SECRET, windowIndex.toString());

  // 5. 第二层HMAC：生成最终签名
  // Python: hmac.new(derived_hex.encode("utf-8"), canonical_string.encode("utf-8"), hashlib.sha256).hexdigest()
  const signature = await hmacSha256(derivedHex, canonicalString);

  return signature;
}

function extractLatestUserContent(messages: any[]): string {
  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i];
    if (msg.role === "user") {
      const content = msg.content;
      
      // 处理字符串内容
      if (typeof content === "string") {
        return content;
      }
      
      // 处理数组内容（OpenAI格式，可能包含text和image_url）
      if (Array.isArray(content)) {
        for (const part of content) {
          if (part.type === "text" && part.text) {
            return part.text;
          }
        }
      }
      
      return "";
    }
  }
  return "";
}

async function makeUpstreamRequest(messages: any[], model: string) {
  const token = await getToken();
  const payload = decodeJwtPayload(token);
  const userId = payload.id || `guest-user-${Math.abs(token.split("").reduce((s, c) => Math.imul(31, s) + c.charCodeAt(0) | 0, 0)) % 1000000}`;
  const chatId = crypto.randomUUID();
  const timestamp = Date.now();
  const requestId = crypto.randomUUID();

  const targetModel = MODEL_MAPPING[model] || model;
  const latestUserContent = extractLatestUserContent(messages);

  // 生成签名（使用完整的签名算法）
  const signature = await generateSignature(
    latestUserContent,
    requestId,
    timestamp,
    userId
  );

  // 调试：打印签名相关信息
  console.log("[Signature Debug]");
  console.log("  User Content:", latestUserContent.substring(0, 50));
  console.log("  Request ID:", requestId);
  console.log("  Timestamp:", timestamp);
  console.log("  User ID:", userId);
  console.log("  Signature:", signature);

  // 生成时间字符串
  const now = new Date();
  const localTime = new Date(now.toLocaleString("en-US", { timeZone: "Asia/Shanghai" }));
  const localTimeStr = `${localTime.getFullYear()}-${String(localTime.getMonth() + 1).padStart(2, "0")}-${String(localTime.getDate()).padStart(2, "0")}T${String(localTime.getHours()).padStart(2, "0")}:${String(localTime.getMinutes()).padStart(2, "0")}:${String(localTime.getSeconds()).padStart(2, "0")}.${String(localTime.getMilliseconds()).padStart(3, "0")}Z`;
  const utcTime = now.toUTCString();

  // 构建完整的查询参数（模拟真实浏览器）
  const url = new URL("https://chat.z.ai/api/chat/completions");
  const queryParams: Record<string, string> = {
    timestamp: timestamp.toString(),
    requestId: requestId,
    user_id: userId,
    version: "0.0.1",
    platform: "web",
    token: token,
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    language: "zh-CN",
    languages: "zh-CN,zh",
    timezone: "Asia/Shanghai",
    cookie_enabled: "true",
    screen_width: "2048",
    screen_height: "1152",
    screen_resolution: "2048x1152",
    viewport_height: "654",
    viewport_width: "1038",
    viewport_size: "1038x654",
    color_depth: "24",
    pixel_ratio: "1.25",
    current_url: `https://chat.z.ai/c/${chatId}`,
    pathname: `/c/${chatId}`,
    search: "",
    hash: "",
    host: "chat.z.ai",
    hostname: "chat.z.ai",
    protocol: "https:",
    referrer: "",
    title: "Z.ai Chat - Free AI powered by GLM-4.6 & GLM-4.5",
    timezone_offset: "-480",
    local_time: localTimeStr,
    utc_time: utcTime,
    is_mobile: "false",
    is_touch: "false",
    max_touch_points: "10",
    browser_name: "Chrome",
    os_name: "Windows",
    signature_timestamp: timestamp.toString(),
  };

  for (const [key, value] of Object.entries(queryParams)) {
    url.searchParams.set(key, value);
  }

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`,
      "X-Fe-Version": FE_VERSION,
      "X-Signature": signature,
      "Content-Type": "application/json",
      "Accept": "*/*",
      "Accept-Encoding": "gzip, deflate, br, zstd",
      "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
      "Connection": "keep-alive",
      "Origin": "https://chat.z.ai",
      "Referer": `https://chat.z.ai/c/${chatId}`,
      "Sec-Fetch-Dest": "empty",
      "Sec-Fetch-Mode": "cors",
      "Sec-Fetch-Site": "same-origin",
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      "Cache-Control": "no-cache",
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
        preview_mode: false,
        flags: [],
        features: [],
        enable_thinking: false,
      },
      background_tasks: {
        title_generation: false,
        tags_generation: false,
      },
      mcp_servers: [],
      variables: {
        "{{USER_NAME}}": "Guest",
        "{{USER_LOCATION}}": "Unknown",
        "{{CURRENT_DATETIME}}": now.toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" }),
        "{{CURRENT_DATE}}": now.toLocaleDateString("zh-CN", { timeZone: "Asia/Shanghai" }),
        "{{CURRENT_TIME}}": now.toLocaleTimeString("zh-CN", { timeZone: "Asia/Shanghai" }),
        "{{CURRENT_WEEKDAY}}": now.toLocaleDateString("zh-CN", { timeZone: "Asia/Shanghai", weekday: "long" }),
        "{{CURRENT_TIMEZONE}}": "Asia/Shanghai",
        "{{USER_LANGUAGE}}": "zh-CN",
      },
      model_item: {
        id: targetModel,
        name: model,
        owned_by: "openai"
      },
      signature_prompt: latestUserContent, // 服务器用此字段验证签名
      chat_id: chatId,
      id: crypto.randomUUID(),
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    console.error(`[Upstream Error] ${response.status} ${response.statusText}: ${errorText}`);
    throw new Error(`Upstream API error: ${response.status} - ${errorText}`);
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
  try {
    const data = await req.json();
    const messages = data.messages || [];
    const model = data.model || "GLM-4.6";
    const stream = data.stream !== false; // 默认流式

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
  } catch (error) {
    console.error("[Chat Completions Error]", error);
    return new Response(
      JSON.stringify({
        error: {
          message: error instanceof Error ? error.message : "Internal server error",
          type: "internal_error",
        },
      }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" },
      }
    );
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
