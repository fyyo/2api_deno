import { serve } from "https://deno.land/std@0.208.0/http/server.ts";
import { encode as base64Encode } from "https://deno.land/std@0.208.0/encoding/base64.ts";

// ========== 配置 ==========
const CONFIG = {
  FE_VERSION: Deno.env.get("ZAI_FE_VERSION") || "prod-fe-1.0.103",
  SIGNING_SECRET: Deno.env.get("ZAI_SIGNING_SECRET") || "junjie",
  AUTH_ENDPOINT: Deno.env.get("ZAI_AUTH_ENDPOINT") || "https://chat.z.ai/api/v1/auths/",
  API_ENDPOINT: Deno.env.get("API_ENDPOINT") || "https://chat.z.ai/api/chat/completions",
  LOG_LEVEL: (Deno.env.get("LOG_LEVEL") || "debug").toLowerCase() as "false" | "info" | "debug",  // 临时改为debug
  MAX_RETRIES: parseInt(Deno.env.get("MAX_RETRIES") || "3"),
  ENABLE_GUEST_TOKEN: (Deno.env.get("ENABLE_GUEST_TOKEN") || "true").toLowerCase() === "true",
};

// ========== 模型映射 ==========
const MODEL_MAPPING: Record<string, string> = {
  "GLM-4.5": "0727-360B-API",
  "GLM-4.5-Thinking": "0727-360B-API",
  "GLM-4.5-Search": "0727-360B-API",
  "GLM-4.5-Air": "0727-106B-API",
  "GLM-4.5V": "glm-4.5v",
  "GLM-4.6": "GLM-4-6-API-V1",
  "GLM-4.6-Thinking": "GLM-4-6-API-V1",
  "GLM-4.6-Search": "GLM-4-6-API-V1",
  "GLM-4.6-advanced-search": "GLM-4-6-API-V1",
};

// ========== 日志系统 ==========
function infoLog(message: string, ...args: unknown[]) {
  if (CONFIG.LOG_LEVEL === "false") return;
  console.log(`[INFO] ${message}`, ...args);
}

function debugLog(message: string, ...args: unknown[]) {
  if (CONFIG.LOG_LEVEL !== "debug") return;
  console.log(`[DEBUG] ${message}`, ...args);
}

function errorLog(message: string, ...args: unknown[]) {
  console.error(`[ERROR] ${message}`, ...args);
}

// ========== Token 管理 ==========
async function getToken(): Promise<string> {
  if (!CONFIG.ENABLE_GUEST_TOKEN) {
    throw new Error("匿名Token功能已禁用，请配置ZAI_TOKEN环境变量");
  }

  const maxRetries = 3;
  let lastError: Error | null = null;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      debugLog(`获取匿名Token (尝试 ${attempt}/${maxRetries})`);
      
      const response = await fetch(CONFIG.AUTH_ENDPOINT, {
        method: "GET",
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
          "Accept": "application/json",
          "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
          "Origin": "https://chat.z.ai",
          "Referer": "https://chat.z.ai/",
        },
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      const token = data.token;
      
      if (!token) {
        throw new Error("响应中缺少token字段");
      }

      infoLog(`成功获取匿名Token: ${token.substring(0, 20)}...`);
      return token;
    } catch (error) {
      lastError = error as Error;
      errorLog(`获取匿名Token失败 (尝试 ${attempt}/${maxRetries}):`, error);
      
      if (attempt < maxRetries) {
        const delay = Math.min(1000 * Math.pow(2, attempt - 1), 5000);
        debugLog(`等待 ${delay}ms 后重试...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }

  throw lastError || new Error("获取匿名Token失败");
}

// ========== JWT 和签名 ==========
function decodeJwtPayload(token: string): any {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) {
      errorLog("Invalid JWT format");
      return {};
    }
    
    let payload = parts[1];
    const padding = 4 - (payload.length % 4);
    if (padding !== 4) payload += "=".repeat(padding);
    
    const decoded = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
    return JSON.parse(decoded);
  } catch (error) {
    errorLog("Failed to decode JWT:", error);
    return {};
  }
}

function extractUserId(token: string): string {
  const payload = decodeJwtPayload(token);
  
  // 尝试多个可能的user_id字段
  for (const key of ["id", "user_id", "uid", "sub"]) {
    const val = payload[key];
    if (val && (typeof val === "string" || typeof val === "number")) {
      return String(val);
    }
  }
  
  // 降级方案：使用token哈希生成guest ID
  const hashCode = token.split("").reduce((s, c) => Math.imul(31, s) + c.charCodeAt(0) | 0, 0);
  return `guest-user-${Math.abs(hashCode) % 1000000}`;
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
 * 完全对照Python版本的实现
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
  // 1. Base64编码消息（使用Deno标准库，与Python保持一致）
  const message = messageText || "";
  const messageBytes = new TextEncoder().encode(message);
  const messageBase64 = base64Encode(messageBytes);

  debugLog("[签名] 步骤1 - Base64编码:");
  debugLog(`  原始消息: ${message.substring(0, 50)}${message.length > 50 ? "..." : ""}`);
  debugLog(`  消息字节数: ${messageBytes.length}`);
  debugLog(`  Base64: ${messageBase64.substring(0, 50)}${messageBase64.length > 50 ? "..." : ""}`);

  // 2. 构建canonical string
  const a = `requestId,${requestId},timestamp,${timestamp},user_id,${userId}`;
  const canonicalString = `${a}|${messageBase64}|${timestamp}`;

  debugLog("[签名] 步骤2 - Canonical String:");
  debugLog(`  前缀: ${a}`);
  debugLog(`  完整: ${canonicalString.substring(0, 100)}...`);

  // 3. 计算时间窗口（5分钟为一个窗口）
  const windowIndex = Math.floor(timestamp / (5 * 60 * 1000));

  debugLog("[签名] 步骤3 - 时间窗口:");
  debugLog(`  时间戳: ${timestamp}`);
  debugLog(`  窗口索引: ${windowIndex}`);

  // 4. 第一层HMAC：生成派生密钥
  const derivedHex = await hmacSha256(CONFIG.SIGNING_SECRET, windowIndex.toString());

  debugLog("[签名] 步骤4 - 第一层HMAC:");
  debugLog(`  密钥: ${CONFIG.SIGNING_SECRET}`);
  debugLog(`  数据: ${windowIndex.toString()}`);
  debugLog(`  派生密钥: ${derivedHex.substring(0, 20)}...`);

  // 5. 第二层HMAC：生成最终签名
  const signature = await hmacSha256(derivedHex, canonicalString);

  debugLog("[签名] 步骤5 - 第二层HMAC:");
  debugLog(`  使用派生密钥签名canonical string`);
  debugLog(`  最终签名: ${signature}`);

  return signature;
}

// ========== 辅助函数 ==========
function generateUUID(): string {
  return crypto.randomUUID();
}

function generateTimeVariables(): Record<string, string> {
  const now = new Date();
  const options: Intl.DateTimeFormatOptions = { 
    timeZone: "Asia/Shanghai",
    weekday: "long" 
  };
  
  return {
    "{{CURRENT_DATETIME}}": now.toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" }),
    "{{CURRENT_DATE}}": now.toLocaleDateString("zh-CN", { timeZone: "Asia/Shanghai" }),
    "{{CURRENT_TIME}}": now.toLocaleTimeString("zh-CN", { timeZone: "Asia/Shanghai" }),
    "{{CURRENT_WEEKDAY}}": now.toLocaleDateString("zh-CN", options),
    "{{CURRENT_TIMEZONE}}": "Asia/Shanghai",
    "{{USER_LANGUAGE}}": "zh-CN",
  };
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
      
      // 处理数组内容（可能包含text和image_url）
      if (Array.isArray(content)) {
        for (const part of content) {
          if (part.type === "text" && part.text) {
            return part.text;
          }
        }
      }
    }
  }
  return "";
}

function detectModelFeatures(model: string): {
  isThinking: boolean;
  isSearch: boolean;
  isAdvancedSearch: boolean;
  isVision: boolean;
} {
  return {
    isThinking: model.includes("Thinking"),
    isSearch: model.includes("Search") && !model.includes("advanced"),
    isAdvancedSearch: model.includes("advanced-search"),
    isVision: model.includes("4.5V"),
  };
}

// ========== 上游请求构造 ==========
async function makeUpstreamRequest(messages: any[], model: string) {
  const token = await getToken();
  const userId = extractUserId(token);
  const chatId = generateUUID();
  const timestamp = Date.now();
  const requestId = generateUUID();

  const targetModel = MODEL_MAPPING[model] || "0727-360B-API";
  const latestUserContent = extractLatestUserContent(messages);
  const features = detectModelFeatures(model);

  debugLog(`开始构造上游请求: ${model} -> ${targetModel}`);
  debugLog(`模型特性:`, features);
  debugLog(`用户内容: ${latestUserContent.substring(0, 100)}${latestUserContent.length > 100 ? "..." : ""}`);
  debugLog(`请求ID: ${requestId}`);
  debugLog(`时间戳: ${timestamp}`);
  debugLog(`用户ID: ${userId}`);

  // 生成签名
  const signature = await generateSignature(
    latestUserContent,
    requestId,
    timestamp,
    userId
  );
  
  infoLog(`✅ 签名生成成功: ${signature.substring(0, 16)}...${signature.substring(signature.length - 8)}`);

  // 构建MCP服务器列表
  const mcpServers: string[] = [];
  if (features.isAdvancedSearch) {
    mcpServers.push("advanced-search");
  } else if (features.isSearch) {
    mcpServers.push("deep-web-search");
  }

  // 构建隐藏的MCP特性列表（模拟真实浏览器请求）
  const hiddenMcpFeatures = [
    { type: "mcp", server: "vibe-coding", status: "hidden" },
    { type: "mcp", server: "ppt-maker", status: "hidden" },
    { type: "mcp", server: "image-search", status: "hidden" },
    { type: "mcp", server: "deep-research", status: "hidden" },
  ];

  // 构建请求体
  const requestBody = {
    stream: true,
    model: targetModel,
    messages,
    params: {},
    features: {
      image_generation: false,
      web_search: features.isSearch || features.isAdvancedSearch,
      auto_web_search: features.isSearch || features.isAdvancedSearch,
      preview_mode: features.isSearch || features.isAdvancedSearch,
      flags: [],
      features: hiddenMcpFeatures,
      enable_thinking: features.isThinking || features.isSearch || features.isAdvancedSearch,
    },
    background_tasks: {
      title_generation: false,
      tags_generation: false,
    },
    mcp_servers: mcpServers,
    variables: {
      "{{USER_NAME}}": "Guest",
      "{{USER_LOCATION}}": "Unknown",
      ...generateTimeVariables(),
    },
    model_item: {
      id: targetModel,
      name: model,
      owned_by: "openai",
    },
    signature_prompt: latestUserContent,
    chat_id: chatId,
    id: generateUUID(),
  };

  // 构建URL和查询参数
  const url = new URL(CONFIG.API_ENDPOINT);
  
  const queryParams: Record<string, string> = {
    timestamp: timestamp.toString(),
    requestId: requestId,
    user_id: userId,
    version: "0.0.1",
    platform: "web",
    token: token,
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
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
    local_time: new Date().toISOString(),
    utc_time: new Date().toUTCString(),
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

  // 发送请求
  const response = await fetch(url.toString(), {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`,
      "X-FE-Version": CONFIG.FE_VERSION,
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
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "Cache-Control": "no-cache",
    },
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    errorLog(`上游返回错误: ${response.status} ${response.statusText}`);
    const errorText = await response.text().catch(() => "无法读取错误详情");
    errorLog(`错误详情: ${errorText.substring(0, 200)}`);
  } else {
    infoLog(`上游响应成功: ${response.status}`);
  }

  return { response, model: targetModel, chatId };
}

// ========== API 端点处理 ==========
async function handleModels(): Promise<Response> {
  const currentTime = Math.floor(Date.now() / 1000);
  
  const models = [
    { id: "GLM-4.5", object: "model", created: currentTime, owned_by: "z.ai" },
    { id: "GLM-4.5-Thinking", object: "model", created: currentTime, owned_by: "z.ai" },
    { id: "GLM-4.5-Search", object: "model", created: currentTime, owned_by: "z.ai" },
    { id: "GLM-4.5-Air", object: "model", created: currentTime, owned_by: "z.ai" },
    { id: "GLM-4.5V", object: "model", created: currentTime, owned_by: "z.ai" },
    { id: "GLM-4.6", object: "model", created: currentTime, owned_by: "z.ai" },
    { id: "GLM-4.6-Thinking", object: "model", created: currentTime, owned_by: "z.ai" },
    { id: "GLM-4.6-Search", object: "model", created: currentTime, owned_by: "z.ai" },
    { id: "GLM-4.6-advanced-search", object: "model", created: currentTime, owned_by: "z.ai" },
  ];

  infoLog(`返回模型列表: ${models.length} 个模型`);
  
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

    infoLog(`收到聊天请求: 模型=${model}, 流式=${stream}, 消息数=${messages.length}`);

    // 重试逻辑
    let lastError: Error | null = null;
    for (let attempt = 1; attempt <= CONFIG.MAX_RETRIES; attempt++) {
      try {
        const { response, model: modelName, chatId } = await makeUpstreamRequest(messages, model);

        if (!response.ok) {
          throw new Error(`上游返回错误: ${response.status} ${response.statusText}`);
        }

        // 返回流式或非流式响应
        if (stream) {
          return handleStreamResponse(response, modelName, chatId);
        } else {
          return await handleNonStreamResponse(response, modelName, chatId);
        }
      } catch (error) {
        lastError = error as Error;
        errorLog(`请求失败 (尝试 ${attempt}/${CONFIG.MAX_RETRIES}):`, error);

        if (attempt < CONFIG.MAX_RETRIES) {
          const delay = Math.min(1500 * attempt, 8000);
          debugLog(`等待 ${delay}ms 后重试...`);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }

    // 所有重试都失败
    throw lastError || new Error("请求失败");
  } catch (error) {
    errorLog("处理聊天请求时发生错误:", error);
    return new Response(
      JSON.stringify({
        error: {
          message: error instanceof Error ? error.message : "内部服务器错误",
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

function handleStreamResponse(response: Response, modelName: string, chatId: string): Response {
  const reader = response.body?.getReader();
  if (!reader) {
    throw new Error("无法读取响应流");
  }

  const encoder = new TextEncoder();
  const completionId = `chatcmpl-${generateUUID().slice(0, 29)}`;

  const readable = new ReadableStream({
    async start(controller) {
      let buffer = "";
      let hasContent = false;

      try {
        while (true) {
          const { done, value } = await reader.read();
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
            } catch (err) {
              debugLog("解析SSE数据失败:", err);
            }
          }
        }

        if (!hasContent) {
          errorLog("流式响应未接收到内容");
        }

        // 发送结束chunk
        const finalChunk = {
          id: completionId,
          object: "chat.completion.chunk",
          created: Math.floor(Date.now() / 1000),
          model: modelName,
          choices: [{ index: 0, delta: {}, finish_reason: "stop" }]
        };
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(finalChunk)}\n\n`));
        controller.enqueue(encoder.encode("data: [DONE]\n\n"));
        
        infoLog("流式响应完成");
      } catch (error) {
        errorLog("流式响应处理错误:", error);
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
}

async function handleNonStreamResponse(
  response: Response,
  modelName: string,
  chatId: string
): Promise<Response> {
  const reader = response.body?.getReader();
  if (!reader) {
    throw new Error("无法读取响应流");
  }

  const chunks: string[] = [];
  let buffer = "";

  try {
    while (true) {
      const { done, value } = await reader.read();
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
        } catch (err) {
          debugLog("解析SSE数据失败:", err);
        }
      }
    }

    const fullContent = chunks.join("");
    
    if (!fullContent) {
      errorLog("非流式响应未接收到内容");
    }

    infoLog(`非流式响应完成: ${fullContent.length} 字符`);

    return new Response(
      JSON.stringify({
        id: `chatcmpl-${generateUUID().slice(0, 29)}`,
        object: "chat.completion",
        created: Math.floor(Date.now() / 1000),
        model: modelName,
        choices: [{
          index: 0,
          message: { role: "assistant", content: fullContent },
          finish_reason: "stop"
        }],
        usage: {
          prompt_tokens: 0,
          completion_tokens: 0,
          total_tokens: 0
        }
      }),
      { headers: { "Content-Type": "application/json" } }
    );
  } catch (error) {
    errorLog("非流式响应处理错误:", error);
    throw error;
  }
}

// ========== 主处理函数 ==========
async function handler(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const { pathname, method } = { pathname: url.pathname, method: req.method };

  debugLog(`收到请求: ${method} ${pathname}`);

  try {
    // 健康检查端点
    if (pathname === "/health" && method === "GET") {
      return new Response(
        JSON.stringify({ status: "healthy", version: CONFIG.FE_VERSION }),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    // 根路径
    if (pathname === "/" && method === "GET") {
      return new Response(
        JSON.stringify({
          message: "Z.AI OpenAI-Compatible API Server",
          version: CONFIG.FE_VERSION,
          description: "完全兼容OpenAI API的Z.AI代理服务",
          endpoints: {
            models: "GET /v1/models",
            chat: "POST /v1/chat/completions",
            health: "GET /health",
          },
        }),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    // 模型列表
    if (pathname === "/v1/models" && method === "GET") {
      return await handleModels();
    }

    // 聊天完成
    if (pathname === "/v1/chat/completions" && method === "POST") {
      return await handleChatCompletions(req);
    }

    // 404 Not Found
    infoLog(`未找到路由: ${method} ${pathname}`);
    return new Response(
      JSON.stringify({ error: { message: "Not Found", type: "not_found" } }),
      { status: 404, headers: { "Content-Type": "application/json" } }
    );
  } catch (error) {
    errorLog("处理请求时发生未捕获错误:", error);
    return new Response(
      JSON.stringify({
        error: {
          message: error instanceof Error ? error.message : "内部服务器错误",
          type: "internal_error",
        },
      }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }
}

// ========== 导出 ==========
// 启动时的配置信息（仅在首次请求时输出，避免重复）
let isFirstRequest = true;

function logStartupInfo() {
  if (isFirstRequest) {
    isFirstRequest = false;
    infoLog("=".repeat(60));
    infoLog("🚀 Z.AI OpenAI-Compatible API Server");
    infoLog(`📌 前端版本: ${CONFIG.FE_VERSION}`);
    infoLog(`📊 日志级别: ${CONFIG.LOG_LEVEL}`);
    infoLog(`🔄 最大重试: ${CONFIG.MAX_RETRIES}`);
    infoLog(`🎫 匿名Token: ${CONFIG.ENABLE_GUEST_TOKEN ? "✅ 启用" : "❌ 禁用"}`);
    infoLog(`🌐 API地址: ${CONFIG.API_ENDPOINT}`);
    infoLog("=".repeat(60));
  }
}

async function wrappedHandler(req: Request): Promise<Response> {
  logStartupInfo();
  return await handler(req);
}

export default { fetch: wrappedHandler };
