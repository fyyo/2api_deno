#!/usr/bin/env -S deno run --allow-net --allow-env --allow-read

/**
 * ZAI Proxy API - Deno Single File Edition
 * 
 * 一个兼容 OpenAI API 格式的 ZAI (z.ai) 代理服务
 * 支持流式和非流式响应，支持图片上传
 */

// @deno-types="npm:@types/node"
// Deno 全局类型声明（用于 IDE 支持）
declare const Deno: any;

// 扩展 ImportMeta 类型以支持 Deno 的 main 属性
declare global {
  interface ImportMeta {
    main: boolean;
  }
}

// ============================================================================
// 类型定义区
// ============================================================================

interface Message {
    role: string;
    content: string | Array<{ type: string; text?: string; image_url?: { url: string } }>;
  }
  
  interface ChatRequest {
    model: string;
    messages: Message[];
    stream?: boolean;
    temperature?: number;
    top_p?: number;
    max_tokens?: number;
  }
  
  interface Model {
    id: string;
    name: string;
  }
  
  interface Settings {
    HOST: string;
    PORT: number;
    DEBUG: boolean;
    WORKERS: number;
    LOG_LEVEL: string;
    PROXY_URL: string;
    HEADERS: Record<string, string>;
    ALLOWED_MODELS: Model[];
    MODELS_MAPPING: Record<string, string>;
  }
  
  // ============================================================================
  // 配置区
  // ============================================================================
  
  function getSettings(): Settings {
    return {
      HOST: Deno.env.get("HOST") || "0.0.0.0",
      PORT: parseInt(Deno.env.get("PORT") || "8001"),
      DEBUG: (Deno.env.get("DEBUG") || "false").toLowerCase() === "true",
      WORKERS: parseInt(Deno.env.get("WORKERS") || "1"),
      LOG_LEVEL: Deno.env.get("LOG_LEVEL") || "INFO",
      PROXY_URL: Deno.env.get("PROXY_URL") || "https://chat.z.ai",
      HEADERS: {
        "Accept": "*/*",
        "Accept-Language": "zh-CN",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Content-Type": "application/json",
        "Origin": "https://chat.z.ai",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
        "X-FE-Version": "prod-fe-1.0.98",
      },
      ALLOWED_MODELS: [
        { id: "glm-4.6", name: "GLM-4.6" },
        { id: "glm-4.5V", name: "GLM-4.5V" },
        { id: "glm-4.5", name: "GLM-4.5" },
        { id: "glm-4.6-search", name: "GLM-4.6-SEARCH" },
        { id: "glm-4.6-advanced-search", name: "GLM-4.6-ADVANCED-SEARCH" },
        { id: "glm-4.6-nothinking", name: "GLM-4.6-NOTHINKING" },
      ],
      MODELS_MAPPING: {
        "glm-4.6": "GLM-4-6-API-V1",
        "glm-4.6-nothinking": "GLM-4-6-API-V1",
        "glm-4.6-search": "GLM-4-6-API-V1",
        "glm-4.6-advanced-search": "GLM-4-6-API-V1",
        "glm-4.5V": "glm-4.5v",
        "glm-4.5": "0727-360B-API",
      },
    };
  }
  
  const settings = getSettings();
  
  // ============================================================================
  // 工具函数区
  // ============================================================================
  
  /**
   * 日志记录器
   */
  class Logger {
    private name: string;
  
    constructor(name: string) {
      this.name = name;
    }
  
    info(message: string) {
      console.log(`[INFO] [${this.name}] ${message}`);
    }
  
    error(message: string, error?: Error) {
      console.error(`[ERROR] [${this.name}] ${message}`, error || "");
    }
  
    debug(message: string) {
      if (settings.DEBUG) {
        console.log(`[DEBUG] [${this.name}] ${message}`);
      }
    }
  }
  
  const logger = new Logger("ZAI-Proxy");
  
  /**
   * 生成 UUID v4
   */
  function generateUUID(): string {
    return crypto.randomUUID();
  }
  
  /**
   * 生成签名
   */
  async function generateSignature(
    t: string,
    e: string,
    r: number
  ): Promise<{ signature: string; timestamp: number }> {
    const timestampMs = r;
  
    // Base64 编码 e
    const encoder = new TextEncoder();
    const encodedE = encoder.encode(e);
    const b64EncodedE = btoa(String.fromCharCode(...encodedE));
  
    // 拼接消息字符串
    const messageString = `${t}|${b64EncodedE}|${timestampMs}`;
  
    // 计算 n
    const n = Math.floor(timestampMs / (5 * 60 * 1000));
  
    // 计算中间密钥 (HMAC-SHA256)
    const key1 = encoder.encode("key-@@@@)))()((9))-xxxx&&&%%%%%");
    const msg1 = encoder.encode(String(n));
  
    const cryptoKey1 = await crypto.subtle.importKey(
      "raw",
      key1,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const intermediateKeyBuffer = await crypto.subtle.sign("HMAC", cryptoKey1, msg1);
    const intermediateKey = Array.from(new Uint8Array(intermediateKeyBuffer))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  
    // 计算最终签名 (HMAC-SHA256)
    const key2 = encoder.encode(intermediateKey);
    const msg2 = encoder.encode(messageString);
  
    const cryptoKey2 = await crypto.subtle.importKey(
      "raw",
      key2,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const finalSignatureBuffer = await crypto.subtle.sign("HMAC", cryptoKey2, msg2);
    const finalSignature = Array.from(new Uint8Array(finalSignatureBuffer))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  
    return { signature: finalSignature, timestamp: timestampMs };
  }
  
  /**
   * Base64 解码
   */
  function base64Decode(base64: string): Uint8Array {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  }
  
  /**
   * Base64 编码
   */
  function base64Encode(data: Uint8Array): string {
    const binaryString = String.fromCharCode(...data);
    return btoa(binaryString);
  }
  
  // ============================================================================
  // 图片上传类
  // ============================================================================
  
  class ImageUploader {
    private accessToken: string;
    private uploadUrl: string;
  
    constructor(accessToken: string) {
      this.accessToken = accessToken;
      this.uploadUrl = `${settings.PROXY_URL}/api/v1/files/`;
    }
  
    private getHeaders(): Record<string, string> {
      return {
        "Accept": "application/json",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Origin": "https://chat.z.ai",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
        "authorization": `Bearer ${this.accessToken}`,
      };
    }
  
    async uploadBase64Image(base64Data: string, filename?: string): Promise<string | null> {
      try {
        if (!filename) {
          filename = `pasted_image_${Date.now()}.png`;
        }
  
        const imageData = base64Decode(base64Data);
  
        const formData = new FormData();
        const blob = new Blob([imageData.buffer as ArrayBuffer], { type: "image/png" });
        formData.append("file", blob, filename);
  
        const headers = this.getHeaders();
        delete headers["Content-Type"];
  
        const response = await fetch(this.uploadUrl, {
          method: "POST",
          headers: headers,
          body: formData,
        });
  
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
  
        const result = await response.json();
        const picId = result.id;
        const cdnUrl = result?.meta?.cdn_url;
  
        if (cdnUrl) {
          logger.info(`图片上传成功: ${filename}`);
          return picId;
        } else {
          logger.error("上传响应中未找到 CDN URL");
          return null;
        }
      } catch (error) {
        logger.error("图片上传失败", error as Error);
        return null;
      }
    }
  
    async uploadImageFromUrl(imageUrl: string): Promise<string | null> {
      try {
        const response = await fetch(imageUrl);
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
  
        const imageData = new Uint8Array(await response.arrayBuffer());
        let filename = imageUrl.split("/").pop() || "";
        if (!filename || !filename.includes(".")) {
          filename = `downloaded_image_${Date.now()}.png`;
        }
  
        const base64Data = base64Encode(imageData);
        return await this.uploadBase64Image(base64Data, filename);
      } catch (error) {
        logger.error("从 URL 上传图片失败", error as Error);
        return null;
      }
    }
  }
  
  // ============================================================================
  // 消息转换与特性处理
  // ============================================================================
  
  function convertMessages(messages: Message[]): {
    messages: Array<{ role: string; content: string }>;
    imageUrls: string[];
  } {
    const transMessages: Array<{ role: string; content: string }> = [];
    const imageUrls: string[] = [];
  
    for (const message of messages) {
      if (typeof message.content === "string") {
        transMessages.push({ role: message.role, content: message.content });
      } else if (Array.isArray(message.content)) {
        for (const part of message.content) {
          if (part.type === "text") {
            transMessages.push({ role: "user", content: part.text || "" });
          } else if (part.type === "image_url") {
            imageUrls.push(part.image_url?.url || "");
          }
        }
      }
    }
  
    return { messages: transMessages, imageUrls };
  }
  
function getFeatures(model: string, streaming: boolean): {
  features: Record<string, any>;
  mcp_servers: string[];
} {
  // 统一模型名称为小写
  const modelKey = model.toLowerCase();
  
  const features: Record<string, any> = {
    image_generation: false,
    web_search: false,
    auto_web_search: false,
    preview_mode: false,
    flags: [],
    enable_thinking: streaming,
  };

  let mcp_servers: string[] = [];

  if (modelKey === "glm-4.6-search" || modelKey === "glm-4.6-advanced-search") {
    features.web_search = true;
    features.auto_web_search = true;
    features.preview_mode = true;
  }

  if (modelKey === "glm-4.6-nothinking") {
    features.enable_thinking = false;
  }

  if (modelKey === "glm-4.6-advanced-search") {
    mcp_servers = ["advanced-search"];
  }

  return { features, mcp_servers };
}
  
  // ============================================================================
  // 聊天处理核心逻辑
  // ============================================================================
  
  async function prepareData(
    request: ChatRequest,
    accessToken: string,
    streaming = true
  ): Promise<{
    zaiData: any;
    params: Record<string, string>;
    headers: Record<string, string>;
  }> {
    const convertDict = convertMessages(request.messages);
    
    // 统一模型名称为小写
    const modelKey = request.model.toLowerCase();
    const mappedModel = settings.MODELS_MAPPING[modelKey];
    
    if (!mappedModel) {
      logger.error(`Model mapping not found for: ${request.model} (normalized: ${modelKey})`);
      throw new Error(`Model ${request.model} has no mapping configuration`);
    }
    
    logger.debug(`Model mapping: ${request.model} -> ${mappedModel}`);
    
    const zaiData: any = {
      stream: true,
      model: mappedModel,
      messages: convertDict.messages,
      chat_id: generateUUID(),
      id: generateUUID(),
    };
  
    const imageUploader = new ImageUploader(accessToken);
    const files: Array<{ type: string; id: string }> = [];
  
    for (const url of convertDict.imageUrls) {
      if (url.startsWith("data:image/")) {
        const imageBase64 = url.split("base64,")[1];
        const picId = await imageUploader.uploadBase64Image(imageBase64);
        if (picId) files.push({ type: "image", id: picId });
      } else if (url.startsWith("http")) {
        const picId = await imageUploader.uploadImageFromUrl(url);
        if (picId) files.push({ type: "image", id: picId });
      }
    }
  
    zaiData.files = files;
  
    const featuresDict = getFeatures(request.model, streaming);
    zaiData.features = featuresDict.features;
    if (featuresDict.mcp_servers.length > 0) {
      zaiData.mcp_servers = featuresDict.mcp_servers;
    }
  
    const params: Record<string, string> = {
      requestId: generateUUID(),
      timestamp: String(Date.now()),
      user_id: generateUUID(),
    };
  
    const t = `requestId,${params.requestId},timestamp,${params.timestamp},user_id,${params.user_id}`;
    const e = zaiData.messages[zaiData.messages.length - 1].content;
    const r = Date.now();
  
    const signatureData = await generateSignature(t, e, r);
    params.signature_timestamp = String(signatureData.timestamp);
  
    const headers = { ...settings.HEADERS };
    headers["Authorization"] = `Bearer ${accessToken}`;
    headers["X-Signature"] = signatureData.signature;
  
    return { zaiData, params, headers };
  }
  
  function createChatCompletionData(
    content: string,
    model: string,
    timestamp: number,
    phase: string,
    usage?: any,
    finishReason?: string | null
  ): any {
    let delta: any;
  
    if (phase === "answer") {
      delta = { content, role: "assistant" };
    } else if (phase === "thinking") {
      delta = { reasoning_content: content, role: "assistant" };
    } else if (phase === "other" || phase === "tool_call") {
      delta = { content, role: "assistant" };
    } else {
      delta = { content, role: "assistant" };
    }
  
    return {
      id: `chatcmpl-${generateUUID()}`,
      object: "chat.completion.chunk",
      created: timestamp,
      model,
      choices: [{
        index: 0,
        delta,
        finish_reason: finishReason || null,
      }],
      usage: usage || null,
    };
  }
  
async function* processStreamingResponse(
  request: ChatRequest,
  accessToken: string
): AsyncGenerator<string> {
  logger.info("Preparing streaming request data...");
  const { zaiData, params, headers } = await prepareData(request, accessToken);

  const url = new URL(`${settings.PROXY_URL}/api/chat/completions`);
  Object.entries(params).forEach(([key, value]) => url.searchParams.append(key, value));

  logger.info(`Sending streaming request to: ${url.toString()}`);
  const response = await fetch(url.toString(), {
    method: "POST",
    headers,
    body: JSON.stringify(zaiData),
  });

  if (!response.ok) {
    const errorText = await response.text();
    logger.error(`HTTP error! status: ${response.status}, body: ${errorText}`);
    throw new Error(`HTTP error! status: ${response.status}`);
  }
  
  logger.info("Streaming response started successfully");
  
    const reader = response.body?.getReader();
    if (!reader) {
      throw new Error("Response body is null");
    }
  
    const decoder = new TextDecoder();
    let buffer = "";
    const timestamp = Math.floor(Date.now() / 1000);
  
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
  
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";
  
        for (const line of lines) {
          if (!line.trim()) continue;
  
          if (line.startsWith("data:")) {
            const jsonStr = line.substring(6).trim();
            if (!jsonStr) continue;
  
            try {
              const jsonObject = JSON.parse(jsonStr);
              const phase = jsonObject.data?.phase;
  
              if (phase === "thinking") {
                let content = jsonObject.data?.delta_content || "";
                if (content.includes("</summary>\n")) {
                  content = content.split("</summary>\n").pop() || "";
                }
                yield `data: ${JSON.stringify(createChatCompletionData(content, request.model, timestamp, "thinking"))}\n\n`;
              } else if (phase === "answer") {
                let content = "";
                if (jsonObject.data?.edit_content && jsonObject.data.edit_content.includes("</summary>\n")) {
                  content = jsonObject.data.edit_content.split("</details>").pop() || "";
                } else if (jsonObject.data?.delta_content) {
                  content = jsonObject.data.delta_content;
                }
                yield `data: ${JSON.stringify(createChatCompletionData(content, request.model, timestamp, "answer"))}\n\n`;
              } else if (phase === "other") {
                const usage = jsonObject.data?.usage || {};
                const content = jsonObject.data?.delta_content || "";
                yield `data: ${JSON.stringify(createChatCompletionData(content, request.model, timestamp, "other", usage, "stop"))}\n\n`;
              } else if (phase === "done") {
                yield "data: [DONE]\n\n";
                break;
              }
            } catch (e) {
              logger.error("Failed to parse JSON", e as Error);
            }
          }
        }
      }
    } finally {
      reader.releaseLock();
    }
  }
  
async function processNonStreamingResponse(
  request: ChatRequest,
  accessToken: string
): Promise<any> {
  logger.info("Preparing non-streaming request data...");
  const { zaiData, params, headers } = await prepareData(request, accessToken, false);

  const url = new URL(`${settings.PROXY_URL}/api/chat/completions`);
  Object.entries(params).forEach(([key, value]) => url.searchParams.append(key, value));

  logger.info(`Sending non-streaming request to: ${url.toString()}`);
  const response = await fetch(url.toString(), {
    method: "POST",
    headers,
    body: JSON.stringify(zaiData),
  });

  if (!response.ok) {
    const errorText = await response.text();
    logger.error(`HTTP error! status: ${response.status}, body: ${errorText}`);
    throw new Error(`HTTP error! status: ${response.status}`);
  }
  
  logger.info("Non-streaming response received, processing...");
  
    const reader = response.body?.getReader();
    if (!reader) {
      throw new Error("Response body is null");
    }
  
    const decoder = new TextDecoder();
    let buffer = "";
    let fullResponse = "";
    let usage = {};
  
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
  
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";
  
        for (const line of lines) {
          if (!line.trim()) continue;
  
          if (line.startsWith("data:")) {
            const jsonStr = line.substring(6).trim();
            if (!jsonStr) continue;
  
            try {
              const jsonObject = JSON.parse(jsonStr);
              const phase = jsonObject.data?.phase;
  
              if (phase === "answer") {
                const content = jsonObject.data?.delta_content || "";
                fullResponse += content;
              } else if (phase === "other") {
                usage = jsonObject.data?.usage || {};
                const content = jsonObject.data?.delta_content || "";
                fullResponse += content;
              }
            } catch (e) {
              logger.error("Failed to parse JSON", e as Error);
            }
          }
        }
      }
    } finally {
      reader.releaseLock();
    }
  
    logger.info(`Non-streaming response completed, content length: ${fullResponse.length} chars`);
  
    return {
      id: `chatcmpl-${generateUUID()}`,
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model: request.model,
      choices: [{
        index: 0,
        message: { role: "assistant", content: fullResponse },
        finish_reason: "stop",
      }],
      usage,
    };
  }
  
  // ============================================================================
  // HTTP 路由处理
  // ============================================================================
  
  function corsHeaders(): Record<string, string> {
    return {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };
  }
  
  async function handleRequest(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const pathname = url.pathname;
  
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 200, headers: corsHeaders() });
    }
  
    if (pathname === "/" && req.method === "GET") {
      return new Response("ZAI Proxy Powered by snaily", {
        status: 200,
        headers: {
          ...corsHeaders(),
          "Content-Type": "text/plain",
          "X-Powered-By": "ZAI Proxy",
        },
      });
    }
  
    if (pathname === "/health" && req.method === "GET") {
      return new Response(JSON.stringify({ status: "ok" }), {
        status: 200,
        headers: {
          ...corsHeaders(),
          "Content-Type": "application/json",
        },
      });
    }
  
    if (pathname === "/v1/models" && req.method === "GET") {
      return new Response(
        JSON.stringify({ object: "list", data: settings.ALLOWED_MODELS, success: true }),
        {
          status: 200,
          headers: {
            ...corsHeaders(),
            "Content-Type": "application/json",
          },
        }
      );
    }
  
    if (pathname === "/v1/chat/completions" && req.method === "POST") {
      try {
        const authHeader = req.headers.get("Authorization");
        const accessToken = authHeader ? authHeader.split(" ").pop() : null;
  
        if (!accessToken) {
          logger.info("No Access Token provided");
          return new Response(
            JSON.stringify({ message: "Unauthorized: Access token is missing" }),
            {
              status: 401,
              headers: {
                ...corsHeaders(),
                "Content-Type": "application/json",
              },
            }
          );
        }
  
        logger.info(`Access Token: ${accessToken}`);
  
        const chatRequest: ChatRequest = await req.json();
        logger.info(`Received chat completion request for model: ${chatRequest.model}`);
  
        // 统一模型名称为小写进行验证
        const requestModelLower = chatRequest.model.toLowerCase();
        const allowedModelIds = settings.ALLOWED_MODELS.map(m => m.id.toLowerCase());
        if (!allowedModelIds.includes(requestModelLower)) {
          return new Response(
            JSON.stringify({
              message: `Model ${chatRequest.model} is not allowed. Allowed models are: ${settings.ALLOWED_MODELS.map(m => m.id).join(", ")}`,
            }),
            {
              status: 400,
              headers: {
                ...corsHeaders(),
                "Content-Type": "application/json",
              },
            }
          );
        }
  
        if (chatRequest.stream) {
          logger.info("Streaming response");
          const stream = new ReadableStream({
            async start(controller) {
              try {
                for await (const chunk of processStreamingResponse(chatRequest, accessToken)) {
                  controller.enqueue(new TextEncoder().encode(chunk));
                }
                controller.close();
              } catch (error) {
                logger.error("Stream error", error as Error);
                controller.error(error);
              }
            },
          });
  
          return new Response(stream, {
            status: 200,
            headers: {
              ...corsHeaders(),
              "Content-Type": "text/event-stream",
              "Cache-Control": "no-cache",
              "Connection": "keep-alive",
            },
          });
        } else {
          logger.info("Non-streaming response");
          const result = await processNonStreamingResponse(chatRequest, accessToken);
          return new Response(JSON.stringify(result), {
            status: 200,
            headers: {
              ...corsHeaders(),
              "Content-Type": "application/json",
            },
          });
        }
      } catch (error) {
        logger.error("Error processing chat completion", error as Error);
        return new Response(
          JSON.stringify({
            message: "An internal server error occurred.",
            detail: settings.DEBUG ? (error as Error).message : undefined,
          }),
          {
            status: 500,
            headers: {
              ...corsHeaders(),
              "Content-Type": "application/json",
            },
          }
        );
      }
    }
  
    return new Response("Not Found", {
      status: 404,
      headers: corsHeaders(),
    });
  }
  
  // ============================================================================
  // 服务器启动
  // ============================================================================
  
  async function main() {
    logger.info(`🚀 ZAI Proxy API starting...`);
    logger.info(`📍 Host: ${settings.HOST}`);
    logger.info(`🔌 Port: ${settings.PORT}`);
    logger.info(`🐛 Debug: ${settings.DEBUG}`);
    logger.info(`🌐 Proxy URL: ${settings.PROXY_URL}`);
  
    await Deno.serve({
      hostname: settings.HOST,
      port: settings.PORT,
      onListen: ({ hostname, port }) => {
        logger.info(`✨ Server is listening on http://${hostname}:${port}`);
      },
    }, handleRequest).finished;
  }
  
  if (import.meta.main) {
    main();
  }
