#!/usr/bin/env -S deno run --allow-net --allow-env

/**
 * WiseCleaner 2 OpenAI API - Deno Version
 * 将 WiseCleaner WebSocket API 封装为 OpenAI 标准接口
 * 
 * 运行: deno run --allow-net --allow-env main.ts
 */

// ============= 类型定义 =============
interface Message {
  role: string;
  content: string;
}

interface ChatCompletionRequest {
  model: string;
  messages: Message[];
  stream?: boolean;
  temperature?: number;
  max_tokens?: number;
  top_p?: number;
}

interface ModelInfo {
  id: string;
  name: string;
}

interface WebSocketMessage {
  token?: string;
  id?: number;
  type?: string;
  message?: string;
  web?: boolean;
  model?: string;
  context?: number;
  ignore_context?: boolean;
  max_tokens?: number;
  temperature?: number;
  top_p?: number;
  top_k?: number;
  presence_penalty?: number;
  frequency_penalty?: number;
  repetition_penalty?: number;
  end?: boolean;
}

// ============= 配置 =============
const WEBSOCKET_URL = "wss://api.euask.com:8094/chat";

const AVAILABLE_MODELS: ModelInfo[] = [
  { id: "o4-mini", name: "GPT-4o mini" },
  { id: "gpt-5-nano", name: "GPT-5 Nano" },
  { id: "gpt-5-mini", name: "GPT-5 Mini" },
  { id: "gpt-5", name: "GPT-5" },
  { id: "doubao-seed-1.6-250615", name: "Doubao seed" },
  { id: "gpt-image-1", name: "Text to Image (GPT4)" },
  { id: "o3", name: "GPT-o3 (Reasoning model)" },
  { id: "qwen-turbo-latest", name: "Qwen - Trubo" },
  { id: "qwen-plus-latest", name: "Qwen - Plus" },
  { id: "qwen-max-latest", name: "Qwen - Max" },
  { id: "google/gemini-2.5-pro-preview-03-25", name: "Gemini-2.5 Pro" },
  { id: "GLM-4-Flash", name: "GLM-4 Flash" },
  { id: "GLM-Z1-Flash", name: "GLM-Z1 Flash" },
  { id: "GLM-Z1-Air", name: "GLM-Z1 Air" },
  { id: "deepseek-reasoner", name: "Deepseek-R1" },
  { id: "deepseek-chat", name: "Deepseek Chat" },
];

const MODEL_IDS = AVAILABLE_MODELS.map((m) => m.id);

// ============= WebSocket 连接池 =============
const activeConnections = new Map<string, WebSocket>();

// ============= 工具函数 =============

/**
 * 获取或创建 WebSocket 连接
 */
async function getOrCreateWebSocket(
  token: string,
  isNewConversation: boolean
): Promise<WebSocket> {
  // 如果是新对话,关闭旧连接
  if (isNewConversation && activeConnections.has(token)) {
    const oldWs = activeConnections.get(token)!;
    try {
      oldWs.close();
    } catch {
      // 忽略关闭错误
    }
    activeConnections.delete(token);
  }

  // 如果已有连接,检查是否还活着
  if (activeConnections.has(token)) {
    const ws = activeConnections.get(token)!;
    if (ws.readyState === WebSocket.OPEN) {
      return ws;
    } else {
      activeConnections.delete(token);
    }
  }

  // 创建新连接
  const ws = new WebSocket(WEBSOCKET_URL, {
    headers: {
      "Origin": "https://aicg.wisecleaner.com",
      "User-Agent":
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
      "Cache-Control": "no-cache",
      "Pragma": "no-cache",
    },
  });

  // 等待连接打开
  await new Promise<void>((resolve, reject) => {
    ws.onopen = () => resolve();
    ws.onerror = (e) => reject(new Error("WebSocket connection failed"));
    // 超时处理
    setTimeout(() => reject(new Error("WebSocket connection timeout")), 10000);
  });

  // 发送认证消息
  const authMessage = { token, id: -1 };
  ws.send(JSON.stringify(authMessage));

  // 保存连接
  activeConnections.set(token, ws);

  return ws;
}

/**
 * 与 WiseCleaner WebSocket API 通信
 */
async function* chatWithWiseCleaner(
  token: string,
  model: string,
  messages: Message[],
  isNewConversation: boolean,
  stream: boolean
): AsyncGenerator<string, void, unknown> {
  // 提取最后一条用户消息
  let userMessage = "";
  for (let i = messages.length - 1; i >= 0; i--) {
    if (messages[i].role === "user") {
      userMessage = messages[i].content;
      break;
    }
  }

  if (!userMessage) {
    throw new Error("没有找到用户消息");
  }

  // 构造聊天消息
  const chatMessage: WebSocketMessage = {
    type: "chat",
    message: userMessage,
    web: false,
    model: model,
    context: 8,
    ignore_context: false,
    max_tokens: 4096,
    temperature: 0.6,
    top_p: 1,
    top_k: 5,
    presence_penalty: 0,
    frequency_penalty: 0,
    repetition_penalty: 1,
  };

  // 获取或创建 WebSocket 连接
  const websocket = await getOrCreateWebSocket(token, isNewConversation);

  // 发送聊天消息
  websocket.send(JSON.stringify(chatMessage));

  let fullResponse = "";

  // 接收响应
  const messageQueue: string[] = [];
  let resolveMessage: ((value: string) => void) | null = null;
  let isComplete = false;

  websocket.onmessage = (event: MessageEvent) => {
    if (resolveMessage) {
      resolveMessage(event.data);
      resolveMessage = null;
    } else {
      messageQueue.push(event.data);
    }
  };

  websocket.onerror = () => {
    isComplete = true;
    if (activeConnections.get(token) === websocket) {
      activeConnections.delete(token);
    }
  };

  try {
    while (!isComplete) {
      let message: string;

      if (messageQueue.length > 0) {
        message = messageQueue.shift()!;
      } else {
        message = await new Promise<string>((resolve) => {
          resolveMessage = resolve;
          // 超时处理
          setTimeout(() => {
            if (resolveMessage === resolve) {
              resolveMessage = null;
              isComplete = true;
              resolve("");
            }
          }, 60000); // 60秒超时
        });

        if (!message) break;
      }

      try {
        const data: WebSocketMessage = JSON.parse(message);

        // 提取消息内容
        const content = data.message || "";
        const endFlag = data.end || false;

        // 如果有内容,累积并输出
        if (content) {
          fullResponse += content;
          if (stream) {
            yield content;
          }
        }

        // 检查是否结束
        if (endFlag) {
          isComplete = true;
          break;
        }
      } catch {
        // JSON解析失败,可能是纯文本消息
        if (message.trim()) {
          fullResponse += message;
          if (stream) {
            yield message;
          }
        }
      }
    }
  } catch (error) {
    console.error("接收循环错误:", error);
    // 如果出错,清理连接
    if (activeConnections.get(token) === websocket) {
      activeConnections.delete(token);
    }
    throw error;
  }

  // 非流式返回完整响应
  if (!stream) {
    yield fullResponse;
  }
}

/**
 * 生成唯一ID
 */
function generateChatId(): string {
  return `chatcmpl-${crypto.randomUUID().slice(0, 8)}`;
}

/**
 * 获取当前时间戳
 */
function getCurrentTimestamp(): number {
  return Math.floor(Date.now() / 1000);
}

// ============= HTML 页面 =============
const HTML_CONTENT = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiseCleaner 2 OpenAI API</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .card {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            padding: 48px;
            max-width: 560px;
            width: 100%;
        }
        .status {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            margin-bottom: 32px;
        }
        .status-dot {
            width: 12px;
            height: 12px;
            background: #10b981;
            border-radius: 50%;
            animation: pulse 2s ease-in-out infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .status-text {
            font-size: 24px;
            font-weight: 600;
            color: #1f2937;
        }
        .subtitle {
            text-align: center;
            color: #6b7280;
            font-size: 16px;
            margin-bottom: 48px;
            line-height: 1.6;
        }
        .section-title {
            font-size: 14px;
            font-weight: 600;
            color: #6b7280;
            margin-bottom: 16px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .endpoint-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .endpoint-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px;
            background: #f9fafb;
            border-radius: 8px;
            transition: all 0.2s;
        }
        .endpoint-item:hover {
            background: #f3f4f6;
            transform: translateX(4px);
        }
        .endpoint-label {
            color: #374151;
            font-weight: 500;
        }
        .endpoint-path {
            color: #6b7280;
            font-family: "Monaco", "Courier New", monospace;
            font-size: 14px;
        }
        .footer {
            text-align: center;
            margin-top: 48px;
            color: #9ca3af;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="status">
            <span class="status-dot"></span>
            <span class="status-text">服务运行正常</span>
        </div>
        
        <div class="subtitle">
            欲买桂花同载酒,终不似,少年游
        </div>
        
        <div class="section-title">API 端点</div>
        <div class="endpoint-list">
            <div class="endpoint-item">
                <span class="endpoint-label">模型列表</span>
                <span class="endpoint-path">/v1/models</span>
            </div>
            <div class="endpoint-item">
                <span class="endpoint-label">聊天完成</span>
                <span class="endpoint-path">/v1/chat/completions</span>
            </div>
        </div>
        
        <div class="footer">
            WiseCleaner OpenAI Proxy v1.0.0 (Deno)
        </div>
    </div>
</body>
</html>`;

// ============= API 路由处理 =============

/**
 * 处理根路径
 */
function handleRoot(): Response {
  return new Response(HTML_CONTENT, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

/**
 * 处理模型列表
 */
function handleModels(): Response {
  const timestamp = getCurrentTimestamp();
  const data = {
    object: "list",
    data: AVAILABLE_MODELS.map((model) => ({
      id: model.id,
      object: "model",
      created: timestamp,
      owned_by: "wisecleaner",
      permission: [],
      root: model.id,
      parent: null,
    })),
  };

  return new Response(JSON.stringify(data), {
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

/**
 * 处理聊天补全
 */
async function handleChatCompletions(request: Request): Promise<Response> {
  try {
    // 提取 token
    const authorization = request.headers.get("authorization");
    if (!authorization) {
      return new Response(
        JSON.stringify({ error: "缺少 Authorization header" }),
        {
          status: 401,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        }
      );
    }

    const token = authorization.replace("Bearer ", "").trim();
    if (!token) {
      return new Response(JSON.stringify({ error: "无效的 token" }), {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        },
      });
    }

    // 解析请求体
    const body: ChatCompletionRequest = await request.json();

    // 验证模型
    if (!MODEL_IDS.includes(body.model)) {
      return new Response(
        JSON.stringify({
          error: `不支持的模型: ${body.model},可用模型: ${MODEL_IDS.join(", ")}`,
        }),
        {
          status: 400,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        }
      );
    }

    // 验证消息
    if (!body.messages || body.messages.length === 0) {
      return new Response(
        JSON.stringify({ error: "messages 不能为空" }),
        {
          status: 400,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        }
      );
    }

    // 统计 user 消息数量
    const userMessageCount = body.messages.filter((msg) => msg.role === "user")
      .length;

    // 生成唯一ID
    const chatId = generateChatId();
    const created = getCurrentTimestamp();

    // 判断是否是新对话:只有1条 user 消息 = 新对话
    const isNewConversation = userMessageCount === 1;

    // 流式响应
    if (body.stream) {
      const stream = new ReadableStream({
        async start(controller) {
          const encoder = new TextEncoder();

          try {
            for await (
              const content of chatWithWiseCleaner(
                token,
                body.model,
                body.messages,
                isNewConversation,
                true
              )
            ) {
              const chunk = {
                id: chatId,
                object: "chat.completion.chunk",
                created: created,
                model: body.model,
                choices: [
                  {
                    index: 0,
                    delta: { content: content },
                    finish_reason: null,
                  },
                ],
              };
              controller.enqueue(
                encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`)
              );
            }

            // 发送结束标记
            const finalChunk = {
              id: chatId,
              object: "chat.completion.chunk",
              created: created,
              model: body.model,
              choices: [
                {
                  index: 0,
                  delta: {},
                  finish_reason: "stop",
                },
              ],
            };
            controller.enqueue(
              encoder.encode(`data: ${JSON.stringify(finalChunk)}\n\n`)
            );
            controller.enqueue(encoder.encode("data: [DONE]\n\n"));
            controller.close();
          } catch (error) {
            console.error("流式响应错误:", error);
            const errorChunk = {
              error: {
                message: String(error),
                type: "server_error",
                code: 500,
              },
            };
            controller.enqueue(
              encoder.encode(`data: ${JSON.stringify(errorChunk)}\n\n`)
            );
            controller.close();
          }
        },
      });

      return new Response(stream, {
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          "Connection": "keep-alive",
          "Access-Control-Allow-Origin": "*",
        },
      });
    }

    // 非流式响应
    let fullResponse = "";
    for await (
      const content of chatWithWiseCleaner(
        token,
        body.model,
        body.messages,
        isNewConversation,
        false
      )
    ) {
      fullResponse = content;
    }

    const response = {
      id: chatId,
      object: "chat.completion",
      created: created,
      model: body.model,
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content: fullResponse,
          },
          finish_reason: "stop",
        },
      ],
      usage: {
        prompt_tokens: 0,
        completion_tokens: 0,
        total_tokens: 0,
      },
    };

    return new Response(JSON.stringify(response), {
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
      },
    });
  } catch (error) {
    console.error("处理聊天请求错误:", error);
    return new Response(
      JSON.stringify({
        error: {
          message: String(error),
          type: "server_error",
          code: 500,
        },
      }),
      {
        status: 500,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        },
      }
    );
  }
}

/**
 * 处理 OPTIONS 预检请求
 */
function handleOptions(): Response {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "86400",
    },
  });
}

// ============= 主服务器 =============

/**
 * 主请求处理器
 */
async function handler(request: Request): Promise<Response> {
  const url = new URL(request.url);

  // 处理 OPTIONS 预检请求
  if (request.method === "OPTIONS") {
    return handleOptions();
  }

  // 路由分发
  if (url.pathname === "/" && request.method === "GET") {
    return handleRoot();
  } else if (url.pathname === "/v1/models" && request.method === "GET") {
    return handleModels();
  } else if (
    url.pathname === "/v1/chat/completions" && request.method === "POST"
  ) {
    return await handleChatCompletions(request);
  } else {
    return new Response(JSON.stringify({ error: "Not Found" }), {
      status: 404,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
      },
    });
  }
}

// ============= 启动服务 =============

/**
 * 清理所有连接
 */
function cleanup() {
  console.log("👋 关闭所有 WebSocket 连接...");
  for (const [token, ws] of activeConnections.entries()) {
    try {
      ws.close();
    } catch {
      // 忽略关闭错误
    }
  }
  activeConnections.clear();
  console.log("👋 WiseCleaner 2 OpenAI API 关闭");
}

// 注册退出处理
globalThis.addEventListener("unload", cleanup);

// 启动服务器
const PORT = parseInt(Deno.env.get("PORT") || "8000");

console.log("=".repeat(60));
console.log("🚀 WiseCleaner 2 OpenAI API (Deno版)");
console.log("=".repeat(60));
console.log(`📡 服务地址: http://0.0.0.0:${PORT}`);
console.log(`🔑 使用方法: Authorization: Bearer <your_token>`);
console.log("=".repeat(60));

Deno.serve({ port: PORT, hostname: "0.0.0.0" }, handler);
