declare namespace Deno {
  interface Conn {
    readonly rid: number;
    localAddr: Addr;
    remoteAddr: Addr;
    read(p: Uint8Array): Promise<number | null>;
    write(p: Uint8Array): Promise<number>;
    close(): void;
  }

  interface Addr {
    hostname: string;
    port: number;
    transport: string;
  }

  interface Listener extends AsyncIterable<Conn> {
    readonly addr: Addr;
    accept(): Promise<Conn>;
    close(): void;
    [Symbol.asyncIterator](): AsyncIterableIterator<Conn>;
  }

  interface HttpConn {
    nextRequest(): Promise<RequestEvent | null>;
    [Symbol.asyncIterator](): AsyncIterableIterator<RequestEvent>;
  }

  interface RequestEvent {
    request: Request;
    respondWith(r: Response | Promise<Response>): Promise<void>;
  }

  function listen(options: { port: number }): Listener;
  function serveHttp(conn: Conn): HttpConn;
  function serve(handler: (request: Request) => Promise<Response>): void;

  namespace env {
    function get(key: string): string | undefined;
  }
}

/**
 * 请求统计信息接口
 * 用于跟踪API调用的各项指标
 */
interface RequestStats {
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  lastRequestTime: Date;
  averageResponseTime: number;
}

/**
 * 实时请求信息接口
 * 用于Dashboard显示最近的API请求记录
 */
interface LiveRequest {
  id: string;
  timestamp: Date;
  method: string;
  path: string;
  status: number;
  duration: number;
  userAgent: string;
  model?: string;
}

/**
 * OpenAI兼容请求结构
 * 标准的聊天完成API请求格式
 */
interface OpenAIRequest {
  model: string;
  messages: Message[];
  stream?: boolean;
  temperature?: number;
  max_tokens?: number;
}

/**
 * 聊天消息结构
 * 支持全方位多模态内容：文本、图像、视频、文档
 */
interface Message {
  role: string;
  content: string | Array<{
    type: string;
    text?: string;
    image_url?: { url: string };
    video_url?: { url: string };
    document_url?: { url: string };
    audio_url?: { url: string };
  }>;
}

/**
 * 上游服务请求结构
 * 向Z.ai服务发送的请求格式
 */
interface UpstreamRequest {
  stream: boolean;
  model: string;
  messages: Message[];
  signature_prompt: string;
  params: Record<string, unknown>;
  features: Record<string, unknown>;
  background_tasks?: Record<string, boolean>;
  chat_id?: string;
  id?: string;
  mcp_servers?: string[];
  model_item?: {
    id: string;
    name: string;
    owned_by: string;
    openai?: any;
    urlIdx?: number;
    info?: any;
    actions?: any[];
    tags?: any[];
  };
  tool_servers?: string[];
  variables?: Record<string, string>;
}

/**
 * OpenAI兼容响应结构
 */
interface OpenAIResponse {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: Choice[];
  usage?: Usage;
}

interface Choice {
  index: number;
  message?: Message;
  delta?: Delta;
  finish_reason?: string;
}

interface Delta {
  role?: string;
  content?: string;
  reasoning_content?: string;  // 用于传输thinking内容
}

interface Usage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

/**
 * 上游SSE数据结构
 */
interface UpstreamData {
  type: string;
  data: {
    delta_content?: string;
    edit_index?: number;
    edit_content?: string;
    phase: string;
    done: boolean;
    usage?: Usage;
    error?: UpstreamError;
    inner?: {
      error?: UpstreamError;
    };
  };
  error?: UpstreamError;
}

interface UpstreamError {
  detail: string;
  code: number;
}

interface ModelsResponse {
  object: string;
  data: Model[];
}

interface Model {
  id: string;
  object: string;
  created: number;
  owned_by: string;
}

/**
 * 环境变量配置
 * https://chat.z.ai/api/chat/completions
 * https://chat.z.ai/api/v2/chat/completions
 */
const UPSTREAM_URL = Deno.env.get("UPSTREAM_URL") || "https://chat.z.ai/api/v2/chat/completions";
const DEFAULT_KEY = Deno.env.get("DEFAULT_KEY") || "sk-your-key";
const ZAI_TOKEN = Deno.env.get("ZAI_TOKEN") || "";
const TIMESTAMP = Deno.env.get("TIMESTAMP") || "";
const SIGNATURE_TIMESTAMP = Deno.env.get("SIGNATURE_TIMESTAMP") || "";
const REQUESTID = Deno.env.get("REQUESTID") || "";
const USER_ID = Deno.env.get("USER_ID") || "";
const X_SIGNATURE = Deno.env.get("X_SIGNATURE") || "";
const SIGNATURE_PROMPT = Deno.env.get("SIGNATURE_PROMPT") || "";

/**
 * 配置常量定义
 */
// 思考内容处理策略: strip-去除<details>标签, think-转为<thinking>标签, raw-保留原样
const THINK_TAGS_MODE = "strip";

// 伪装前端头部（来自抓包分析）
const X_FE_VERSION = "1000";
const BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 Edg/139.0.0.0";
const SEC_CH_UA = "\"Not;A=Brand\";v=\"99\", \"Microsoft Edge\";v=\"139\", \"Chromium\";v=\"139\"";
const SEC_CH_UA_MOB = "?0";
const SEC_CH_UA_PLAT = "\"Windows\"";
const ORIGIN_BASE = "https://chat.z.ai";
// const TIMESTAMP = '1763251325370'
// const REQUESTID = '7355f6dd-d17b-4326-82a7-90a73adf1315'
// const USER_ID = 'a1458217-c795-4d2e-b7b2-c007397f4138'
// const SIGNATURE_TIMESTAMP = '1763251325370'
// const X_SIGNATURE = '9f733e4706bb3193a94923c2437589b3620f247a35ecd3ab02efa6c31a4992be';


const ANON_TOKEN_ENABLED = true;



/**
 * 支持的模型配置
 */
interface ModelConfig {
  id: string;           // OpenAI API中的模型ID
  name: string;         // 显示名称
  upstreamId: string;   // Z.ai上游的模型ID
  capabilities: {
    vision: boolean;
    mcp: boolean;
    thinking: boolean;
  };
  defaultParams: {
    top_p: number;
    temperature: number;
    max_tokens?: number;
  };
}

const SUPPORTED_MODELS: ModelConfig[] = [
  {
    id: "GLM-4-6-API-V1",
    name: "GLM-4.6",
    upstreamId: "GLM-4-6-API-V1",
    capabilities: {
      vision: false,
      mcp: true,
      thinking: true
    },
    defaultParams: {
      top_p: 0.95,
      temperature: 0.6,
      max_tokens: 80000
    }
  },
  {
    id: "GLM-4-6-API-V1",
    name: "claude-sonnet-4-5-20250929",
    upstreamId: "GLM-4-6-API-V1",
    capabilities: {
      vision: false,
      mcp: true,
      thinking: true
    },
    defaultParams: {
      top_p: 0.95,
      temperature: 0.6,
      max_tokens: 80000
    }
  },
  {
    id: "GLM-4.5v",
    name: "GLM-4.5v",
    upstreamId: "GLM-4.5v",
    capabilities: {
      vision: true,
      mcp: false,
      thinking: true
    },
    defaultParams: {
      top_p: 0.6,
      temperature: 0.8
    }
  }
];

// 默认模型
const DEFAULT_MODEL = SUPPORTED_MODELS[0];

// 根据模型ID获取配置
function getModelConfig(modelId: string): ModelConfig {
  // 标准化模型ID，处理Cherry Studio等客户端的大小写差异
  const normalizedModelId = normalizeModelId(modelId);
  const found = SUPPORTED_MODELS.find(m => m.id === normalizedModelId);

  if (!found) {
    debugLog("⚠️ 未找到模型配置: %s (标准化后: %s)，使用默认模型: %s",
      modelId, normalizedModelId, DEFAULT_MODEL.name);
  }

  return found || DEFAULT_MODEL;
}

/**
 * 标准化模型ID，处理不同客户端的命名差异
 * Cherry Studio等客户端可能使用不同的大小写格式
 */
function normalizeModelId(modelId: string): string {
  const normalized = modelId.toLowerCase().trim();

  // 处理常见的模型ID映射
  const modelMappings: Record<string, string> = {
    'GLM-4.5v': 'GLM-4.5v',
    'glm_4.5v': 'GLM-4.5v',
    'glm-4-6-api-v1': 'GLM-4-6-API-V1',
    'GLM-4.6': 'GLM-4-6-API-V1',
    'glm-4.6': 'GLM-4-6-API-V1',
    'claude-sonnet-4-5-20250929': 'GLM-4-6-API-V1'  // 向后兼容
  };

  const mapped = modelMappings[normalized];
  if (mapped) {
    debugLog("🔄 模型ID映射: %s → %s", modelId, mapped);
    return mapped;
  }

  return normalized;
}

/**
 * 处理和验证全方位多模态消息
 * 支持图像、视频、文档、音频等多种媒体类型
 */
function processMessages(messages: Message[], modelConfig: ModelConfig): Message[] {
  const processedMessages: Message[] = [];

  for (const message of messages) {
    const processedMessage: Message = { ...message };

    // 检查是否为多模态消息
    if (Array.isArray(message.content)) {
      debugLog("检测到多模态消息，内容块数量: %d", message.content.length);

      // 统计各种媒体类型
      const mediaStats = {
        text: 0,
        images: 0,
        videos: 0,
        documents: 0,
        audios: 0,
        others: 0
      };

      // 验证模型是否支持多模态
      if (!modelConfig.capabilities.vision) {
        debugLog("警告: 模型 %s 不支持多模态，但收到了多模态消息", modelConfig.name);
        // 只保留文本内容
        const textContent = message.content
          .filter(block => block.type === 'text')
          .map(block => block.text)
          .join('\n');
        processedMessage.content = textContent;
      } else {
        // GLM-4.5v 支持全方位多模态，处理所有内容类型
        for (const block of message.content) {
          switch (block.type) {
            case 'text':
              if (block.text) {
                mediaStats.text++;
                debugLog("📝 文本内容，长度: %d", block.text.length);
              }
              break;

            case 'image_url':
              if (block.image_url?.url) {
                mediaStats.images++;
                const url = block.image_url.url;
                if (url.startsWith('data:image/')) {
                  const mimeMatch = url.match(/data:image\/([^;]+)/);
                  const format = mimeMatch ? mimeMatch[1] : 'unknown';
                  debugLog("🖼️ 图像数据: %s格式, 大小: %d字符", format, url.length);
                } else if (url.startsWith('http')) {
                  debugLog("🔗 图像URL: %s", url);
                } else {
                  debugLog("⚠️ 未知图像格式: %s", url.substring(0, 50));
                }
              }
              break;

            case 'video_url':
              if (block.video_url?.url) {
                mediaStats.videos++;
                const url = block.video_url.url;
                if (url.startsWith('data:video/')) {
                  const mimeMatch = url.match(/data:video\/([^;]+)/);
                  const format = mimeMatch ? mimeMatch[1] : 'unknown';
                  debugLog("🎥 视频数据: %s格式, 大小: %d字符", format, url.length);
                } else if (url.startsWith('http')) {
                  debugLog("🔗 视频URL: %s", url);
                } else {
                  debugLog("⚠️ 未知视频格式: %s", url.substring(0, 50));
                }
              }
              break;

            case 'document_url':
              if (block.document_url?.url) {
                mediaStats.documents++;
                const url = block.document_url.url;
                if (url.startsWith('data:application/')) {
                  const mimeMatch = url.match(/data:application\/([^;]+)/);
                  const format = mimeMatch ? mimeMatch[1] : 'unknown';
                  debugLog("📄 文档数据: %s格式, 大小: %d字符", format, url.length);
                } else if (url.startsWith('http')) {
                  debugLog("🔗 文档URL: %s", url);
                } else {
                  debugLog("⚠️ 未知文档格式: %s", url.substring(0, 50));
                }
              }
              break;

            case 'audio_url':
              if (block.audio_url?.url) {
                mediaStats.audios++;
                const url = block.audio_url.url;
                if (url.startsWith('data:audio/')) {
                  const mimeMatch = url.match(/data:audio\/([^;]+)/);
                  const format = mimeMatch ? mimeMatch[1] : 'unknown';
                  debugLog("🎵 音频数据: %s格式, 大小: %d字符", format, url.length);
                } else if (url.startsWith('http')) {
                  debugLog("🔗 音频URL: %s", url);
                } else {
                  debugLog("⚠️ 未知音频格式: %s", url.substring(0, 50));
                }
              }
              break;

            default:
              mediaStats.others++;
              debugLog("❓ 未知内容类型: %s", block.type);
          }
        }

        // 输出统计信息
        const totalMedia = mediaStats.images + mediaStats.videos + mediaStats.documents + mediaStats.audios;
        if (totalMedia > 0) {
          debugLog("🎯 多模态内容统计: 文本(%d) 图像(%d) 视频(%d) 文档(%d) 音频(%d)",
            mediaStats.text, mediaStats.images, mediaStats.videos, mediaStats.documents, mediaStats.audios);
        }
      }
    } else if (typeof message.content === 'string') {
      debugLog("📝 纯文本消息，长度: %d", message.content.length);
    }

    processedMessages.push(processedMessage);
  }

  return processedMessages;
}

const DEBUG_MODE = Deno.env.get("DEBUG_MODE") !== "false"; // 默认为true
const DEFAULT_STREAM = Deno.env.get("DEFAULT_STREAM") !== "false"; // 默认为true
const DASHBOARD_ENABLED = Deno.env.get("DASHBOARD_ENABLED") !== "false"; // 默认为true

/**
 * 全局状态变量
 */

let stats: RequestStats = {
  totalRequests: 0,
  successfulRequests: 0,
  failedRequests: 0,
  lastRequestTime: new Date(),
  averageResponseTime: 0
};

let liveRequests: LiveRequest[] = [];

/**
 * 工具函数
 */

function debugLog(format: string, ...args: unknown[]): void {
  if (DEBUG_MODE) {
    console.log(`[DEBUG] ${format}`, ...args);
  }
}

function recordRequestStats(startTime: number, path: string, status: number): void {
  const duration = Date.now() - startTime;

  stats.totalRequests++;
  stats.lastRequestTime = new Date();

  if (status >= 200 && status < 300) {
    stats.successfulRequests++;
  } else {
    stats.failedRequests++;
  }

  // 更新平均响应时间
  if (stats.totalRequests > 0) {
    const totalDuration = stats.averageResponseTime * (stats.totalRequests - 1) + duration;
    stats.averageResponseTime = totalDuration / stats.totalRequests;
  } else {
    stats.averageResponseTime = duration;
  }
}

function addLiveRequest(method: string, path: string, status: number, duration: number, userAgent: string, model?: string): void {
  const request: LiveRequest = {
    id: Date.now().toString(),
    timestamp: new Date(),
    method,
    path,
    status,
    duration,
    userAgent,
    model
  };

  liveRequests.push(request);

  // 只保留最近的100条请求
  if (liveRequests.length > 100) {
    liveRequests = liveRequests.slice(1);
  }
}

function getLiveRequestsData(): string {
  try {
    // 确保liveRequests是数组
    if (!Array.isArray(liveRequests)) {
      debugLog("liveRequests不是数组，重置为空数组");
      liveRequests = [];
    }

    // 确保返回的数据格式与前端期望的一致
    const requestData = liveRequests.map(req => ({
      id: req.id || "",
      timestamp: req.timestamp || new Date(),
      method: req.method || "",
      path: req.path || "",
      status: req.status || 0,
      duration: req.duration || 0,
      user_agent: req.userAgent || ""
    }));

    return JSON.stringify(requestData);
  } catch (error) {
    debugLog("获取实时请求数据失败: %v", error);
    return JSON.stringify([]);
  }
}

function getStatsData(): string {
  try {
    // 确保stats对象存在
    if (!stats) {
      debugLog("stats对象不存在，使用默认值");
      stats = {
        totalRequests: 0,
        successfulRequests: 0,
        failedRequests: 0,
        lastRequestTime: new Date(),
        averageResponseTime: 0
      };
    }

    // 确保返回的数据格式与前端期望的一致
    const statsData = {
      totalRequests: stats.totalRequests || 0,
      successfulRequests: stats.successfulRequests || 0,
      failedRequests: stats.failedRequests || 0,
      averageResponseTime: stats.averageResponseTime || 0
    };

    return JSON.stringify(statsData);
  } catch (error) {
    debugLog("获取统计数据失败: %v", error);
    return JSON.stringify({
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      averageResponseTime: 0
    });
  }
}

function getClientIP(request: Request): string {
  // 检查X-Forwarded-For头
  const xff = request.headers.get("X-Forwarded-For");
  if (xff) {
    const ips = xff.split(",");
    if (ips.length > 0) {
      return ips[0].trim();
    }
  }

  // 检查X-Real-IP头
  const xri = request.headers.get("X-Real-IP");
  if (xri) {
    return xri;
  }

  // 对于Deno Deploy，我们无法直接获取RemoteAddr，返回一个默认值
  return "unknown";
}

function setCORSHeaders(headers: Headers): void {
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  headers.set("Access-Control-Allow-Credentials", "true");
}

function validateApiKey(authHeader: string | null): boolean {
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return false;
  }

  const apiKey = authHeader.substring(7);
  return apiKey === DEFAULT_KEY;
}

async function getAnonymousToken(): Promise<string> {
  try {
    const response = await fetch(`${ORIGIN_BASE}/api/v1/auths/`, {
      method: "GET",
      headers: {
        "User-Agent": BROWSER_UA,
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "X-FE-Version": X_FE_VERSION,
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": SEC_CH_UA_MOB,
        "sec-ch-ua-platform": SEC_CH_UA_PLAT,
        "Origin": ORIGIN_BASE,
        "Referer": `${ORIGIN_BASE}/`
      }
    });

    if (!response.ok) {
      throw new Error(`Anonymous token request failed with status ${response.status}`);
    }

    const data = await response.json() as { token: string };
    if (!data.token) {
      throw new Error("Anonymous token is empty");
    }

    return data.token;
  } catch (error) {
    debugLog("获取匿名token失败: %v", error);
    throw error;
  }
}

// 调用上游API
async function callUpstreamWithHeaders(
  upstreamReq: UpstreamRequest,
  refererChatID: string,
  authToken: string
): Promise<Response> {
  try {
    debugLog("调用上游API: %s", UPSTREAM_URL);

    // 特别检查和记录全方位多模态内容
    const hasMultimedia = upstreamReq.messages.some(msg =>
      Array.isArray(msg.content) &&
      msg.content.some(block =>
        ['image_url', 'video_url', 'document_url', 'audio_url'].includes(block.type)
      )
    );

    if (hasMultimedia) {
      debugLog("🎯 请求包含多模态数据，正在发送到上游...");

      for (let i = 0; i < upstreamReq.messages.length; i++) {
        const msg = upstreamReq.messages[i];
        if (Array.isArray(msg.content)) {
          for (let j = 0; j < msg.content.length; j++) {
            const block = msg.content[j];

            // 处理图像
            if (block.type === 'image_url' && block.image_url?.url) {
              const url = block.image_url.url;
              if (url.startsWith('data:image/')) {
                const mimeMatch = url.match(/data:image\/([^;]+)/);
                const format = mimeMatch ? mimeMatch[1] : 'unknown';
                const sizeKB = Math.round(url.length * 0.75 / 1024); // base64 大约是原文件的 1.33 倍
                debugLog("🖼️ 消息[%d] 图像[%d]: %s格式, 数据长度: %d字符 (~%dKB)",
                  i, j, format, url.length, sizeKB);

                // 图片大小警告
                if (sizeKB > 1000) {
                  debugLog("⚠️  图片较大 (%dKB)，可能导致上游处理失败", sizeKB);
                  debugLog("💡 建议: 将图片压缩到 500KB 以下");
                } else if (sizeKB > 500) {
                  debugLog("⚠️  图片偏大 (%dKB)，建议压缩", sizeKB);
                }
              } else {
                debugLog("🔗 消息[%d] 图像[%d]: 外部URL - %s", i, j, url);
              }
            }

            // 处理视频
            if (block.type === 'video_url' && block.video_url?.url) {
              const url = block.video_url.url;
              if (url.startsWith('data:video/')) {
                const mimeMatch = url.match(/data:video\/([^;]+)/);
                const format = mimeMatch ? mimeMatch[1] : 'unknown';
                debugLog("🎥 消息[%d] 视频[%d]: %s格式, 数据长度: %d字符",
                  i, j, format, url.length);
              } else {
                debugLog("🔗 消息[%d] 视频[%d]: 外部URL - %s", i, j, url);
              }
            }

            // 处理文档
            if (block.type === 'document_url' && block.document_url?.url) {
              const url = block.document_url.url;
              if (url.startsWith('data:application/')) {
                const mimeMatch = url.match(/data:application\/([^;]+)/);
                const format = mimeMatch ? mimeMatch[1] : 'unknown';
                debugLog("📄 消息[%d] 文档[%d]: %s格式, 数据长度: %d字符",
                  i, j, format, url.length);
              } else {
                debugLog("🔗 消息[%d] 文档[%d]: 外部URL - %s", i, j, url);
              }
            }

            // 处理音频
            if (block.type === 'audio_url' && block.audio_url?.url) {
              const url = block.audio_url.url;
              if (url.startsWith('data:audio/')) {
                const mimeMatch = url.match(/data:audio\/([^;]+)/);
                const format = mimeMatch ? mimeMatch[1] : 'unknown';
                debugLog("🎵 消息[%d] 音频[%d]: %s格式, 数据长度: %d字符",
                  i, j, format, url.length);
              } else {
                debugLog("🔗 消息[%d] 音频[%d]: 外部URL - %s", i, j, url);
              }
            }
          }
        }
      }
    }

    debugLog("上游请求体: %s", JSON.stringify(upstreamReq));

    // 构造URL参数
    const urlParams = new URLSearchParams();

    // 添加基本参数
    urlParams.append('timestamp', TIMESTAMP);
    urlParams.append('requestId', REQUESTID);
    urlParams.append('user_id', USER_ID);
    urlParams.append('signature_timestamp', SIGNATURE_TIMESTAMP);

    // 构造完整的URL
    const fullUrl = `${UPSTREAM_URL}?${urlParams.toString()}`;

    debugLog("完整请求URL: %s", fullUrl);

    const response = await fetch(fullUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": BROWSER_UA,
        "Authorization": `Bearer ${authToken}`,
        "X-FE-Version": X_FE_VERSION,
        "X-Signature": X_SIGNATURE,
      },
      body: JSON.stringify(upstreamReq)
    });

    debugLog("上游响应状态: %d %s", response.status, response.statusText);
    return response;
  } catch (error) {
    debugLog("调用上游失败: %v", error);
    throw error;
  }
}

/**
 * 检测中英文重复内容
 */
function isChineseEnglishDuplicate(content: string): boolean {
  // 简单的中英文重复检测：检查是否包含常见的中英文重复模式
  const chinesePattern = /[\u4e00-\u9fff]{10,}/; // 至少10个中文字符
  const englishPattern = /[a-zA-Z]{20,}/; // 至少20个英文字符

  const hasChinese = chinesePattern.test(content);
  const hasEnglish = englishPattern.test(content);

  // 如果同时包含大量中文和英文，可能是重复内容
  if (hasChinese && hasEnglish) {
    // 进一步检查是否有相似的结构或关键词重复
    const lines = content.split('\n');
    if (lines.length > 2) {
      const firstLines = lines.slice(0, Math.floor(lines.length / 2)).join('\n');
      const secondLines = lines.slice(Math.floor(lines.length / 2)).join('\n');

      // 简单的相似度检查：如果两部分都包含类似的结构标记
      const structureMarkers = ['>', '*', '#', '1.', '2.', '3.'];
      const firstHalfMarkers = structureMarkers.filter(marker => firstLines.includes(marker)).length;
      const secondHalfMarkers = structureMarkers.filter(marker => secondLines.includes(marker)).length;

      // 如果两部分都有类似的结构标记，可能是重复
      if (firstHalfMarkers > 2 && secondHalfMarkers > 2) {
        debugLog("检测到可能的中英文重复内容，结构标记相似度: %d/%d", firstHalfMarkers, secondHalfMarkers);
        return true;
      }
    }
  }

  return false;
}

/**
 * 从重复内容中提取主要语言
 */
function extractPrimaryLanguage(content: string): string {
  const chineseCount = (content.match(/[\u4e00-\u9fff]/g) || []).length;
  const englishCount = (content.match(/[a-zA-Z]/g) || []).length;

  // 根据字符数量判断主要语言
  if (chineseCount > englishCount) {
    // 保留中文部分，移除英文部分
    return content.split('\n').filter(line => {
      const chineseInLine = (line.match(/[\u4e00-\u9fff]/g) || []).length;
      const englishInLine = (line.match(/[a-zA-Z]/g) || []).length;
      return chineseInLine >= englishInLine; // 保留中文为主的行
    }).join('\n');
  } else {
    // 保留英文部分，移除中文部分
    return content.split('\n').filter(line => {
      const chineseInLine = (line.match(/[\u4e00-\u9fff]/g) || []).length;
      const englishInLine = (line.match(/[a-zA-Z]/g) || []).length;
      return englishInLine > chineseInLine; // 保留英文为主的行
    }).join('\n');
  }
}

/**
 * 计算内容哈希值
 */
// ==================== 补丁 1: 替换 hashContent 函数 ====================
/**
 * 改进的内容哈希函数 - 减少碰撞，特别处理短内容和流式内容
 */
function hashContent(content: string): string {
  const trimmed = content.trim();

  if (trimmed.length === 0) {
    return "";
  }

  if (trimmed.length < 5) {
    // 对于非常短的内容（1-4字符），直接返回原内容，避免哈希冲突
    return trimmed;
  }

  if (trimmed.length < 15) {
    // 对于短内容（5-14字符），使用字符级哈希，提高精确度
    let hash = 0;
    for (let i = 0; i < trimmed.length; i++) {
      const char = trimmed.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // 转换为32位整数
    }
    return hash.toString(36);
  }

  // 对于较长内容（15+字符），使用多点采样
  let hash = trimmed.length.toString(36);

  // 动态采样大小，避免固定20字符在短内容上采样过多
  const len = trimmed.length;
  const sampleSize = Math.min(20, Math.floor(len * 0.3));

  const samples = [
    trimmed.substring(0, Math.min(sampleSize, len)),
    trimmed.substring(Math.floor(len * 0.25), Math.min(Math.floor(len * 0.25) + sampleSize, len)),
    trimmed.substring(Math.max(0, Math.floor(len * 0.5) - Math.floor(sampleSize / 2)), Math.min(Math.floor(len * 0.5) + Math.floor(sampleSize / 2), len)),
    trimmed.substring(Math.floor(len * 0.75), Math.min(Math.floor(len * 0.75) + sampleSize, len)),
    trimmed.substring(Math.max(0, len - sampleSize))
  ];

  hash += '|' + samples.filter(s => s.length > 0).join('|');

  return hash;
}

function transformThinking(content: string): string {
  // 提取<details>标签中的元数据属性
  const detailsMatch = content.match(/<details([^>]*)>/);
  const attributes: Record<string, string> = {};

  if (detailsMatch) {
    const attrStr = detailsMatch[1];
    // 提取属性，如 type="reasoning", duration="2" 等
    const attrRegex = /(\w+)="([^"]*)"/g;
    let match;
    while ((match = attrRegex.exec(attrStr)) !== null) {
      attributes[match[1]] = match[2];
    }
  }

  // 提取<summary>内容
  const summaryMatch = content.match(/<summary>(.*?)<\/summary>/s);
  const summary = summaryMatch ? summaryMatch[1] : "";

  // 提取实际思考内容（在</summary>之后的所有内容，直到</details>）
  let thinkingContent = content;
  thinkingContent = thinkingContent.replace(/<details[^>]*>\s*<summary>.*?<\/summary>/gs, "");
  thinkingContent = thinkingContent.replace(/<\/details>/g, "");
  thinkingContent = thinkingContent.trim();

  // 处理每行前缀 "> "（包括起始位置）
  thinkingContent = thinkingContent.replace(/^> /, "");
  thinkingContent = thinkingContent.replace(/\n> /g, "\n");

  // 清理其他残留自定义标签
  thinkingContent = thinkingContent.replace(/<\/thinking>/g, "");
  thinkingContent = thinkingContent.replace(/<Full>/g, "");
  thinkingContent = thinkingContent.replace(/<\/Full>/g, "");
  thinkingContent = thinkingContent.trim();

  // 检测并处理中英文重复内容
  if (isChineseEnglishDuplicate(thinkingContent)) {
    debugLog("检测到中英文重复内容，进行去重处理");
    thinkingContent = extractPrimaryLanguage(thinkingContent);
    debugLog("去重后内容长度: %d", thinkingContent.length);
  }

  // 根据模式返回不同格式的内容
  switch (THINK_TAGS_MODE as "strip" | "think" | "raw") {
    case "think": {
      // 使用OpenAI风格的<thinking>标签包装，并包含元数据
      const metadata = [];
      if (attributes.type) metadata.push(`type="${attributes.type}"`);
      if (attributes.duration) metadata.push(`duration="${attributes.duration}s"`);
      if (summary && summary !== "Thinking…") metadata.push(`summary="${summary}"`);

      const metaStr = metadata.length > 0 ? ` ${metadata.join(" ")}` : "";
      return `<thinking${metaStr}>\n${thinkingContent}\n</thinking>`;
    }

    case "raw": {
      // 保留原始格式，但清理不必要的标签
      let rawContent = content;
      // 只移除残留的自定义标签，保留<details>、<summary>等结构
      rawContent = rawContent.replace(/<\/thinking>/g, "");
      rawContent = rawContent.replace(/<Full>/g, "");
      rawContent = rawContent.replace(/<\/Full>/g, "");
      return rawContent.trim();
    }

    case "strip":
    default: {
      // 只返回纯文本内容
      return thinkingContent;
    }
  }
}

// ==================== 补丁 2: 替换 processUpstreamStream 函数 ====================
/**
 * 修复后的流处理函数
 * 解决 reasoning_content 重复和 content 截断问题
 * 终极修复版 processUpstreamStream
 * 解决：1. 重复的 [DONE] 标记  2. 内容截断
 * 3. 添加content缓冲机制避免过度分割
 */

async function processUpstreamStream(
  body: ReadableStream<Uint8Array>,
  writer: WritableStreamDefaultWriter<Uint8Array>,
  encoder: TextEncoder,
  modelName: string
): Promise<void> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let hasProcessedEditContent = false;
  let processedContentHashes = new Set<string>();
  let hasStartedAnswer = false;
  let hasSentEndMarker = false;  // 🔧 新增：防止重复发送 [DONE]
  let answerContentBuffer = "";  // 🔧 新增：用于累积answer阶段的内容

  try {
    while (true) {
      const { done, value } = await reader.read();

      if (value) {
        buffer += decoder.decode(value, { stream: true });
      }

      const lines = buffer.split('\n');

      // 如果读取完成，处理所有行；否则保留最后一行
      if (!done) {
        buffer = lines.pop() || "";
      } else {
        buffer = "";
      }

      // 🔧 关键修复：先处理所有内容，再检查是否结束
      for (const line of lines) {
        if (!line.startsWith("data: ")) continue;

        const dataStr = line.substring(6).trim();
        if (dataStr === "" || dataStr === "[DONE]") continue;

        try {
          const upstreamData = JSON.parse(dataStr) as UpstreamData;

          // 🔧 添加上游响应流详细日志
          debugLog("📥 上游响应流 - phase: %s, hasDeltaContent: %s, hasEditContent: %s, done: %s",
            upstreamData.data.phase,
            !!upstreamData.data.delta_content,
            !!upstreamData.data.edit_content,
            upstreamData.data.done);

          if (upstreamData.data.delta_content) {
            debugLog("📄 上游delta_content预览: %s",
              upstreamData.data.delta_content.length > 100 ?
                upstreamData.data.delta_content.substring(0, 100) + "..." :
                upstreamData.data.delta_content);
          }

          if (upstreamData.data.edit_content) {
            debugLog("📝 上游edit_content预览: %s",
              upstreamData.data.edit_content.length > 100 ?
                upstreamData.data.edit_content.substring(0, 100) + "..." :
                upstreamData.data.edit_content);
          }

          // === 错误处理 ===
          if (upstreamData.error || upstreamData.data.error ||
            (upstreamData.data.inner && upstreamData.data.inner.error)) {

            // 🔧 发送缓冲的content
            if (answerContentBuffer) {
              const chunk = {
                id: `chatcmpl-${Date.now()}`,
                object: "chat.completion.chunk",
                created: Math.floor(Date.now() / 1000),
                model: modelName,
                choices: [{
                  index: 0,
                  delta: {
                    role: "assistant",
                    content: answerContentBuffer,
                    reasoning_content: ""
                  }
                }]
              };
              await writer.write(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));
              answerContentBuffer = "";
            }

            if (!hasSentEndMarker) {
              const endChunk = {
                id: `chatcmpl-${Date.now()}`,
                object: "chat.completion.chunk",
                created: Math.floor(Date.now() / 1000),
                model: modelName,
                choices: [{ index: 0, delta: {}, finish_reason: "stop" }]
              };

              await writer.write(encoder.encode(`data: ${JSON.stringify(endChunk)}\n\n`));
              await writer.write(encoder.encode("data: [DONE]\n\n"));
              hasSentEndMarker = true;
            }
            return;
          }

          const isThinkingPhase = upstreamData.data.phase === "thinking";
          const isAnswerPhase = upstreamData.data.phase === "answer";
          const isOtherPhase = upstreamData.data.phase === "other";
          const isDonePhase = upstreamData.data.phase === "done";

          // === 处理 edit_content (深度思考链摘要) ===
          // 关键的修复：edit_content 可能在 thinking 阶段或 answer 阶段收到
          // 无论哪个阶段，只要收到 edit_content 且之前没处理过，就应该处理
          if (upstreamData.data.edit_content && upstreamData.data.edit_content !== "" && !hasProcessedEditContent) {

            // 🔧 发送缓冲的content（如果有）
            if (answerContentBuffer) {
              const chunk = {
                id: `chatcmpl-${Date.now()}`,
                object: "chat.completion.chunk",
                created: Math.floor(Date.now() / 1000),
                model: modelName,
                choices: [{
                  index: 0,
                  delta: {
                    role: "assistant",
                    content: answerContentBuffer,
                    reasoning_content: ""
                  }
                }]
              };
              await writer.write(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));
              answerContentBuffer = "";
            }

            // 提取<details>标签中的实际思考内容，跳过<summary>部分
            let thinkingContent = upstreamData.data.edit_content;

            // 检查是否包含<summary>标签
            const summaryMatch = thinkingContent.match(/<summary>.*?<\/summary>/s);
            if (summaryMatch) {
              // 方法1：提取<summary>之后、</details>之前的内容
              const summaryEnd = thinkingContent.indexOf(summaryMatch[0]) + summaryMatch[0].length;
              const detailsEnd = thinkingContent.lastIndexOf('</details>');

              if (detailsEnd > summaryEnd) {
                // 提取<summary>和</details>之间的内容
                thinkingContent = thinkingContent.substring(summaryEnd, detailsEnd);
              } else {
                // 如果没有找到</details>，移除<summary>标签后的内容
                thinkingContent = thinkingContent.substring(summaryEnd);
              }

              // 清理可能残留的<details>标签
              thinkingContent = thinkingContent.replace(/<details[^>]*>/g, '');
              thinkingContent = thinkingContent.replace(/<\/details>/g, '');
              thinkingContent = thinkingContent.trim();
            }

            // 如果处理后的内容为空，但原始内容包含<details>，说明格式异常，直接清理HTML标签
            if (thinkingContent === "" && upstreamData.data.edit_content.includes('<details')) {
              thinkingContent = upstreamData.data.edit_content.replace(/<[^>]+>/g, '');
              thinkingContent = thinkingContent.replace(/^> /gm, '');
              thinkingContent = thinkingContent.trim();
            }

            const out = transformThinking(thinkingContent);

            if (out !== "") {
              const contentHash = hashContent(out);

              if (!processedContentHashes.has(contentHash)) {
                processedContentHashes.add(contentHash);
                hasProcessedEditContent = true;  // 🔧 标记已经处理过 edit_content

                const chunk = {
                  id: `chatcmpl-${Date.now()}`,
                  object: "chat.completion.chunk",
                  created: Math.floor(Date.now() / 1000),
                  model: modelName,
                  choices: [{
                    index: 0,
                    delta: {
                      role: "assistant",
                      content: "",
                      reasoning_content: out
                    }
                  }]
                };

                await writer.write(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));
              }
            }

            // 🔧 记录已经处理 edit_content，后续将跳过 delta thinking
            debugLog("📥 已处理 edit_content，标记 hasProcessedEditContent=true");

            // 🔧 记录下发的thinking内容
            debugLog("📤 下发thinking块(edit) - 长度: %d, 内容预览: %s",
              out.length,
              out.length > 50 ? out.substring(0, 50) + "..." : out);
          }

          // === 处理 delta_content ===
          if (upstreamData.data.delta_content &&
            upstreamData.data.delta_content !== "") {

            let out = upstreamData.data.delta_content;

            // 如果已进入 answer 阶段，跳过 thinking 内容
            if (hasStartedAnswer && isThinkingPhase) {
              continue;
            }

            if (isThinkingPhase) {
              // 🔧 发送缓冲的content（如果有）
              if (answerContentBuffer) {
                const chunk = {
                  id: `chatcmpl-${Date.now()}`,
                  object: "chat.completion.chunk",
                  created: Math.floor(Date.now() / 1000),
                  model: modelName,
                  choices: [{
                    index: 0,
                    delta: {
                      role: "assistant",
                      content: answerContentBuffer,
                      reasoning_content: ""
                    }
                  }]
                };
                await writer.write(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));
                answerContentBuffer = "";
              }

              // 如果已处理 edit_content，跳过所有 thinking delta
              if (hasProcessedEditContent) {
                continue;
              }

              // 清理 thinking 内容
              out = out.replace(/<[^>]+>/g, "");
              out = out.replace(/^> /, "");
              out = out.replace(/\n> /g, "\n");
              out = out.trim();

              if (out !== "") {
                const contentHash = hashContent(out);

                if (!processedContentHashes.has(contentHash)) {
                  processedContentHashes.add(contentHash);

                  const chunk = {
                    id: `chatcmpl-${Date.now()}`,
                    object: "chat.completion.chunk",
                    created: Math.floor(Date.now() / 1000),
                    model: modelName,
                    choices: [{
                      index: 0,
                      delta: {
                        role: "assistant",
                        content: "",
                        reasoning_content: out
                      }
                    }]
                  };

                  await writer.write(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));
                }
              }
            } else if (isAnswerPhase) {
              // Answer 阶段 - 处理回复正文
              if (!hasStartedAnswer) {
                // 在进入answer阶段前，先发送所有缓冲的thinking内容
                hasStartedAnswer = true;
                debugLog("🤖 ---->>>> 进入 answer 阶段");
              }

              if (out.trim() !== "") {
                // 🔧 累积content而不是立即发送
                answerContentBuffer += out;

                // 🔧 如果缓冲区足够大，或者包含换行符，则发送
                if (answerContentBuffer.length >= 50 || answerContentBuffer.includes('\n')) {
                  const chunk = {
                    id: `chatcmpl-${Date.now()}`,
                    object: "chat.completion.chunk",
                    created: Math.floor(Date.now() / 1000),
                    model: modelName,
                    choices: [{
                      index: 0,
                      delta: {
                        role: "assistant",
                        content: answerContentBuffer,
                        reasoning_content: ""
                      }
                    }]
                  };
                  await writer.write(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));

                  // 🔧 记录发送的answer内容
                  debugLog("📤 下发answer块 - 长度: %d, 内容预览: %s",
                    answerContentBuffer.length,
                    answerContentBuffer.length > 50 ? answerContentBuffer.substring(0, 50) + "..." : answerContentBuffer);

                  answerContentBuffer = "";
                }
              }
            }
          }

          // 🔧 处理 phase=other 的 edit_content（回复正文结尾）
          // 这必须独立于 delta_content 的处理，确保无论是否有 delta_content 都能执行
          if (isOtherPhase && upstreamData.data.edit_content && upstreamData.data.edit_content !== "") {
            // 根据上游API文档，正文的结束字符放在phase=other的edit_content中
            answerContentBuffer += upstreamData.data.edit_content;

            debugLog("📥 收到other阶段结束字符: '%s' (缓冲区总长度: %d)",
              upstreamData.data.edit_content,
              answerContentBuffer.length);
          }

          // 🔧 关键修复：不要在这里 break，继续处理所有数据
          // 只是标记已经收到 done 信号

          // 🔧 新增：如果收到done信号，立即发送缓冲区
          if (isDonePhase || upstreamData.data.done) {
            if (answerContentBuffer) {
              debugLog("收到done信号，发送剩余缓冲内容，长度: %d", answerContentBuffer.length);
              const chunk = {
                id: `chatcmpl-${Date.now()}`,
                object: "chat.completion.chunk",
                created: Math.floor(Date.now() / 1000),
                model: modelName,
                choices: [{
                  index: 0,
                  delta: {
                    role: "assistant",
                    content: answerContentBuffer,
                    reasoning_content: ""
                  }
                }]
              };
              await writer.write(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));

              // 🔧 记录发送的最终内容
              debugLog("📤 下发最终内容(done) - 长度: %d", answerContentBuffer.length);

              answerContentBuffer = "";
            }
          }

        } catch (error) {
          debugLog("SSE数据解析失败: %v", error);
        }
      }

      // 🔧 修复点：在处理完所有数据后，检查是否应该结束
      if (done) {
        // 🔧 发送剩余的缓冲content（双重保险）
        if (answerContentBuffer) {
          debugLog("流结束: 发送剩余缓冲内容，长度: %d", answerContentBuffer.length);
          const chunk = {
            id: `chatcmpl-${Date.now()}`,
            object: "chat.completion.chunk",
            created: Math.floor(Date.now() / 1000),
            model: modelName,
            choices: [{
              index: 0,
              delta: {
                role: "assistant",
                content: answerContentBuffer,
                reasoning_content: ""
              }
            }]
          };
          await writer.write(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));

          // 🔧 记录发送的最终内容
          debugLog("📤 下发最终内容(流结束) - 长度: %d", answerContentBuffer.length);

          answerContentBuffer = "";
        }

        debugLog("Reader done, 准备发送最终[DONE]标记");
        break;
      }
    }

    // 🔧 在 while 循环结束后，统一发送一次结束标记
    if (!hasSentEndMarker) {
      debugLog("发送最终结束标记");

      // 确保所有数据都已刷新
      await writer.write(encoder.encode(""));
      await new Promise(resolve => setTimeout(resolve, 100));

      const endChunk = {
        id: `chatcmpl-${Date.now()}`,
        object: "chat.completion.chunk",
        created: Math.floor(Date.now() / 1000),
        model: modelName,
        choices: [{
          index: 0,
          delta: {},
          finish_reason: "stop"
        }]
      };

      await writer.write(encoder.encode(`data: ${JSON.stringify(endChunk)}\n\n`));
      await writer.write(encoder.encode("data: [DONE]\n\n"));
      hasSentEndMarker = true;
    }

  } catch (error) {
    debugLog("处理上游流时出错: %v", error);
  } finally {
    debugLog("准备关闭 writer");

    // 最后的刷新
    await new Promise(resolve => setTimeout(resolve, 50));

    try {
      await writer.close();
      debugLog("Writer 已关闭");
    } catch (e) {
      debugLog("关闭 writer 时出错: %v", e);
    }
  }
}

// 收集完整响应（用于非流式响应）
async function collectFullResponse(body: ReadableStream<Uint8Array>): Promise<string> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let fullContent = "";

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || ""; // 保留最后一个不完整的行

      for (const line of lines) {
        if (line.startsWith("data: ")) {
          const dataStr = line.substring(6);
          if (dataStr === "") continue;

          try {
            const upstreamData = JSON.parse(dataStr) as UpstreamData;

            if (upstreamData.data.delta_content && upstreamData.data.delta_content !== "") {
              let out = upstreamData.data.delta_content;
              if (upstreamData.data.phase === "thinking") {
                out = transformThinking(out);
              }

              if (out !== "") {
                fullContent += out;
              }
            }

            // 检查是否结束
            if (upstreamData.data.done || (upstreamData.data.phase as string) === "done") {
              debugLog("检测到完成信号，停止收集");
              return fullContent;
            }
          } catch (error) {
            // 忽略解析错误
          }
        }
      }
    }
  } finally {
    reader.releaseLock();
  }

  return fullContent;
}

/**
 * HTTP服务器和路由处理
 */

function getIndexHTML(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZtoApi - OpenAI兼容API代理</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 40px;
            margin-top: 40px;
        }
        header {
            text-align: center;
            margin-bottom: 40px;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 2.5rem;
        }
        .subtitle {
            color: #666;
            font-size: 1.2rem;
            margin-bottom: 30px;
        }
        .links {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 40px;
        }
        .link-card {
            background-color: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            border: 1px solid #e9ecef;
        }
        .link-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .link-card h3 {
            margin-top: 0;
            color: #007bff;
        }
        .link-card p {
            color: #666;
            margin-bottom: 20px;
        }
        .link-card a {
            display: inline-block;
            background-color: #007bff;
            color: white;
            padding: 10px 20px;
            border-radius: 4px;
            text-decoration: none;
            font-weight: bold;
            transition: background-color 0.3s ease;
        }
        .link-card a:hover {
            background-color: #0056b3;
        }
        .features {
            margin-top: 60px;
        }
        .features h2 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
        }
        .feature-list {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
        }
        .feature-item {
            text-align: center;
            padding: 20px;
        }
        .feature-item i {
            font-size: 2rem;
            color: #007bff;
            margin-bottom: 15px;
        }
        .feature-item h3 {
            color: #333;
            margin-bottom: 10px;
        }
        .feature-item p {
            color: #666;
        }
        footer {
            text-align: center;
            margin-top: 60px;
            padding-top: 20px;
            border-top: 1px solid #e9ecef;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>ZtoApi</h1>
            <div class="subtitle">OpenAI兼容API代理 for Z.ai GLM-4.6</div>
            <p>一个高性能、易于部署的API代理服务，让你能够使用OpenAI兼容的格式访问Z.ai的GLM-4.6模型。</p>
        </header>
        
        <div class="links">
            <div class="link-card">
                <h3>📖 API文档</h3>
                <p>查看完整的API文档，了解如何使用本服务。</p>
                <a href="/docs">查看文档</a>
            </div>
            
            <div class="link-card">
                <h3>📊 API调用看板</h3>
                <p>实时监控API调用情况，查看请求统计和性能指标。</p>
                <a href="/dashboard">查看看板</a>
            </div>
            
            <div class="link-card">
                <h3>🤖 模型列表</h3>
                <p>查看可用的AI模型列表及其详细信息。</p>
                <a href="/v1/models">查看模型</a>
            </div>
        </div>
        
        <div class="features">
            <h2>功能特性</h2>
            <div class="feature-list">
                <div class="feature-item">
                    <div>🔄</div>
                    <h3>OpenAI API兼容</h3>
                    <p>完全兼容OpenAI的API格式，无需修改客户端代码</p>
                </div>
                
                <div class="feature-item">
                    <div>🌊</div>
                    <h3>流式响应支持</h3>
                    <p>支持实时流式输出，提供更好的用户体验</p>
                </div>
                
                <div class="feature-item">
                    <div>🔐</div>
                    <h3>身份验证</h3>
                    <p>支持API密钥验证，确保服务安全</p>
                </div>
                
                <div class="feature-item">
                    <div>🛠️</div>
                    <h3>灵活配置</h3>
                    <p>通过环境变量进行灵活配置</p>
                </div>
                
                <div class="feature-item">
                    <div>📝</div>
                    <h3>思考过程展示</h3>
                    <p>智能处理并展示模型的思考过程</p>
                </div>
                
                <div class="feature-item">
                    <div>📊</div>
                    <h3>实时监控</h3>
                    <p>提供Web仪表板，实时显示API转发情况和统计信息</p>
                </div>
            </div>
        </div>
        
        <footer>
            <p>© 2024 ZtoApi. Powered by Deno & Z.ai GLM-4.6</p>
        </footer>
    </div>
</body>
</html>`;
}

async function handleIndex(request: Request): Promise<Response> {
  if (request.method !== "GET") {
    return new Response("Method not allowed", { status: 405 });
  }

  return new Response(getIndexHTML(), {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8"
    }
  });
}

async function handleOptions(request: Request): Promise<Response> {
  const headers = new Headers();
  setCORSHeaders(headers);

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 200, headers });
  }

  return new Response("Not Found", { status: 404, headers });
}

async function handleModels(request: Request): Promise<Response> {
  const headers = new Headers();
  setCORSHeaders(headers);

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 200, headers });
  }

  // 支持的模型
  const models = SUPPORTED_MODELS.map(model => ({
    id: model.name,
    object: "model",
    created: Math.floor(Date.now() / 1000),
    owned_by: "z.ai"
  }));

  const response: ModelsResponse = {
    object: "list",
    data: models
  };

  headers.set("Content-Type", "application/json");
  return new Response(JSON.stringify(response), {
    status: 200,
    headers
  });
}

async function handleChatCompletions(request: Request): Promise<Response> {
  const startTime = Date.now();
  const url = new URL(request.url);
  const path = url.pathname;
  const userAgent = request.headers.get("User-Agent") || "";

  debugLog("收到chat completions请求");
  debugLog("🌐 User-Agent: %s", userAgent);

  // Cherry Studio 检测
  const isCherryStudio = userAgent.toLowerCase().includes('cherry') || userAgent.toLowerCase().includes('studio');
  if (isCherryStudio) {
    debugLog("🍒 检测到 Cherry Studio 客户端版本: %s",
      userAgent.match(/CherryStudio\/([^\s]+)/)?.[1] || 'unknown');
  }

  const headers = new Headers();
  setCORSHeaders(headers);

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 200, headers });
  }

  // 验证API Key
  const authHeader = request.headers.get("Authorization");
  if (!validateApiKey(authHeader)) {
    debugLog("缺少或无效的Authorization头");
    const duration = Date.now() - startTime;
    recordRequestStats(startTime, path, 401);
    addLiveRequest(request.method, path, 401, duration, userAgent);
    return new Response("Missing or invalid Authorization header", {
      status: 401,
      headers
    });
  }

  debugLog("API key验证通过");

  // 读取请求体
  let body: string;
  try {
    body = await request.text();
    debugLog("📥 收到请求体长度: %d 字符", body.length);

    // 为Cherry Studio调试：记录原始请求体（截取前1000字符避免日志过长）
    const bodyPreview = body.length > 1000 ? body.substring(0, 1000) + "..." : body;
    debugLog("📄 请求体预览: %s", bodyPreview);
  } catch (error) {
    debugLog("读取请求体失败: %v", error);
    const duration = Date.now() - startTime;
    recordRequestStats(startTime, path, 400);
    addLiveRequest(request.method, path, 400, duration, userAgent);
    return new Response("Failed to read request body", {
      status: 400,
      headers
    });
  }

  // 解析请求
  let req: OpenAIRequest;
  try {
    req = JSON.parse(body) as OpenAIRequest;
    debugLog("✅ JSON解析成功");
  } catch (error) {
    debugLog("JSON解析失败: %v", error);
    const duration = Date.now() - startTime;
    recordRequestStats(startTime, path, 400);
    addLiveRequest(request.method, path, 400, duration, userAgent);
    return new Response("Invalid JSON", {
      status: 400,
      headers
    });
  }

  // 如果客户端没有明确指定stream参数，使用默认值
  if (!body.includes('"stream"')) {
    req.stream = DEFAULT_STREAM;
    debugLog("客户端未指定stream参数，使用默认值: %v", DEFAULT_STREAM);
  }

  // 获取模型配置
  const modelConfig = getModelConfig(req.model);
  debugLog("请求解析成功 - 模型: %s (%s), 流式: %v, 消息数: %d", req.model, modelConfig.name, req.stream, req.messages.length);

  // Cherry Studio 调试：详细检查每条消息
  debugLog("🔍 Cherry Studio 调试 - 检查原始消息:");
  for (let i = 0; i < req.messages.length; i++) {
    const msg = req.messages[i];
    debugLog("  消息[%d] role: %s", i, msg.role);

    if (typeof msg.content === 'string') {
      debugLog("  消息[%d] content: 字符串类型, 长度: %d", i, msg.content.length);
      if (msg.content.length === 0) {
        debugLog("  ⚠️  消息[%d] 内容为空字符串!", i);
      } else {
        debugLog("  消息[%d] 内容预览: %s", i, msg.content.substring(0, 100));
      }
    } else if (Array.isArray(msg.content)) {
      debugLog("  消息[%d] content: 数组类型, 块数: %d", i, msg.content.length);
      for (let j = 0; j < msg.content.length; j++) {
        const block = msg.content[j];
        debugLog("    块[%d] type: %s", j, block.type);
        if (block.type === 'text' && block.text) {
          debugLog("    块[%d] text: %s", j, block.text.substring(0, 50));
        } else if (block.type === 'image_url' && block.image_url?.url) {
          debugLog("    块[%d] image_url: %s格式, 长度: %d", j,
            block.image_url.url.startsWith('data:') ? 'base64' : 'url',
            block.image_url.url.length);
        }
      }
    } else {
      debugLog("  ⚠️  消息[%d] content 类型异常: %s", i, typeof msg.content);
    }
  }

  // 处理和验证消息（特别是多模态内容）
  const processedMessages = processMessages(req.messages, modelConfig);
  debugLog("消息处理完成，处理后消息数: %d", processedMessages.length);

  // 检查是否包含多模态内容
  const hasMultimodal = processedMessages.some(msg =>
    Array.isArray(msg.content) &&
    msg.content.some(block =>
      ['image_url', 'video_url', 'document_url', 'audio_url'].includes(block.type)
    )
  );

  if (hasMultimodal) {
    debugLog("🎯 检测到全方位多模态请求，模型: %s", modelConfig.name);
    if (!modelConfig.capabilities.vision) {
      debugLog("❌ 严重错误: 模型不支持多模态，但收到了多媒体内容！");
      debugLog("💡 Cherry Studio用户请检查: 确认选择了 'GLM-4.5v' 而不是 'GLM-4.6'");
      debugLog("🔧 模型映射状态: %s → %s (vision: %s)",
        req.model, modelConfig.upstreamId, modelConfig.capabilities.vision);
    } else {
      debugLog("✅ GLM-4.5v支持全方位多模态理解：图像、视频、文档、音频");

      // 检查是否使用匿名token（多模态功能的重要限制）
      if (!ZAI_TOKEN || ZAI_TOKEN.trim() === "") {
        debugLog("⚠️ 重要警告: 正在使用匿名token处理多模态请求");
        debugLog("💡 Z.ai的匿名token可能不支持图像/视频/文档处理");
        debugLog("🔧 解决方案: 设置 ZAI_TOKEN 环境变量为正式的API Token");
        debugLog("📋 如果请求失败，这很可能是token权限问题");
      } else {
        debugLog("✅ 使用正式API Token，支持完整多模态功能");
      }
    }
  } else if (modelConfig.capabilities.vision && modelConfig.id === 'GLM-4.5v') {
    debugLog("ℹ️ 使用GLM-4.5v模型但未检测到多媒体数据，仅处理文本内容");
  }

  // 生成会话相关ID
  const chatID = `${Date.now()}-${Math.floor(Date.now() / 1000)}`;
  const msgID = Date.now().toString();

  // 构造上游请求
  const upstreamReq: UpstreamRequest = {
    stream: true, // 总是使用流式从上游获取
    chat_id: chatID,
    id: msgID,
    model: modelConfig.upstreamId,
    messages: processedMessages,
    signature_prompt: SIGNATURE_PROMPT,
    params: modelConfig.defaultParams,
    features: {
      enable_thinking: modelConfig.capabilities.thinking,
      image_generation: false,
      web_search: false,
      auto_web_search: false,
      preview_mode: modelConfig.capabilities.vision
    },
    background_tasks: {
      title_generation: false,
      tags_generation: false
    },
    mcp_servers: modelConfig.capabilities.mcp ? [] : undefined,
    model_item: {
      id: modelConfig.upstreamId,
      name: modelConfig.name,
      owned_by: "openai",
      openai: {
        id: modelConfig.upstreamId,
        name: modelConfig.upstreamId,
        owned_by: "openai",
        openai: {
          id: modelConfig.upstreamId
        },
        urlIdx: 1
      },
      urlIdx: 1,
      info: {
        id: modelConfig.upstreamId,
        user_id: "api-user",
        base_model_id: null,
        name: modelConfig.name,
        params: modelConfig.defaultParams,
        meta: {
          profile_image_url: "/static/favicon.png",
          description: modelConfig.capabilities.vision ? "Advanced visual understanding and analysis" : "Most advanced model, proficient in coding and tool use",
          capabilities: {
            vision: modelConfig.capabilities.vision,
            citations: false,
            preview_mode: modelConfig.capabilities.vision,
            web_search: false,
            language_detection: false,
            restore_n_source: false,
            mcp: modelConfig.capabilities.mcp,
            file_qa: modelConfig.capabilities.mcp,
            returnFc: true,
            returnThink: modelConfig.capabilities.thinking,
            think: modelConfig.capabilities.thinking
          }
        }
      }
    },
    tool_servers: [],
    variables: {
      "{{USER_NAME}}": `Guest-${Date.now()}`,
      "{{USER_LOCATION}}": "Unknown",
      "{{CURRENT_DATETIME}}": new Date().toLocaleString('zh-CN'),
      "{{CURRENT_DATE}}": new Date().toLocaleDateString('zh-CN'),
      "{{CURRENT_TIME}}": new Date().toLocaleTimeString('zh-CN'),
      "{{CURRENT_WEEKDAY}}": new Date().toLocaleDateString('zh-CN', { weekday: 'long' }),
      "{{CURRENT_TIMEZONE}}": "Asia/Shanghai",
      "{{USER_LANGUAGE}}": "zh-CN"
    }
  };

  // 选择本次对话使用的token
  let authToken = ZAI_TOKEN;
  if (ANON_TOKEN_ENABLED) {
    try {
      const anonToken = await getAnonymousToken();
      authToken = anonToken;
      // debugLog("匿名token获取成功: %s...", anonToken.substring(0, 10));
      debugLog("=============================================");
      debugLog("匿名token获取成功: %s", anonToken);
      debugLog("=============================================");
    } catch (error) {
      debugLog("匿名token获取失败，回退固定token: %v", error);
    }
  }

  // 调用上游API
  try {
    if (req.stream) {
      return await handleStreamResponse(upstreamReq, chatID, authToken, startTime, path, userAgent, req, modelConfig);
    } else {
      return await handleNonStreamResponse(upstreamReq, chatID, authToken, startTime, path, userAgent, req, modelConfig);
    }
  } catch (error) {
    debugLog("调用上游失败: %v", error);
    const duration = Date.now() - startTime;
    recordRequestStats(startTime, path, 502);
    addLiveRequest(request.method, path, 502, duration, userAgent);
    return new Response("Failed to call upstream", {
      status: 502,
      headers
    });
  }
}

async function handleStreamResponse(
  upstreamReq: UpstreamRequest,
  chatID: string,
  authToken: string,
  startTime: number,
  path: string,
  userAgent: string,
  req: OpenAIRequest,
  modelConfig: ModelConfig
): Promise<Response> {
  debugLog("开始处理流式响应 (chat_id=%s)", chatID);

  try {
    const response = await callUpstreamWithHeaders(upstreamReq, chatID, authToken);

    if (!response.ok) {
      debugLog("上游返回错误状态: %d", response.status);
      const duration = Date.now() - startTime;
      recordRequestStats(startTime, path, 502);
      addLiveRequest("POST", path, 502, duration, userAgent);
      return new Response("Upstream error", { status: 502 });
    }

    if (!response.body) {
      debugLog("上游响应体为空");
      const duration = Date.now() - startTime;
      recordRequestStats(startTime, path, 502);
      addLiveRequest("POST", path, 502, duration, userAgent);
      return new Response("Upstream response body is empty", { status: 502 });
    }

    // 创建可读流
    const { readable, writable } = new TransformStream();
    const writer = writable.getWriter();
    const encoder = new TextEncoder();

    // 发送第一个chunk（role）
    const firstChunk: OpenAIResponse = {
      id: `chatcmpl-${Date.now()}`,
      object: "chat.completion.chunk",
      created: Math.floor(Date.now() / 1000),
      model: req.model,
      choices: [
        {
          index: 0,
          delta: { role: "assistant" }
        }
      ]
    };

    // 写入第一个chunk
    writer.write(encoder.encode(`data: ${JSON.stringify(firstChunk)}\n\n`));

    // 处理上游SSE流
    processUpstreamStream(response.body, writer, encoder, req.model).catch(error => {
      debugLog("处理上游流时出错: %v", error);
    });

    // 记录成功请求统计
    const duration = Date.now() - startTime;
    recordRequestStats(startTime, path, 200);
    addLiveRequest("POST", path, 200, duration, userAgent, modelConfig.name);

    return new Response(readable, {
      status: 200,
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Credentials": "true"
      }
    });
  } catch (error) {
    debugLog("处理流式响应时出错: %v", error);
    const duration = Date.now() - startTime;
    recordRequestStats(startTime, path, 502);
    addLiveRequest("POST", path, 502, duration, userAgent);
    return new Response("Failed to process stream response", { status: 502 });
  }
}

async function handleNonStreamResponse(
  upstreamReq: UpstreamRequest,
  chatID: string,
  authToken: string,
  startTime: number,
  path: string,
  userAgent: string,
  req: OpenAIRequest,
  modelConfig: ModelConfig
): Promise<Response> {
  debugLog("开始处理非流式响应 (chat_id=%s)", chatID);

  try {
    const response = await callUpstreamWithHeaders(upstreamReq, chatID, authToken);

    if (!response.ok) {
      debugLog("上游返回错误状态: %d", response.status);
      const duration = Date.now() - startTime;
      recordRequestStats(startTime, path, 502);
      addLiveRequest("POST", path, 502, duration, userAgent);
      return new Response("Upstream error", { status: 502 });
    }

    if (!response.body) {
      debugLog("上游响应体为空");
      const duration = Date.now() - startTime;
      recordRequestStats(startTime, path, 502);
      addLiveRequest("POST", path, 502, duration, userAgent);
      return new Response("Upstream response body is empty", { status: 502 });
    }

    // 收集完整响应
    const finalContent = await collectFullResponse(response.body);
    debugLog("内容收集完成，最终长度: %d", finalContent.length);

    // 构造完整响应
    const openAIResponse: OpenAIResponse = {
      id: `chatcmpl-${Date.now()}`,
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model: req.model,
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content: finalContent
          },
          finish_reason: "stop"
        }
      ],
      usage: {
        prompt_tokens: 0,
        completion_tokens: 0,
        total_tokens: 0
      }
    };

    // 记录成功请求统计
    const duration = Date.now() - startTime;
    recordRequestStats(startTime, path, 200);
    addLiveRequest("POST", path, 200, duration, userAgent, modelConfig.name);

    return new Response(JSON.stringify(openAIResponse), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Credentials": "true"
      }
    });
  } catch (error) {
    debugLog("处理非流式响应时出错: %v", error);
    const duration = Date.now() - startTime;
    recordRequestStats(startTime, path, 502);
    addLiveRequest("POST", path, 502, duration, userAgent);
    return new Response("Failed to process non-stream response", { status: 502 });
  }
}

/**
 * 生成 Dashboard 监控页面HTML模板
 * 提供实时API调用监控和统计信息展示  
 * @returns string 完整的HTML页面内容
 */
function getDashboardHTML(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API调用看板</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 20px;
        }
        h1 {
            color: #333;
            text-align: center;
            margin-bottom: 30px;
        }
        .stats-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background-color: #f8f9fa;
            border-radius: 6px;
            padding: 15px;
            text-align: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: #007bff;
        }
        .stat-label {
            font-size: 14px;
            color: #6c757d;
            margin-top: 5px;
        }
        .requests-container {
            margin-top: 30px;
        }
        .requests-table {
            width: 100%;
            border-collapse: collapse;
        }
        .requests-table th, .requests-table td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        .requests-table th {
            background-color: #f8f9fa;
        }
        .status-success {
            color: #28a745;
        }
        .status-error {
            color: #dc3545;
        }
        .refresh-info {
            text-align: center;
            margin-top: 20px;
            color: #6c757d;
            font-size: 14px;
        }
        .pagination-container {
            display: flex;
            justify-content: center;
            align-items: center;
            margin-top: 20px;
            gap: 10px;
        }
        .pagination-container button {
            padding: 5px 10px;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        .pagination-container button:disabled {
            background-color: #cccccc;
            cursor: not-allowed;
        }
        .pagination-container button:hover:not(:disabled) {
            background-color: #0056b3;
        }
        .chart-container {
            margin-top: 30px;
            height: 300px;
            background-color: #f8f9fa;
            border-radius: 6px;
            padding: 15px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>API调用看板</h1>
        
        <div class="stats-container">
            <div class="stat-card">
                <div class="stat-value" id="total-requests">0</div>
                <div class="stat-label">总请求数</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="successful-requests">0</div>
                <div class="stat-label">成功请求</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="failed-requests">0</div>
                <div class="stat-label">失败请求</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="avg-response-time">0s</div>
                <div class="stat-label">平均响应时间</div>
            </div>
        </div>
        
        <div class="chart-container">
            <h2>请求统计图表</h2>
            <canvas id="requestsChart"></canvas>
        </div>
        
        <div class="requests-container">
            <h2>实时请求</h2>
            <table class="requests-table">
                <thead>
                    <tr>
                        <th>时间</th>
                        <th>模型</th>
                        <th>方法</th>
                        <th>状态</th>
                        <th>耗时</th>
                        <th>User Agent</th>
                    </tr>
                </thead>
                <tbody id="requests-tbody">
                    <!-- 请求记录将通过JavaScript动态添加 -->
                </tbody>
            </table>
            <div class="pagination-container">
                <button id="prev-page" disabled>上一页</button>
                <span id="page-info">第 1 页，共 1 页</span>
                <button id="next-page" disabled>下一页</button>
            </div>
        </div>
        
        <div class="refresh-info">
            数据每5秒自动刷新一次
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        // 全局变量
        let allRequests = [];
        let currentPage = 1;
        const itemsPerPage = 10;
        let requestsChart = null;
        
        // 更新统计数据
        function updateStats() {
            fetch('/dashboard/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('total-requests').textContent = data.totalRequests || 0;
                    document.getElementById('successful-requests').textContent = data.successfulRequests || 0;
                    document.getElementById('failed-requests').textContent = data.failedRequests || 0;
                    document.getElementById('avg-response-time').textContent = ((data.averageResponseTime || 0) / 1000).toFixed(2) + 's';
                })
                .catch(error => console.error('Error fetching stats:', error));
        }
        
        // 更新请求列表
        function updateRequests() {
            fetch('/dashboard/requests')
                .then(response => response.json())
                .then(data => {
                    // 检查数据是否为数组
                    if (!Array.isArray(data)) {
                        console.error('返回的数据不是数组:', data);
                        return;
                    }
                    
                    // 保存所有请求数据
                    allRequests = data;
                    
                    // 按时间倒序排列
                    allRequests.sort((a, b) => {
                        const timeA = new Date(a.timestamp);
                        const timeB = new Date(b.timestamp);
                        return timeB - timeA;
                    });
                    
                    // 更新表格
                    updateTable();
                    
                    // 更新图表
                    updateChart();
                    
                    // 更新分页信息
                    updatePagination();
                })
                .catch(error => console.error('Error fetching requests:', error));
        }
        
        // 更新表格显示
        function updateTable() {
            const tbody = document.getElementById('requests-tbody');
            tbody.innerHTML = '';
            
            // 计算当前页的数据范围
            const startIndex = (currentPage - 1) * itemsPerPage;
            const endIndex = startIndex + itemsPerPage;
            const currentRequests = allRequests.slice(startIndex, endIndex);
            
            currentRequests.forEach(request => {
                const row = document.createElement('tr');
                
                // 格式化时间 - 检查时间戳是否有效
                let timeStr = "Invalid Date";
                if (request.timestamp) {
                    try {
                        const time = new Date(request.timestamp);
                        if (!isNaN(time.getTime())) {
                            timeStr = time.toLocaleTimeString();
                        }
                    } catch (e) {
                        console.error("时间格式化错误:", e);
                    }
                }
                
                // 判断模型名称
                let modelName = "GLM-4.6";
                if (request.path && request.path.includes('GLM-4.5v')) {
                    modelName = "GLM-4.5v";
                } else if (request.model) {
                    modelName = request.model;
                }
                
                // 状态样式
                const statusClass = request.status >= 200 && request.status < 300 ? 'status-success' : 'status-error';
                const status = request.status || "undefined";
                
                // 截断 User Agent，避免过长
                let userAgent = request.user_agent || "undefined";
                if (userAgent.length > 30) {
                    userAgent = userAgent.substring(0, 30) + "...";
                }
                
                row.innerHTML = "<td>" + timeStr + "</td>" + "<td>" + modelName + "</td>" + "<td>" + (request.method || "undefined") + "</td>" + "<td class='" + statusClass + "'>" + status + "</td>" + "<td>" + ((request.duration / 1000).toFixed(2) || "undefined") + "s</td>" + "<td title='" + (request.user_agent || "") + "'>" + userAgent + "</td>";
                
                tbody.appendChild(row);
            });
        }
        
        // 更新分页信息
        function updatePagination() {
            const totalPages = Math.ceil(allRequests.length / itemsPerPage);
            document.getElementById('page-info').textContent = "第 " + currentPage + " 页，共 " + totalPages + " 页";
            
            document.getElementById('prev-page').disabled = currentPage <= 1;
            document.getElementById('next-page').disabled = currentPage >= totalPages;
        }
        
        // 更新图表
        function updateChart() {
            const ctx = document.getElementById('requestsChart').getContext('2d');
            
            // 准备图表数据 - 最近20条请求的响应时间
            const chartData = allRequests.slice(0, 20).reverse();
            const labels = chartData.map(req => {
                const time = new Date(req.timestamp);
                return time.toLocaleTimeString();
            });
            const responseTimes = chartData.map(req => req.duration);
            
            // 如果图表已存在，先销毁
            if (requestsChart) {
                requestsChart.destroy();
            }
            
            // 创建新图表
            requestsChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        label: '响应时间 (s)',
                        data: responseTimes.map(time => time / 1000),
                        borderColor: '#007bff',
                        backgroundColor: 'rgba(0, 123, 255, 0.1)',
                        tension: 0.1,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: '响应时间 (s)'
                            }
                        },
                        x: {
                            title: {
                                display: true,
                                text: '时间'
                            }
                        }
                    },
                    plugins: {
                        title: {
                            display: true,
                            text: '最近20条请求的响应时间趋势 (s)'
                        }
                    }
                }
            });
        }
        
        // 分页按钮事件
        document.getElementById('prev-page').addEventListener('click', function() {
            if (currentPage > 1) {
                currentPage--;
                updateTable();
                updatePagination();
            }
        });
        
        document.getElementById('next-page').addEventListener('click', function() {
            const totalPages = Math.ceil(allRequests.length / itemsPerPage);
            if (currentPage < totalPages) {
                currentPage++;
                updateTable();
                updatePagination();
            }
        });
        
        // 初始加载
        updateStats();
        updateRequests();
        
        // 定时刷新
        setInterval(updateStats, 5000);
        setInterval(updateRequests, 5000);
    </script>
</body>
</html>`;
}

/**
 * 处理 Dashboard 监控页面请求
 * 返回实时监控面板的HTML页面
 * @param request HTTP请求对象
 * @returns Promise<Response> HTML响应
 */
async function handleDashboard(request: Request): Promise<Response> {
  if (request.method !== "GET") {
    return new Response("Method not allowed", { status: 405 });
  }

  return new Response(getDashboardHTML(), {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8"
    }
  });
}

// 处理Dashboard统计数据
async function handleDashboardStats(request: Request): Promise<Response> {
  return new Response(getStatsData(), {
    status: 200,
    headers: {
      "Content-Type": "application/json"
    }
  });
}

async function handleDashboardRequests(request: Request): Promise<Response> {
  return new Response(getLiveRequestsData(), {
    status: 200,
    headers: {
      "Content-Type": "application/json"
    }
  });
}


function getDocsHTML(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ZtoApi 文档</title>
<style>
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        margin: 0;
        padding: 20px;
        background-color: #f5f5f5;
        line-height: 1.6;
    }
    .container {
        max-width: 1200px;
        margin: 0 auto;
        background-color: white;
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        padding: 30px;
    }
    h1 {
        color: #333;
        text-align: center;
        margin-bottom: 30px;
        border-bottom: 2px solid #007bff;
        padding-bottom: 10px;
    }
    h2 {
        color: #007bff;
        margin-top: 30px;
        margin-bottom: 15px;
    }
    h3 {
        color: #333;
        margin-top: 25px;
        margin-bottom: 10px;
    }
    .endpoint {
        background-color: #f8f9fa;
        border-radius: 6px;
        padding: 15px;
        margin-bottom: 20px;
        border-left: 4px solid #007bff;
    }
    .method {
        display: inline-block;
        padding: 4px 8px;
        border-radius: 4px;
        color: white;
        font-weight: bold;
        margin-right: 10px;
        font-size: 14px;
    }
    .get { background-color: #28a745; }
    .post { background-color: #007bff; }
    .path {
        font-family: monospace;
        background-color: #e9ecef;
        padding: 2px 6px;
        border-radius: 3px;
        font-size: 16px;
    }
    .description {
        margin: 15px 0;
    }
    .parameters {
        margin: 15px 0;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        margin: 15px 0;
    }
    th, td {
        padding: 10px;
        text-align: left;
        border-bottom: 1px solid #ddd;
    }
    th {
        background-color: #f8f9fa;
        font-weight: bold;
    }
    .example {
        background-color: #f8f9fa;
        border-radius: 6px;
        padding: 15px;
        margin: 15px 0;
        font-family: monospace;
        white-space: pre-wrap;
        overflow-x: auto;
    }
    .note {
        background-color: #fff3cd;
        border-left: 4px solid #ffc107;
        padding: 10px 15px;
        margin: 15px 0;
        border-radius: 0 4px 4px 0;
    }
    .response {
        background-color: #f8f9fa;
        border-radius: 6px;
        padding: 15px;
        margin: 15px 0;
        font-family: monospace;
        white-space: pre-wrap;
        overflow-x: auto;
    }
    .tab {
        overflow: hidden;
        border: 1px solid #ccc;
        background-color: #f1f1f1;
        border-radius: 4px 4px 0 0;
    }
    .tab button {
        background-color: inherit;
        float: left;
        border: none;
        outline: none;
        cursor: pointer;
        padding: 14px 16px;
        transition: 0.3s;
        font-size: 16px;
    }
    .tab button:hover {
        background-color: #ddd;
    }
    .tab button.active {
        background-color: #ccc;
    }
    .tabcontent {
        display: none;
        padding: 6px 12px;
        border: 1px solid #ccc;
        border-top: none;
        border-radius: 0 0 4px 4px;
    }
    .toc {
        background-color: #f8f9fa;
        border-radius: 6px;
        padding: 15px;
        margin-bottom: 20px;
    }
    .toc ul {
        padding-left: 20px;
    }
    .toc li {
        margin: 5px 0;
    }
    .toc a {
        color: #007bff;
        text-decoration: none;
    }
    .toc a:hover {
        text-decoration: underline;
    }
</style>
</head>
<body>
<div class="container">
    <h1>ZtoApi 文档</h1>
    
    <div class="toc">
        <h2>目录</h2>
        <ul>
            <li><a href="#overview">概述</a></li>
            <li><a href="#authentication">身份验证</a></li>
            <li><a href="#endpoints">API端点</a>
                <ul>
                    <li><a href="#models">获取模型列表</a></li>
                    <li><a href="#chat-completions">聊天完成</a></li>
                </ul>
            </li>
            <li><a href="#examples">使用示例</a></li>
            <li><a href="#error-handling">错误处理</a></li>
        </ul>
    </div>
    
    <section id="overview">
        <h2>概述</h2>
        <p>这是一个为Z.ai GLM-4.6模型提供OpenAI兼容API接口的代理服务器。它允许你使用标准的OpenAI API格式与Z.ai的GLM-4.6模型进行交互，支持流式和非流式响应。</p>
        <p><strong>基础URL:</strong> <code>http://localhost:9090/v1</code></p>
        <div class="note">
            <strong>注意:</strong> 默认端口为9090，可以通过环境变量PORT进行修改。
        </div>
    </section>
    
    <section id="authentication">
        <h2>身份验证</h2>
        <p>所有API请求都需要在请求头中包含有效的API密钥进行身份验证：</p>
        <div class="example">
Authorization: Bearer your-api-key</div>
        <p>默认的API密钥为 <code>sk-your-key</code>，可以通过环境变量 <code>DEFAULT_KEY</code> 进行修改。</p>
    </section>
    
    <section id="endpoints">
        <h2>API端点</h2>
        
        <div class="endpoint" id="models">
            <h3>获取模型列表</h3>
            <div>
                <span class="method get">GET</span>
                <span class="path">/v1/models</span>
            </div>
            <div class="description">
                <p>获取可用模型列表。</p>
            </div>
            <div class="parameters">
                <h4>请求参数</h4>
                <p>无</p>
            </div>
            <div class="response">
{
  "object": "list",
  "data": [
    {
      "id": "GLM-4.6",
      "object": "model",
      "created": 1756788845,
      "owned_by": "z.ai"
    }
  ]
}</div>
        </div>
        
        <div class="endpoint" id="chat-completions">
            <h3>聊天完成</h3>
            <div>
                <span class="method post">POST</span>
                <span class="path">/v1/chat/completions</span>
            </div>
            <div class="description">
                <p>基于消息列表生成模型响应。支持流式和非流式两种模式。</p>
            </div>
            <div class="parameters">
                <h4>请求参数</h4>
                <table>
                    <thead>
                        <tr>
                            <th>参数名</th>
                            <th>类型</th>
                            <th>必需</th>
                            <th>说明</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>model</td>
                            <td>string</td>
                            <td>是</td>
                            <td>要使用的模型ID，例如 "GLM-4.6"</td>
                        </tr>
                        <tr>
                            <td>messages</td>
                            <td>array</td>
                            <td>是</td>
                            <td>消息列表，包含角色和内容</td>
                        </tr>
                        <tr>
                            <td>stream</td>
                            <td>boolean</td>
                            <td>否</td>
                            <td>是否使用流式响应，默认为true</td>
                        </tr>
                        <tr>
                            <td>temperature</td>
                            <td>number</td>
                            <td>否</td>
                            <td>采样温度，控制随机性</td>
                        </tr>
                        <tr>
                            <td>max_tokens</td>
                            <td>integer</td>
                            <td>否</td>
                            <td>生成的最大令牌数</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            <div class="parameters">
                <h4>消息格式</h4>
                <table>
                    <thead>
                        <tr>
                            <th>字段</th>
                            <th>类型</th>
                            <th>说明</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>role</td>
                            <td>string</td>
                            <td>消息角色，可选值：system、user、assistant</td>
                        </tr>
                        <tr>
                            <td>content</td>
                            <td>string</td>
                            <td>消息内容</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </section>
    
    <section id="examples">
        <h2>使用示例</h2>
        
        <div class="tab">
            <button class="tablinks active" onclick="openTab(event, 'python-tab')">Python</button>
            <button class="tablinks" onclick="openTab(event, 'curl-tab')">cURL</button>
            <button class="tablinks" onclick="openTab(event, 'javascript-tab')">JavaScript</button>
        </div>
        
        <div id="python-tab" class="tabcontent" style="display: block;">
            <h3>Python示例</h3>
            <div class="example">
import openai

# 配置客户端
client = openai.OpenAI(
api_key="your-api-key",  # 对应 DEFAULT_KEY
base_url="http://localhost:9090/v1"
)

# 非流式请求 - 使用GLM-4.6
response = client.chat.completions.create(
model="GLM-4.6",
messages=[{"role": "user", "content": "你好，请介绍一下自己"}]
)

print(response.choices[0].message.content)


# 流式请求 - 使用GLM-4.6
response = client.chat.completions.create(
model="GLM-4.6",
messages=[{"role": "user", "content": "请写一首关于春天的诗"}],
stream=True
)


for chunk in response:
if chunk.choices[0].delta.content:
    print(chunk.choices[0].delta.content, end="")</div>
        </div>
        
        <div id="curl-tab" class="tabcontent">
            <h3>cURL示例</h3>
            <div class="example">
# 非流式请求
curl -X POST http://localhost:9090/v1/chat/completions \
-H "Content-Type: application/json" \
-H "Authorization: Bearer your-api-key" \
-d '{
"model": "GLM-4.6",
"messages": [{"role": "user", "content": "你好"}],
"stream": false
}'

# 流式请求
curl -X POST http://localhost:9090/v1/chat/completions \
-H "Content-Type: application/json" \
-H "Authorization: Bearer your-api-key" \
-d '{
"model": "GLM-4.6",
"messages": [{"role": "user", "content": "你好"}],
"stream": true
}'</div>
        </div>
        
        <div id="javascript-tab" class="tabcontent">
            <h3>JavaScript示例</h3>
            <div class="example">
const fetch = require('node-fetch');

async function chatWithGLM(message, stream = false) {
const response = await fetch('http://localhost:9090/v1/chat/completions', {
method: 'POST',
headers: {
  'Content-Type': 'application/json',
  'Authorization': 'Bearer your-api-key'
},
body: JSON.stringify({
  model: 'GLM-4.6',
  messages: [{ role: 'user', content: message }],
  stream: stream
})
});

if (stream) {
// 处理流式响应
const reader = response.body.getReader();
const decoder = new TextDecoder();

while (true) {
  const { done, value } = await reader.read();
  if (done) break;
  
  const chunk = decoder.decode(value);
  const lines = chunk.split('\n');
  
  for (const line of lines) {
    if (line.startsWith('data: ')) {
      const data = line.slice(6);
      if (data === '[DONE]') {
        console.log('\n流式响应完成');
        return;
      }
      
      try {
        const parsed = JSON.parse(data);
        const content = parsed.choices[0]?.delta?.content;
        if (content) {
          process.stdout.write(content);
        }
      } catch (e) {
        // 忽略解析错误
      }
    }
  }
}
} else {
// 处理非流式响应
const data = await response.json();
console.log(data.choices[0].message.content);
}
}

// 使用示例
chatWithGLM('你好，请介绍一下JavaScript', false);</div>
        </div>
    </section>
    
    <section id="error-handling">
        <h2>错误处理</h2>
        <p>API使用标准HTTP状态码来表示请求的成功或失败：</p>
        <table>
            <thead>
                <tr>
                    <th>状态码</th>
                    <th>说明</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>200 OK</td>
                    <td>请求成功</td>
                </tr>
                <tr>
                    <td>400 Bad Request</td>
                    <td>请求格式错误或参数无效</td>
                </tr>
                <tr>
                    <td>401 Unauthorized</td>
                    <td>API密钥无效或缺失</td>
                </tr>
                <tr>
                    <td>502 Bad Gateway</td>
                    <td>上游服务错误</td>
                </tr>
            </tbody>
        </table>
        <div class="note">
            <strong>注意:</strong> 在调试模式下，服务器会输出详细的日志信息，可以通过设置环境变量 DEBUG_MODE=true 来启用。
        </div>
    </section>
</div>

<script>
    function openTab(evt, tabName) {
        var i, tabcontent, tablinks;
        tabcontent = document.getElementsByClassName("tabcontent");
        for (i = 0; i < tabcontent.length; i++) {
            tabcontent[i].style.display = "none";
        }
        tablinks = document.getElementsByClassName("tablinks");
        for (i = 0; i < tablinks.length; i++) {
            tablinks[i].className = tablinks[i].className.replace(" active", "");
        }
        document.getElementById(tabName).style.display = "block";
        evt.currentTarget.className += " active";
    }
</script>
</body>
</html>`;
}

// 处理API文档页面
async function handleDocs(request: Request): Promise<Response> {
  if (request.method !== "GET") {
    return new Response("Method not allowed", { status: 405 });
  }

  return new Response(getDocsHTML(), {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8"
    }
  });
}

// 主HTTP服务器
async function main() {
  console.log(`OpenAI兼容API服务器启动`);
  console.log(`支持的模型: ${SUPPORTED_MODELS.map(m => `${m.id} (${m.name})`).join(', ')}`);
  console.log(`上游: ${UPSTREAM_URL}`);
  console.log(`Debug模式: ${DEBUG_MODE}`);
  console.log(`默认流式响应: ${DEFAULT_STREAM}`);
  console.log(`Dashboard启用: ${DASHBOARD_ENABLED}`);

  // 检测是否在Deno Deploy上运行
  const isDenoDeploy = Deno.env.get("DENO_DEPLOYMENT_ID") !== undefined;

  if (isDenoDeploy) {
    // Deno Deploy环境
    console.log("运行在Deno Deploy环境中");
    Deno.serve(handleRequest);
  } else {
    // 本地或自托管环境
    const port = parseInt(Deno.env.get("PORT") || "9090");
    console.log(`运行在本地环境中，端口: ${port}`);

    if (DASHBOARD_ENABLED) {
      console.log(`Dashboard已启用，访问地址: http://localhost:${port}/dashboard`);
    }

    const server = Deno.listen({ port });

    for await (const conn of server) {
      handleHttp(conn);
    }
  }
}

// 处理HTTP连接（用于本地环境）
async function handleHttp(conn: Deno.Conn) {
  const httpConn = Deno.serveHttp(conn);

  while (true) {
    const requestEvent = await httpConn.nextRequest();
    if (!requestEvent) break;

    const { request, respondWith } = requestEvent;
    const url = new URL(request.url);
    const startTime = Date.now();
    const userAgent = request.headers.get("User-Agent") || "";

    try {
      // 路由分发
      if (url.pathname === "/") {
        const response = await handleIndex(request);
        await respondWith(response);
        recordRequestStats(startTime, url.pathname, response.status);
        addLiveRequest(request.method, url.pathname, response.status, Date.now() - startTime, userAgent);
      } else if (url.pathname === "/v1/models") {
        const response = await handleModels(request);
        await respondWith(response);
        recordRequestStats(startTime, url.pathname, response.status);
        addLiveRequest(request.method, url.pathname, response.status, Date.now() - startTime, userAgent);
      } else if (url.pathname === "/v1/chat/completions") {
        const response = await handleChatCompletions(request);
        await respondWith(response);
        // 请求统计已在handleChatCompletions中记录
      } else if (url.pathname === "/docs") {
        const response = await handleDocs(request);
        await respondWith(response);
        recordRequestStats(startTime, url.pathname, response.status);
        addLiveRequest(request.method, url.pathname, response.status, Date.now() - startTime, userAgent);
      } else if (url.pathname === "/dashboard" && DASHBOARD_ENABLED) {
        const response = await handleDashboard(request);
        await respondWith(response);
        recordRequestStats(startTime, url.pathname, response.status);
        addLiveRequest(request.method, url.pathname, response.status, Date.now() - startTime, userAgent);
      } else if (url.pathname === "/dashboard/stats" && DASHBOARD_ENABLED) {
        const response = await handleDashboardStats(request);
        await respondWith(response);
        recordRequestStats(startTime, url.pathname, response.status);
        addLiveRequest(request.method, url.pathname, response.status, Date.now() - startTime, userAgent);
      } else if (url.pathname === "/dashboard/requests" && DASHBOARD_ENABLED) {
        const response = await handleDashboardRequests(request);
        await respondWith(response);
        recordRequestStats(startTime, url.pathname, response.status);
        addLiveRequest(request.method, url.pathname, response.status, Date.now() - startTime, userAgent);
      } else {
        const response = await handleOptions(request);
        await respondWith(response);
        recordRequestStats(startTime, url.pathname, response.status);
        addLiveRequest(request.method, url.pathname, response.status, Date.now() - startTime, userAgent);
      }
    } catch (error) {
      debugLog("处理请求时出错: %v", error);
      const response = new Response("Internal Server Error", { status: 500 });
      await respondWith(response);
      recordRequestStats(startTime, url.pathname, 500);
      addLiveRequest(request.method, url.pathname, 500, Date.now() - startTime, userAgent);
    }
  }
}

// 处理HTTP请求（用于Deno Deploy环境）
async function handleRequest(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const startTime = Date.now();
  const userAgent = request.headers.get("User-Agent") || "";

  try {
    // 路由分发
    if (url.pathname === "/") {
      const response = await handleIndex(request);
      recordRequestStats(startTime, url.pathname, response.status);
      addLiveRequest(request.method, url.pathname, response.status, Date.now() - startTime, userAgent);
      return response;
    } else if (url.pathname === "/v1/models") {
      const response = await handleModels(request);
      recordRequestStats(startTime, url.pathname, response.status);
      addLiveRequest(request.method, url.pathname, response.status, Date.now() - startTime, userAgent);
      return response;
    } else if (url.pathname === "/v1/chat/completions") {
      const response = await handleChatCompletions(request);
      // 请求统计已在handleChatCompletions中记录
      return response;
    } else if (url.pathname === "/docs") {
      const response = await handleDocs(request);
      recordRequestStats(startTime, url.pathname, response.status);
      addLiveRequest(request.method, url.pathname, response.status, Date.now() - startTime, userAgent);
      return response;
    } else if (url.pathname === "/dashboard" && DASHBOARD_ENABLED) {
      const response = await handleDashboard(request);
      recordRequestStats(startTime, url.pathname, response.status);
      addLiveRequest(request.method, url.pathname, response.status, Date.now() - startTime, userAgent);
      return response;
    } else if (url.pathname === "/dashboard/stats" && DASHBOARD_ENABLED) {
      const response = await handleDashboardStats(request);
      recordRequestStats(startTime, url.pathname, response.status);
      addLiveRequest(request.method, url.pathname, response.status, Date.now() - startTime, userAgent);
      return response;
    } else if (url.pathname === "/dashboard/requests" && DASHBOARD_ENABLED) {
      const response = await handleDashboardRequests(request);
      recordRequestStats(startTime, url.pathname, response.status);
      addLiveRequest(request.method, url.pathname, response.status, Date.now() - startTime, userAgent);
      return response;
    } else {
      const response = await handleOptions(request);
      recordRequestStats(startTime, url.pathname, response.status);
      addLiveRequest(request.method, url.pathname, response.status, Date.now() - startTime, userAgent);
      return response;
    }
  } catch (error) {
    debugLog("处理请求时出错: %v", error);
    recordRequestStats(startTime, url.pathname, 500);
    addLiveRequest(request.method, url.pathname, 500, Date.now() - startTime, userAgent);
    return new Response("Internal Server Error", { status: 500 });
  }
}

// 启动服务器
main();
