import { serve } from "https://deno.land/std@0.208.0/http/server.ts";

// 定义常量
const TARGET_URL = "https://grok.com";
const ORIGIN_DOMAIN = "grok.com"; // 用于替换时的域名部分
const SITE_PASSWORD = Deno.env.get("site_password") ?? "";
const COOKIE = Deno.env.get("cookie") ?? "";

// WebSocket 处理函数
async function handleWebSocket(req: Request): Promise<Response> {
  const { socket: clientWs, response } = Deno.upgradeWebSocket(req);

  const url = new URL(req.url);
  const targetUrl = `wss://grok.com${url.pathname}${url.search}`;

  console.log("Target URL:", targetUrl);

  const pendingMessages: string[] = [];
  const targetWs = new WebSocket(targetUrl);

  targetWs.onopen = () => {
    console.log("Connected to grok");
    pendingMessages.forEach((msg) => targetWs.send(msg));
    pendingMessages.length = 0;
  };

  clientWs.onmessage = (event) => {
    console.log("Client message received");
    if (targetWs.readyState === WebSocket.OPEN) {
      targetWs.send(event.data);
    } else {
      pendingMessages.push(event.data as string);
    }
  };

  targetWs.onmessage = (event) => {
    console.log("Message received");
    if (clientWs.readyState === WebSocket.OPEN) {
      clientWs.send(event.data);
    }
  };

  clientWs.onclose = (event) => {
    console.log("Client connection closed");
    if (targetWs.readyState === WebSocket.OPEN) {
      targetWs.close(1000, event.reason);
    }
  };

  targetWs.onclose = (event) => {
    console.log("Connection closed");
    if (clientWs.readyState === WebSocket.OPEN) {
      clientWs.close(event.code, event.reason);
    }
  };

  targetWs.onerror = (error) => {
    console.error("WebSocket error:", error);
  };

  return response;
}

// 获取 Cookie 的辅助函数
function getCookie(headers: Headers, name: string): string | null {
  const cookieHeader = headers.get("cookie");
  if (!cookieHeader) return null;

  const cookies = cookieHeader.split(";").map((c) => c.trim());
  const cookie = cookies.find((c) => c.startsWith(`${name}=`));
  return cookie ? cookie.split("=")[1] : null;
}

// 读取密码页面
const passwordPage = await Deno.readTextFile("./src/password_page.html");

// 主处理函数
const handler = async (req: Request): Promise<Response> => {
  const url = new URL(req.url);

  // 验证密码的端点
  if (url.pathname === "/verify-password" && req.method === "POST") {
    try {
      const body = (await req.json()) as { password?: string };
      if (body.password === SITE_PASSWORD) {
        const headers = new Headers();
        headers.set("Set-Cookie", `auth=${SITE_PASSWORD}; Path=/; HttpOnly; SameSite=Strict`);
        return new Response(JSON.stringify({ success: true }), {
          headers,
          status: 200,
        });
      }
      return new Response(JSON.stringify({ success: false }), { status: 401 });
    } catch (error) {
      return new Response(JSON.stringify({ success: false }), { status: 400 });
    }
  }

  // 检查认证状态
  const authCookie = getCookie(req.headers, "auth");
  if (authCookie !== SITE_PASSWORD) {
    if (url.pathname === "/") {
      return new Response(passwordPage, {
        headers: { "Content-Type": "text/html" },
      });
    }
    return new Response("Unauthorized", { status: 401 });
  }

  // WebSocket 处理
  if (req.headers.get("Upgrade")?.toLowerCase() === "websocket") {
    return handleWebSocket(req);
  }

  // 使用 TARGET_URL 作为基地址
  const targetUrl = new URL(url.pathname + url.search, TARGET_URL);

  // 构造代理请求
  const headers = new Headers(req.headers);
  headers.set("Host", targetUrl.host);
  headers.delete("Referer");
  headers.delete("Cookie");
  headers.set("cookie", COOKIE);

  try {
    const proxyResponse = await fetch(targetUrl.toString(), {
      method: req.method,
      headers,
      body: req.method === "GET" || req.method === "HEAD" ? null : req.body,
      redirect: "manual" as const,
    });

    // 处理响应头
    const responseHeaders = new Headers(proxyResponse.headers);
    responseHeaders.delete("Content-Length");
    const location = responseHeaders.get("Location");
    if (location) {
      responseHeaders.set("Location", location.replace(TARGET_URL, `https://${ORIGIN_DOMAIN}`));
    }

    // 处理无响应体状态码
    if ([204, 205, 304].includes(proxyResponse.status)) {
      return new Response(null, { status: proxyResponse.status, headers: responseHeaders });
    }

    // 创建流式转换器
    const transformStream = new TransformStream({
      start(controller) {
        (this as any).decoder = new TextDecoder("utf-8");
        (this as any).encoder = new TextEncoder();
      },
      transform(chunk: Uint8Array, controller: TransformStreamDefaultController) {
        const contentType = responseHeaders.get("Content-Type") || "";
        if (contentType.startsWith("text/") || contentType.includes("json")) {
          const decoder = (this as any).decoder as TextDecoder;
          const encoder = (this as any).encoder as TextEncoder;
          const text = decoder.decode(chunk, { stream: true });
          const transformedText = text.replaceAll(TARGET_URL, ORIGIN_DOMAIN);
          controller.enqueue(encoder.encode(transformedText));
        } else {
          controller.enqueue(chunk);
        }
      },
      flush(controller: TransformStreamDefaultController) {
        const decoder = (this as any).decoder as TextDecoder;
        const encoder = (this as any).encoder as TextEncoder;
        const remainingText = decoder.decode();
        if (remainingText) {
          const transformedText = remainingText.replaceAll(TARGET_URL, ORIGIN_DOMAIN);
          controller.enqueue(encoder.encode(transformedText));
        }
      },
    });

    const readableStream = proxyResponse.body?.pipeThrough(transformStream) ?? null;

    return new Response(readableStream, {
      status: proxyResponse.status,
      headers: responseHeaders,
    });
  } catch (error) {
    console.error("Proxy Error:", error);
    return new Response(`Proxy Error: ${(error as Error).message}`, { status: 500 });
  }
};

// 启动服务
serve(handler, { port: 8000 });