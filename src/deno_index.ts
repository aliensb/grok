import { serve } from "https://deno.land/std@0.202.0/http/server.ts";

const TARGET_URL = "https://grok.com";
const ORIGIN_DOMAIN = "grok.com"; // 注意：此处应仅为域名，不含协议
const SITE_PASSWORD = Deno.env.get("site_password");
const cookie = Deno.env.get("cookie");

async function handleWebSocket(req: Request): Promise<Response> {
  const { socket: clientWs, response } = Deno.upgradeWebSocket(req);

  const url = new URL(req.url);
  const targetUrl = `wss://grok.com${url.pathname}${url.search}`;

  console.log('Target URL:', targetUrl);

  const pendingMessages: string[] = [];
  const targetWs = new WebSocket(targetUrl);

  targetWs.onopen = () => {
    console.log('Connected to grok');
    pendingMessages.forEach(msg => targetWs.send(msg));
    pendingMessages.length = 0;
  };

  clientWs.onmessage = (event) => {
    console.log('Client message received');
    if (targetWs.readyState === WebSocket.OPEN) {
      targetWs.send(event.data);
    } else {
      pendingMessages.push(event.data);
    }
  };

  targetWs.onmessage = (event) => {
    console.log('message received');
    if (clientWs.readyState === WebSocket.OPEN) {
      clientWs.send(event.data);
    }
  };

  clientWs.onclose = (event) => {
    console.log('Client connection closed');
    if (targetWs.readyState === WebSocket.OPEN) {
      targetWs.close(1000, event.reason);
    }
  };

  targetWs.onclose = (event) => {
    console.log('connection closed');
    if (clientWs.readyState === WebSocket.OPEN) {
      clientWs.close(event.code, event.reason);
    }
  };

  targetWs.onerror = (error) => {
    console.error('WebSocket error:', error);
  };

  return response;
}

// 添加新的辅助函数
function getCookie(headers: Headers, name: string): string | null {
  const cookieHeader = headers.get('cookie');
  if (!cookieHeader) return null;
  
  const cookies = cookieHeader.split(';').map(c => c.trim());
  const cookie = cookies.find(c => c.startsWith(`${name}=`));
  return cookie ? cookie.split('=')[1] : null;
}

// 读取密码页面
const passwordPage = await Deno.readTextFile('./src/password_page.html');

const handler = async (req: Request): Promise<Response> => {
  const url = new URL(req.url);

  // 验证密码的端点
  if (url.pathname === '/verify-password' && req.method === 'POST') {
    try {
      const body = await req.json();
      if (body.password === SITE_PASSWORD) {
        const headers = new Headers();
        headers.set('Set-Cookie', `auth=${SITE_PASSWORD}; Path=/; HttpOnly; SameSite=Strict`);
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
  const authCookie = getCookie(req.headers, 'auth');
  if (authCookie !== SITE_PASSWORD) {
    // 如果未认证，返回密码页面
    if (url.pathname === '/') {
      return new Response(passwordPage, {
        headers: { 'Content-Type': 'text/html' },
      });
    }
    return new Response('Unauthorized', { status: 401 });
  }

  // WebSocket 处理
  if (req.headers.get("Upgrade")?.toLowerCase() === "websocket") {
    return handleWebSocket(req);
  }

  const targetUrl = new URL(url.pathname + url.search, TARGET_URL);

  // 构造代理请求
  const headers = new Headers(req.headers);
  headers.set("Host", targetUrl.host);
  headers.delete("Referer");
  headers.delete("Cookie");
  headers.set("cookie", cookie || '');

  try {
    const proxyResponse = await fetch(targetUrl.toString(), {
      method: req.method,
      headers,
      body: req.body,
      redirect: "manual",
    });

    // 处理响应头
    const responseHeaders = new Headers(proxyResponse.headers);
    responseHeaders.delete("Content-Length"); // 移除固定长度头
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
      transform: async (chunk, controller) => {
        const contentType = responseHeaders.get("Content-Type") || "";
        if (contentType.startsWith("text/") || contentType.includes("json")) {
          let text = new TextDecoder("utf-8", { stream: true }).decode(chunk);

          //   if(contentType.includes("json"))
          //   {
          //       if(text.includes("streamingImageGenerationResponse"))
          //       {
          //           text = text.replaceAll('users/','https://assets.grok.com/users/');
          //       }
          //   }

          controller.enqueue(
            new TextEncoder().encode(text.replaceAll(TARGET_URL, ORIGIN_DOMAIN))
          );
        } else {
          controller.enqueue(chunk);
        }
      }
    });

    // 创建可读流
    const readableStream = proxyResponse.body?.pipeThrough(transformStream);

    return new Response(readableStream, {
      status: proxyResponse.status,
      headers: responseHeaders,
    });
  } catch (error) {
    return new Response(`Proxy Error: ${error.message}`, { status: 500 });
  }
};

serve(handler, { port: 8000 });