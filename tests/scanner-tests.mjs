import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";

const root = path.resolve(new URL("..", import.meta.url).pathname);

function loadScanner(relativePath, extraContext = {}) {
  const filePath = path.join(root, relativePath);
  const code = fs.readFileSync(filePath, "utf8");
  const context = vm.createContext({
    console,
    URL,
    AbortSignal,
    setTimeout,
    clearTimeout,
    ...extraContext
  });
  vm.runInContext(code, context, { filename: relativePath });
  return context;
}

function headers(values) {
  const normalized = new Map(
    Object.entries(values).map(([key, value]) => [key.toLowerCase(), value])
  );
  return {
    forEach(callback) {
      for (const [key, value] of normalized.entries()) callback(value, key);
    },
    get(key) {
      return normalized.get(key.toLowerCase()) || null;
    }
  };
}

function response({ status = 200, headers: headerValues = {}, body = "" } = {}) {
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: headers(headerValues),
    async text() {
      return body;
    }
  };
}

async function testHeaderScanner() {
  const context = loadScanner("scanner/headerScanner.js", {
    fetch: async () => response({
      headers: {
        "x-powered-by": "Express",
        "server": "nginx/1.25.1",
        "access-control-allow-origin": "*"
      }
    })
  });

  const result = await context.runHeaderScan("https://example.com");
  const ids = result.issues.map(issue => issue.id);

  assert.equal(result.techStack, "Node.js / Express, Nginx");
  assert.ok(ids.includes("hsts-missing"));
  assert.ok(ids.includes("csp-missing"));
  assert.ok(ids.includes("cors-wildcard"));
  assert.ok(context.getHeaderCheckCount() > 0);
}

async function testEndpointScanner() {
  const context = loadScanner("scanner/endpointScanner.js", {
    fetch: async (url) => {
      const pathName = new URL(url).pathname;
      if (pathName === "/.env") {
        return response({
          headers: { "content-type": "text/plain" },
          body: "OPENAI_API_KEY=" + "sk" + "-test"
        });
      }
      if (pathName === "/admin") {
        return response({
          headers: { "content-type": "text/html" },
          body: "<h1>Login</h1>"
        });
      }
      return response({ status: 404 });
    }
  });

  const result = await context.runEndpointScan("https://example.com", "Vercel");
  const envIssue = result.issues.find(issue => issue.id === "env-exposed");
  const adminIssue = result.issues.find(issue => issue.id === "admin-exposed");

  assert.equal(envIssue?.severity, "P0");
  assert.equal(adminIssue?.severity, "P2");
  assert.match(envIssue.fixPrompt, /Tech stack: Vercel/);
}

async function testCookieScanner() {
  const context = loadScanner("scanner/cookieScanner.js", {
    chrome: {
      cookies: {
        async getAll() {
          return [
            { name: "session_token", httpOnly: false, secure: false, sameSite: "unspecified" },
            { name: "analytics_id", httpOnly: false, secure: true, sameSite: "lax" }
          ];
        }
      }
    }
  });

  const result = await context.runCookieScan("https://example.com", "Next.js");
  const ids = result.issues.map(issue => issue.id);

  assert.ok(ids.includes("cookie-no-httponly"));
  assert.ok(ids.includes("cookie-no-secure"));
  assert.ok(ids.includes("cookie-no-samesite"));
  assert.match(result.issues[0].detail, /ses/);
}

async function testDomScanner() {
  const sameOriginBundle = "console.log('token', authToken); const token = localStorage.getItem('auth_token');";
  const fakeOpenAiProjectKey = "sk" + "-proj-" + "abcdefghijklmnopqrstuvwxyz1234567890";
  const fakeDocument = {
    documentElement: {
      innerHTML: `const exposed = '${fakeOpenAiProjectKey}';`
    },
    querySelectorAll(selector) {
      if (selector === "script:not([src])") {
        return [{ textContent: "document.write(userInput); eval(userInput);" }];
      }
      if (selector === "script[src]") {
        return [{
          getAttribute(name) {
            if (name === "src") return "/assets/app.js";
            if (name === "integrity") return null;
            return "";
          }
        }];
      }
      return [];
    }
  };

  const context = loadScanner("scanner/domScanner.js", {
    window: {
      location: {
        href: "https://example.com/app",
        origin: "https://example.com",
        hostname: "example.com"
      }
    },
    document: fakeDocument,
    localStorage: {
      auth_token: "redacted"
    },
    fetch: async () => response({
      headers: { "content-type": "application/javascript" },
      body: sameOriginBundle
    })
  });

  const issues = await context.runDomScan();
  const ids = issues.map(issue => issue.id);

  assert.ok(ids.some(id => id.startsWith("api-key-")));
  assert.ok(ids.includes("xss-innerhtml"));
  assert.ok(ids.includes("console-log-found"));
  assert.ok(ids.includes("localstorage-token"));
  assert.ok(ids.includes("eval-usage"));
}

await testHeaderScanner();
await testEndpointScanner();
await testCookieScanner();
await testDomScanner();

console.log("Scanner tests passed.");
