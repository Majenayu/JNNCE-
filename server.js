const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const path = require("path");
const fetch = (...args) => import("node-fetch").then(({ default: fetch }) => fetch(...args));
const cheerio = require("cheerio");
const http = require("http");
const https = require("https");
const PDFDocument = require("pdfkit");
const QuickChart = require("quickchart-js");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors({ origin: process.env.CORS_ORIGIN || "*" }));
app.use(express.static(path.join(__dirname)));

// Rate limiting to prevent abuse
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per IP
  message: { error: "Too many requests, please try again later" }
}));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, { retryWrites: true, w: "majority" })
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ MongoDB error:", err));

// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String
});
const User = mongoose.model("User", userSchema);

// Content Security Policy with nonce
app.use((req, res, next) => {
  const nonce = crypto.randomBytes(16).toString("base64");
  res.setHeader(
    "Content-Security-Policy",
    `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}' https://cdn.tailwindcss.com;`
  );
  res.locals.nonce = nonce;
  next();
});

// ------------------- AUTH ROUTES -------------------
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    if (!name || !email || !password) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ error: "Email already registered" });
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();
    res.json({ message: "Registration successful" });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Error registering user", details: err.message });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password) {
      return res.status(400).json({ error: "Missing email or password" });
    }
    const user = await User.findOne({ email });
    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const token = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.json({ message: "Login successful", token, redirect: "/ayu.html" });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Error logging in", details: err.message });
  }
});

// Middleware to verify JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Access token required" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid or expired token" });
    req.user = user;
    next();
  });
}

// Default routes
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/ayu.html", authenticateToken, (req, res) => res.sendFile(path.join(__dirname, "ayu.html")));

// ------------------- SECURITY SCANNER ROUTES -------------------
app.get("/scan/ssl", authenticateToken, async (req, res) => {
  let { url } = req.query;
  if (!url) return res.status(400).json({ error: "Missing ?url parameter" });
  url = url.replace(/^https?:\/\//, "").replace(/\/$/, "");

  async function poll(attempts = 0, maxAttempts = 10) {
    if (attempts >= maxAttempts) {
      return { error: "SSL Labs scan timed out after 10 attempts" };
    }
    const response = await fetch(`https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(url)}&all=done`);
    const data = await response.json();
    if (data.status !== "READY" && data.status !== "ERROR") {
      await new Promise(r => setTimeout(r, 5000));
      return poll(attempts + 1, maxAttempts);
    }
    return data;
  }

  try {
    const result = await poll();
    if (result.error) return res.status(500).json(result);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: "SSL Labs scan failed", details: err.message });
  }
});

app.get("/scan/headers", authenticateToken, async (req, res) => {
  let { url } = req.query;
  if (!url) return res.status(400).json({ error: "Missing ?url parameter" });
  if (!url.startsWith("http")) url = "https://" + url;
  try {
    const response = await fetch(url, { headers: { "User-Agent": "Mozilla/5.0" } });
    const headers = {};
    response.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });
    const importantHeaders = {
      "content-security-policy": headers["content-security-policy"] || "❌ Missing",
      "strict-transport-security": headers["strict-transport-security"] || "❌ Missing",
      "x-frame-options": headers["x-frame-options"] || "❌ Missing",
      "x-content-type-options": headers["x-content-type-options"] || "❌ Missing",
      "referrer-policy": headers["referrer-policy"] || "❌ Missing",
      "permissions-policy": headers["permissions-policy"] || "❌ Missing"
    };
    res.json(importantHeaders);
  } catch (err) {
    res.status(500).json({ error: "Header fetch failed", details: err.message });
  }
});

app.get("/scan/libs", authenticateToken, async (req, res) => {
  let { url } = req.query;
  if (!url) return res.status(400).json({ error: "Missing ?url parameter" });
  if (!url.startsWith("http")) url = "https://" + url;
  try {
    const response = await fetch(url);
    const body = await response.text();
    const $ = cheerio.load(body);

    const scripts = [];
    $("script[src]").each((i, el) => scripts.push($(el).attr("src")));
    const results = [];

    for (const src of scripts) {
      const match = src.match(/\/([^\/]+)-([\d\.]+)(?:\.min)?\.js/);
      if (match) {
        const libName = match[1];
        const libVersion = match[2];
        let latestVersion = "unknown";
        let outdated = false;
        let vulnerabilities = [];

        try {
          const cdnRes = await fetch(`https://api.cdnjs.com/libraries/${libName}?fields=version`);
          const cdnData = await cdnRes.json();
          if (cdnData.version) {
            latestVersion = cdnData.version;
            outdated = libVersion !== latestVersion;
          }
        } catch {}

        try {
          const ossRes = await fetch("https://ossindex.sonatype.org/api/v3/component-report", {
            method: "POST",
            headers: { "Content-Type": "application/vnd.ossindex.component-report-request+json" },
            body: JSON.stringify({ coordinates: [`pkg:npm/${libName}@${libVersion}`] })
          });
          const ossData = await ossRes.json();
          if (Array.isArray(ossData) && ossData.length > 0 && ossData[0].vulnerabilities) {
            vulnerabilities = ossData[0].vulnerabilities.map(v => ({
              title: v.title,
              cve: v.cve,
              severity: v.cvssScore
            }));
          }
        } catch {}

        results.push({ library: libName, current: libVersion, latest: latestVersion, outdated, vulnerabilities });
      }
    }
    res.json(results.length ? results : []);
  } catch (err) {
    res.status(500).json({ error: "Library scan failed", details: err.message });
  }
});

app.get("/scan/xss", authenticateToken, async (req, res) => {
  try {
    const { url } = req.query;
    if (!url) return res.status(400).json({ error: "Missing ?url parameter" });
    const response = await fetch(url);
    const html = await response.text();
    const findings = [];
    if (/<script[^>]*>/.test(html)) findings.push("Inline <script> tags found");
    if (/on\w+=/i.test(html)) findings.push("Event handlers detected");
    if (/javascript:/i.test(html)) findings.push("JavaScript links found");
    if (/{{.*}}/.test(html)) findings.push("Unescaped template variables detected");
    res.json({ url, findings });
  } catch (err) {
    res.status(500).json({ error: "Failed to scan for XSS", details: err.message });
  }
});

app.get("/scan/ports", authenticateToken, async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: "Missing ?url parameter" });
  const parsedUrl = new URL(url.startsWith("http") ? url : "http://" + url);
  const host = parsedUrl.hostname;
  const ports = [80, 443, 8080, 8443, 3000, 5000];
  const open = [];
  await Promise.all(
    ports.map(p =>
      new Promise(resolve => {
        const client = (p === 443 ? https : http)
          .request({ host, port: p, method: "HEAD", timeout: 2000 }, () => {
            open.push(p);
            resolve();
          })
          .on("error", () => resolve())
          .end();
      })
    )
  );
  const panels = ["/admin", "/login", "/phpmyadmin"];
  const panelHits = [];
  for (const path of panels) {
    try {
      const r = await fetch(parsedUrl.origin + path, { method: "HEAD" });
      if (r.status < 400) panelHits.push(parsedUrl.origin + path);
    } catch {}
  }
  res.json({ host, openPorts: open, adminPanels: panelHits });
});

app.get("/scan/csrf", authenticateToken, async (req, res) => {
  try {
    const { url } = req.query;
    if (!url) return res.status(400).json({ error: "Missing ?url parameter" });
    const response = await fetch(url);
    const html = await response.text();
    const $ = cheerio.load(html);
    const forms = [];
    $("form").each((i, el) => {
      const inputs = $(el).find("input[type=hidden]");
      let hasToken = false;
      inputs.each((j, inp) => {
        const name = $(inp).attr("name") || "";
        if (/csrf|token|authenticity/i.test(name)) hasToken = true;
      });
      forms.push({ action: $(el).attr("action"), hasToken });
    });
    res.json({ url, forms });
  } catch (err) {
    res.status(500).json({ error: "Failed CSRF scan", details: err.message });
  }
});

app.get("/scan/sensitive", authenticateToken, async (req, res) => {
  try {
    const { url } = req.query;
    if (!url) return res.status(400).json({ error: "Missing ?url parameter" });
    const response = await fetch(url);
    const html = await response.text();
    const findings = [];
    const regexes = {
      apiKey: /(AIza[0-9A-Za-z-_]{35})/,
      aws: /AKIA[0-9A-Z]{16}/,
      email: /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i,
      secrets: /(password|secret|token)[\s:=].{4,}/i
    };
    for (const [name, regex] of Object.entries(regexes)) {
      const match = html.match(regex);
      if (match) findings.push(`${name}: ${match[0]}`);
    }
    res.json({ url, findings });
  } catch (err) {
    res.status(500).json({ error: "Failed sensitive scan", details: err.message });
  }
});

// ------------------- AI + SCORE ENGINE -------------------
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;

// Fallback suggestions for common issues
const fallbackSuggestions = {
  "content-security-policy missing": "Add a Content-Security-Policy header to restrict resource loading.",
  "strict-transport-security missing": "Implement Strict-Transport-Security header to enforce HTTPS.",
  "x-frame-options missing": "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking.",
  "x-content-type-options missing": "Add X-Content-Type-Options: nosniff to prevent MIME-type sniffing.",
  "referrer-policy missing": "Set Referrer-Policy to strict-origin-when-cross-origin for privacy.",
  "permissions-policy missing": "Use Permissions-Policy to disable unused browser features.",
  "missing meta description": "Add a meta description tag to improve SEO and click-through rates.",
  "missing viewport meta tag": "Include <meta name='viewport' content='width=device-width, initial-scale=1'> for mobile responsiveness.",
  "missing sitemap.xml": "Create and submit a sitemap.xml to improve search engine crawling.",
  "missing robots.txt": "Add a robots.txt file to guide search engine crawlers.",
  "inline <script> tags found": "Move inline scripts to external files to improve security and caching.",
  "event handlers detected": "Replace inline event handlers with addEventListener for better maintainability.",
  "broken link": "Fix or remove broken links to improve user experience and SEO.",
  "page load time": "Optimize server response time and resource loading to reduce page load time below 500ms.",
  "time to first byte": "Reduce Time to First Byte by optimizing server performance or using a CDN.",
  "resource load time": "Optimize resource delivery by compressing files, using a CDN, or deferring non-critical resources."
};

// AI Fix Endpoint
app.get("/ai-fix", authenticateToken, async (req, res) => {
  const { issue } = req.query;
  if (!issue) return res.status(400).json({ error: "Missing ?issue parameter" });

  const normalizedIssue = issue.toLowerCase().split(":")[0].trim();
  const suggestion = fallbackSuggestions[normalizedIssue] || fallbackSuggestions[issue.toLowerCase()];
  if (suggestion) {
    return res.json({ suggestion });
  }

  try {
    const response = await fetch("https://openrouter.ai/api/v1/...", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${OPENROUTER_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ prompt: `Suggest a fix for this website issue: ${issue}` })
    });
    const data = await response.json();
    res.json({ suggestion: data.response || "No specific fix available; consider optimizing resource loading for better performance." });
  } catch (err) {
    res.json({ suggestion: "No specific fix available; consider optimizing resource loading for better performance." });
  }
});

// Calculate score and status
function calculateScore(findings) {
  if (!findings || findings.length === 0) return { score: 100, status: "Safe 🟢" };
  const severity = Math.min(findings.length * 10, 100);
  const score = Math.max(0, 100 - severity);
  const status = score >= 80 ? "Safe 🟢" : score >= 50 ? "Warning 🟡" : "Critical 🔴";
  return { score, status };
}

// Report Generation (Security Report Example)
app.post("/report/security", authenticateToken, async (req, res) => {
  try {
    const { scanResults } = req.body;
    if (!scanResults) return res.status(400).json({ error: "Missing scanResults" });

    const doc = new PDFDocument();
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", 'attachment; filename="security_report.pdf"');
    doc.pipe(res);

    doc.fontSize(20).text("Website Security Report", { align: "center" });
    doc.moveDown(2);

    let totalScore = 0;
    const sectionScores = [];
    for (const [scanType, findings] of Object.entries(scanResults)) {
      const { score } = calculateScore(findings);
      sectionScores.push({ scanType, score });
      totalScore += score;
    }
    const overallScore = Math.round(totalScore / sectionScores.length);

    doc.fontSize(18).fillColor("#000").text("📌 Summary", { underline: true });
    doc.moveDown();
    doc.fontSize(14).fillColor(overallScore >= 80 ? "green" : overallScore >= 50 ? "orange" : "red")
      .text(`Overall Security Score: ${overallScore}%`);
    doc.moveDown(0.5);
    doc.fontSize(12).fillColor("#000").text("Highlights:");
    doc.moveDown(0.5);
    if (overallScore < 50) {
      doc.fillColor("red").text("⚠️ Critical issues detected. Immediate action required!");
    } else if (overallScore < 80) {
      doc.fillColor("orange").text("⚠️ Some vulnerabilities found. Fix recommended.");
    } else {
      doc.fillColor("green").text("✅ Good security posture. Few minor issues detected.");
    }
    doc.moveDown(2);

    try {
      const qc = new QuickChart();
      qc.setConfig({
        type: "bar",
        data: {
          labels: sectionScores.map(s => s.scanType.toUpperCase()),
          datasets: [{
            label: "Security Score (%)",
            data: sectionScores.map(s => s.score),
            backgroundColor: sectionScores.map(s => s.score >= 80 ? "green" : s.score >= 50 ? "orange" : "red")
          }]
        }
      }).setWidth(500).setHeight(300).setBackgroundColor("white");

      const chartImageBase64 = await qc.toDataUrl();
      const chartBuffer = Buffer.from(chartImageBase64.split(",")[1], "base64");
      doc.image(chartBuffer, { align: "center", width: 400 });
    } catch (chartErr) {
      doc.fontSize(12).fillColor("red").text("⚠️ Unable to load chart. (Network issue)", { align: "center" });
    }

    doc.moveDown(2);

    for (const [scanType, findings] of Object.entries(scanResults)) {
      const { score, status } = calculateScore(findings);
      const statusColor = score >= 80 ? "green" : score >= 50 ? "orange" : "red";

      doc.fontSize(16).fillColor("#4B0082").text(`🔍 ${scanType.toUpperCase()}`);
      doc.fontSize(12).fillColor(statusColor).text(`Score: ${score}%`);
      doc.moveDown(0.5);

      if (findings.length === 0) {
        doc.fillColor("green").text("✅ No issues found.");
      } else {
        findings.forEach((issue, idx) => {
          doc.fillColor("#000").text(`${idx + 1}. ${issue}`);
        });
      }
      doc.moveDown(1);
    }

    doc.end();
  } catch (err) {
    console.error("Report generation error:", err);
    if (!res.headersSent) {
      res.status(500).json({ error: "Failed to generate report", details: err.message });
    }
  }
});

// ------------------- PERFORMANCE SCANNER ROUTES -------------------
app.get("/perf/pageload", authenticateToken, async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: "Missing ?url parameter" });

  const start = Date.now();
  try {
    const response = await fetch(url);
    await response.text();
    const duration = Date.now() - start;
    res.json({ url, loadTimeMs: duration });
  } catch (err) {
    res.status(500).json({ error: "Page load test failed", details: err.message });
  }
});

app.get("/perf/server", authenticateToken, async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: "Missing ?url parameter" });

  const start = Date.now();
  try {
    const response = await fetch(url);
    const firstByte = Date.now() - start;
    res.json({ url, ttfbMs: firstByte, status: response.status });
  } catch (err) {
    res.status(500).json({ error: "Server response test failed", details: err.message });
  }
});

app.get("/perf/images", authenticateToken, async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: "Missing ?url parameter" });

  try {
    const response = await fetch(url);
    const html = await response.text();
    const $ = cheerio.load(html);

    const images = [];
    $("img").each((i, el) => {
      const src = $(el).attr("src");
      if (src) images.push(src);
    });

    const results = [];
    for (let src of images.slice(0, 10)) {
      try {
        const imgRes = await fetch(src.startsWith("http") ? src : new URL(src, url).href, { method: "HEAD" });
        const size = imgRes.headers.get("content-length") || "unknown";
        results.push({ src, size });
      } catch {
        results.push({ src, size: "unknown" });
      }
    }

    res.json({ url, images: results });
  } catch (err) {
    res.status(500).json({ error: "Image scan failed", details: err.message });
  }
});

app.get("/perf/js-css", authenticateToken, async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: "Missing ?url parameter" });
  try {
    const response = await fetch(url);
    const html = await response.text();
    const $ = cheerio.load(html);

    const scripts = $("script[src]").map((i, el) => $(el).attr("src")).get();
    const styles = $("link[rel=stylesheet]").map((i, el) => $(el).attr("href")).get();

    res.json({ url, scripts, styles, blocking: scripts.length + styles.length });
  } catch (err) {
    res.status(500).json({ error: "JS/CSS scan failed", details: err.message });
  }
});

app.get("/perf/resources", authenticateToken, async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: "Missing ?url parameter" });
  try {
    const response = await fetch(url);
    const html = await response.text();
    const $ = cheerio.load(html);

    const resources = [];
    $("script[src], link[href], img[src]").each((i, el) => {
      const attr = $(el).attr("src") || $(el).attr("href");
      if (attr) resources.push(attr);
    });

    const results = [];
    for (let r of resources.slice(0, 10)) {
      const target = r.startsWith("http") ? r : new URL(r, url).href;
      const start = Date.now();
      try {
        await fetch(target, { method: "HEAD" });
        results.push({ resource: target, loadMs: Date.now() - start });
      } catch {
        results.push({ resource: target, loadMs: "failed" });
      }
    }

    res.json({ url, resources: results });
  } catch (err) {
    res.status(500).json({ error: "Resource loading scan failed", details: err.message });
  }
});

// ------------------- SEO SCANNER ROUTES -------------------
app.get("/seo/meta", authenticateToken, async (req, res) => {
  try {
    let { url } = req.query;
    if (!url) return res.status(400).json({ error: "Missing ?url parameter" });
    if (!url.startsWith("http")) url = "https://" + url;
    const response = await fetch(url);
    const html = await response.text();
    const $ = cheerio.load(html);
    let issues = [];
    if (!$("title").text()) issues.push("Missing <title> tag");
    if (!$("meta[name=description]").attr("content")) issues.push("Missing meta description");
    res.json({ issues });
  } catch (err) {
    res.status(500).json({ error: "Meta analysis failed", details: err.message });
  }
});

app.get("/seo/keywords", authenticateToken, async (req, res) => {
  try {
    let { url } = req.query;
    if (!url) return res.status(400).json({ error: "Missing ?url parameter" });
    if (!url.startsWith("http")) url = "https://" + url;
    const response = await fetch(url);
    const html = await response.text();
    const text = cheerio.load(html)("body").text().toLowerCase();
    let words = text.split(/\s+/);
    let freq = {};
    words.forEach(w => { if (w.length > 3) freq[w] = (freq[w] || 0) + 1; });
    let top = Object.entries(freq).sort((a, b) => b[1] - a[1]).slice(0, 10);
    res.json({ keywords: top, issues: [] });
  } catch (err) {
    res.status(500).json({ error: "Keyword density failed", details: err.message });
  }
});

app.get("/seo/headings", authenticateToken, async (req, res) => {
  try {
    let { url } = req.query;
    if (!url) return res.status(400).json({ error: "Missing ?url parameter" });
    if (!url.startsWith("http")) url = "https://" + url;
    const response = await fetch(url);
    const html = await response.text();
    const $ = cheerio.load(html);
    let h1 = $("h1").length, h2 = $("h2").length;
    let issues = [];
    if (h1 !== 1) issues.push(`Page has ${h1} H1 tags (should be exactly 1)`);
    if (h2 < 1) issues.push("No H2 tags found");
    res.json({ issues });
  } catch (err) {
    res.status(500).json({ error: "Heading analysis failed", details: err.message });
  }
});

app.get("/seo/url", authenticateToken, async (req, res) => {
  try {
    let { url } = req.query;
    if (!url) return res.status(400).json({ error: "Missing ?url parameter" });
    if (!url.startsWith("http")) url = "https://" + url;
    const issues = [];
    if (url.length > 75) issues.push("URL too long");
    if (url.includes("?")) issues.push("Dynamic parameters in URL");
    res.json({ issues });
  } catch (err) {
    res.status(500).json({ error: "URL structure failed", details: err.message });
  }
});

app.get("/seo/mobile", authenticateToken, async (req, res) => {
  try {
    let { url } = req.query;
    if (!url) return res.status(400).json({ error: "Missing ?url parameter" });
    if (!url.startsWith("http")) url = "https://" + url;
    const response = await fetch(url);
    const html = await response.text();
    const $ = cheerio.load(html);
    let viewport = $("meta[name=viewport]").attr("content");
    let issues = [];
    if (!viewport) issues.push("Missing viewport meta tag");
    res.json({ issues });
  } catch (err) {
    res.status(500).json({ error: "Mobile friendliness failed", details: err.message });
  }
});

app.get("/seo/broken", authenticateToken, async (req, res) => {
  try {
    let { url } = req.query;
    if (!url) return res.status(400).json({ error: "Missing ?url parameter" });
    if (!url.startsWith("http")) url = "https://" + url;
    const response = await fetch(url);
    const html = await response.text();
    const $ = cheerio.load(html);
    let links = $("a[href]").map((i, el) => $(el).attr("href")).get();
    let issues = [];
    for (let link of links.slice(0, 10)) {
      try {
        const r = await fetch(link.startsWith("http") ? link : new URL(link, url).href, { method: "HEAD" });
        if (r.status >= 400) issues.push(`Broken link: ${link}`);
      } catch {
        issues.push(`Invalid link: ${link}`);
      }
    }
    res.json({ issues });
  } catch (err) {
    res.status(500).json({ error: "Broken link check failed", details: err.message });
  }
});

app.get("/seo/images", authenticateToken, async (req, res) => {
  try {
    let { url } = req.query;
    if (!url) return res.status(400).json({ error: "Missing ?url parameter" });
    if (!url.startsWith("http")) url = "https://" + url;
    const response = await fetch(url);
    const html = await response.text();
    const $ = cheerio.load(html);
    let issues = [];
    $("img").each((i, el) => {
      if (!$(el).attr("alt")) issues.push("Image missing alt attribute");
    });
    res.json({ issues });
  } catch (err) {
    res.status(500).json({ error: "Image optimization failed", details: err.message });
  }
});

app.get("/seo/sitemap", authenticateToken, async (req, res) => {
  try {
    let { url } = req.query;
    if (!url) return res.status(400).json({ error: "Missing ?url parameter" });
    if (!url.startsWith("http")) url = "https://" + url;
    const base = new URL(url).origin;
    let issues = [];
    try {
      const sm = await fetch(base + "/sitemap.xml");
      if (sm.status >= 400) issues.push("Missing sitemap.xml");
    } catch { issues.push("Missing sitemap.xml"); }
    try {
      const rb = await fetch(base + "/robots.txt");
      if (rb.status >= 400) issues.push("Missing robots.txt");
    } catch { issues.push("Missing robots.txt"); }
    res.json({ issues });
  } catch (err) {
    res.status(500).json({ error: "Sitemap/robots check failed", details: err.message });
  }
});

app.get("/seo/crawl", authenticateToken, async (req, res) => {
  try {
    let { url } = req.query;
    if (!url) return res.status(400).json({ error: "Missing ?url parameter" });
    if (!url.startsWith("http")) url = "https://" + url;
    const response = await fetch(url);
    let issues = [];
    if (response.status >= 400) issues.push(`Homepage returned ${response.status}`);
    res.json({ issues });
  } catch (err) {
    res.status(500).json({ error: "Crawl error check failed", details: err.message });
  }
});

// Import history routes
require("./script")(app);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
