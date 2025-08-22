const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const path = require("path");
const fetch = (...args) => import("node-fetch").then(({ default: fetch }) => fetch(...args));
const cheerio = require("cheerio");
const http = require("http");
const https = require("https");

const app = express();
app.use(express.json());
app.use(cors());

// ✅ Serve static files
app.use(express.static(path.join(__dirname)));

// ✅ MongoDB Connection
mongoose.connect("mongodb+srv://nss:nss@nss.otjxidx.mongodb.net/?retryWrites=true&w=majority&appName=nss")
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ MongoDB error:", err));

// ✅ User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String
});
const User = mongoose.model("User", userSchema);

app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; style-src 'self' 'unsafe-inline' https://unpkg.com; script-src 'self' 'unsafe-inline' https://unpkg.com;"
  );
  next();
});


// ------------------- AUTH ROUTES -------------------
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ message: "Email already registered" });
    const user = new User({ name, email, password });
    await user.save();
    res.json({ message: "Registration successful" });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ message: "Error registering user" });
  }
});

app.post("/login", async (req, res) => {
  const { name, password } = req.body;
  try {
    const user = await User.findOne({ name, password });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });
    res.json({ message: "Login successful", user, redirect: "/ayu.html" });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Error logging in" });
  }
});

// ✅ Default routes
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/ayu.html", (req, res) => res.sendFile(path.join(__dirname, "ayu.html")));


// ------------------- SECURITY SCANNER ROUTES -------------------

// 1. SSL Labs
app.get("/scan/ssl", async (req, res) => {
  let { url } = req.query;
  if (!url) return res.status(400).json({ error: "Missing ?url parameter" });
  url = url.replace(/^https?:\/\//, "").replace(/\/$/, "");

  async function poll() {
    const response = await fetch(`https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(url)}&all=done`);
    const data = await response.json();
    if (data.status !== "READY" && data.status !== "ERROR") {
      await new Promise(r => setTimeout(r, 5000));
      return poll();
    }
    return data;
  }

  try {
    const result = await poll();
    res.json(result);
  } catch {
    res.status(500).json({ error: "SSL Labs scan failed" });
  }
});

// 2. Security Headers
app.get("/scan/headers", async (req, res) => {
  let { url } = req.query;
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
  } catch {
    res.status(500).json({ error: "Header fetch failed" });
  }
});

// 3. Outdated JS Libraries
app.get("/scan/libs", async (req, res) => {
  let { url } = req.query;
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
  } catch {
    res.status(500).json({ error: "Library scan failed" });
  }
});

// 4. XSS Heuristic
app.get("/scan/xss", async (req, res) => {
  try {
    const url = req.query.url;
    const response = await fetch(url);
    const html = await response.text();
    const findings = [];
    if (/<script[^>]*>/.test(html)) findings.push("Inline <script> tags found");
    if (/on\w+=/i.test(html)) findings.push("Event handlers detected");
    if (/javascript:/i.test(html)) findings.push("JavaScript links found");
    if (/{{.*}}/.test(html)) findings.push("Unescaped template variables detected");
    res.json({ url, findings });
  } catch {
    res.status(500).json({ error: "Failed to scan for XSS" });
  }
});

// 5. Ports + Admin Panels
app.get("/scan/ports", async (req, res) => {
  const url = new URL(req.query.url.startsWith("http") ? req.query.url : "http://" + req.query.url);
  const host = url.hostname;
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
      const r = await fetch(url.origin + path, { method: "HEAD" });
      if (r.status < 400) panelHits.push(url.origin + path);
    } catch {}
  }
  res.json({ host, openPorts: open, adminPanels: panelHits });
});

// 6. CSRF Token Detection
app.get("/scan/csrf", async (req, res) => {
  try {
    const url = req.query.url;
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
  } catch {
    res.status(500).json({ error: "Failed CSRF scan" });
  }
});

// 7. Sensitive Data Exposure
app.get("/scan/sensitive", async (req, res) => {
  try {
    const url = req.query.url;
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
  } catch {
    res.status(500).json({ error: "Failed sensitive scan" });
  }
});



// ------------------- NEW: AI + SCORE ENGINE -------------------
const PDFDocument = require("pdfkit");
const fs = require("fs");

const OPENROUTER_API_KEY = "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";

// Helper: Calculate score and status
function calculateScore(findings) {
  if (!findings || findings.length === 0) return { score: 100, status: "Safe 🟢" };
  const severity = findings.length * 10;
  let score = Math.max(0, 100 - severity);
  let status = score >= 80 ? "Safe 🟢" : score >= 50 ? "Warning 🟡" : "Critical 🔴";
  return { score, status };
}

// Helper: Get AI suggestion (one-liner)
async function getAISolution(issue) {
  try {
    const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${OPENROUTER_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: "openai/gpt-4o-mini",
        messages: [{ role: "user", content: `Give a one-line fix for: ${issue}` }]
      })
    });
    const data = await response.json();
    return data.choices?.[0]?.message?.content || "No AI suggestion";
  } catch (err) {
    return "AI service unavailable";
  }
}

// NEW ROUTE: AI fix per issue
app.get("/ai-fix", async (req, res) => {
  const { issue } = req.query;
  if (!issue) return res.status(400).json({ error: "Missing ?issue" });
  const fix = await getAISolution(issue);
  res.json({ issue, fix });
});


// ------------------- NEW ROUTE: Unified Report -------------------
const QuickChart = require('quickchart-js'); // Install: npm i quickchart-js
app.post("/generate-report", async (req, res) => {
  try {
    const { scanResults } = req.body;
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", "attachment; filename=SecurityReport.pdf");

    const doc = new PDFDocument({ margin: 30 });
    doc.pipe(res);

    // === Header ===
    doc.fontSize(26).fillColor("#4B0082").text("🔐 Security Audit Report", { align: "center" });
    doc.moveDown(0.5);
    doc.fontSize(12).fillColor("#444").text(`Generated on: ${new Date().toLocaleString()}`, { align: "center" });
    doc.moveDown(2);

    // === Compute scores ===
    let totalScore = 0;
    const sectionScores = [];
    for (const [scanType, findings] of Object.entries(scanResults)) {
      const severity = findings.length * 10;
      const score = Math.max(0, 100 - severity);
      sectionScores.push({ scanType, score });
      totalScore += score;
    }
    const overallScore = Math.round(totalScore / sectionScores.length);

    // === Summary ===
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

    // === Add Chart ===
    try {
      const QuickChart = require('quickchart-js');
      const qc = new QuickChart();
      qc.setConfig({
        type: 'bar',
        data: {
          labels: sectionScores.map(s => s.scanType.toUpperCase()),
          datasets: [{
            label: 'Security Score (%)',
            data: sectionScores.map(s => s.score),
            backgroundColor: sectionScores.map(s => s.score >= 80 ? 'green' : s.score >= 50 ? 'orange' : 'red')
          }]
        }
      }).setWidth(500).setHeight(300).setBackgroundColor('white');

      const chartImageBase64 = await qc.toDataUrl();
      const chartBuffer = Buffer.from(chartImageBase64.split(",")[1], 'base64');
      doc.image(chartBuffer, { align: "center", width: 400 });
    } catch (chartErr) {
      doc.fontSize(12).fillColor("red").text("⚠️ Unable to load chart. (Network issue)", { align: "center" });
    }

    doc.moveDown(2);

    // === Detailed Sections ===
    for (const [scanType, findings] of Object.entries(scanResults)) {
      const severity = findings.length * 10;
      const score = Math.max(0, 100 - severity);
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
      res.status(500).json({ error: "Failed to generate report" });
    }
  }
});




// ------------------- PERFORMANCE SCANNER ROUTES -------------------
app.get("/perf/pageload", async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: "Missing ?url" });

  const start = Date.now();
  try {
    const response = await fetch(url);
    await response.text();
    const duration = Date.now() - start;
    res.json({ url, loadTimeMs: duration });
  } catch {
    res.status(500).json({ error: "Page load test failed" });
  }
});

app.get("/perf/server", async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: "Missing ?url" });

  const start = Date.now();
  try {
    const response = await fetch(url);
    const firstByte = Date.now() - start;
    res.json({ url, ttfbMs: firstByte, status: response.status });
  } catch {
    res.status(500).json({ error: "Server response test failed" });
  }
});

app.get("/perf/images", async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: "Missing ?url" });

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
    for (let src of images.slice(0, 10)) { // limit 10 for speed
      try {
        const imgRes = await fetch(src.startsWith("http") ? src : new URL(src, url).href, { method: "HEAD" });
        const size = imgRes.headers.get("content-length") || "unknown";
        results.push({ src, size });
      } catch {
        results.push({ src, size: "unknown" });
      }
    }

    res.json({ url, images: results });
  } catch {
    res.status(500).json({ error: "Image scan failed" });
  }
});

app.get("/perf/js-css", async (req, res) => {
  const { url } = req.query;
  try {
    const response = await fetch(url);
    const html = await response.text();
    const $ = cheerio.load(html);

    const scripts = $("script[src]").map((i, el) => $(el).attr("src")).get();
    const styles = $("link[rel=stylesheet]").map((i, el) => $(el).attr("href")).get();

    res.json({ url, scripts, styles, blocking: scripts.length + styles.length });
  } catch {
    res.status(500).json({ error: "JS/CSS scan failed" });
  }
});

app.get("/perf/resources", async (req, res) => {
  const { url } = req.query;
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
  } catch {
    res.status(500).json({ error: "Resource loading scan failed" });
  }
});

// 1. Meta Tags
app.get("/seo/meta", async (req, res) => {
  try {
    let { url } = req.query;
    if (!url.startsWith("http")) url = "https://" + url;
    const response = await fetch(url);
    const html = await response.text();
    const $ = cheerio.load(html);
    let issues = [];
    if (!$("title").text()) issues.push("Missing <title> tag");
    if (!$("meta[name=description]").attr("content")) issues.push("Missing meta description");
    res.json({ issues });
  } catch {
    res.status(500).json({ error: "Meta analysis failed" });
  }
});

// 2. Keyword Density
app.get("/seo/keywords", async (req, res) => {
  try {
    let { url } = req.query;
    if (!url.startsWith("http")) url = "https://" + url;
    const response = await fetch(url);
    const html = await response.text();
    const text = cheerio.load(html)("body").text().toLowerCase();
    let words = text.split(/\s+/);
    let freq = {};
    words.forEach(w => { if (w.length > 3) freq[w] = (freq[w] || 0) + 1; });
    let top = Object.entries(freq).sort((a, b) => b[1] - a[1]).slice(0, 10);
    res.json({ keywords: top, issues: [] });
  } catch {
    res.status(500).json({ error: "Keyword density failed" });
  }
});

// 3. Heading Structure
app.get("/seo/headings", async (req, res) => {
  try {
    let { url } = req.query;
    if (!url.startsWith("http")) url = "https://" + url;
    const response = await fetch(url);
    const html = await response.text();
    const $ = cheerio.load(html);
    let h1 = $("h1").length, h2 = $("h2").length;
    let issues = [];
    if (h1 !== 1) issues.push(`Page has ${h1} H1 tags (should be exactly 1)`);
    if (h2 < 1) issues.push("No H2 tags found");
    res.json({ issues });
  } catch {
    res.status(500).json({ error: "Heading analysis failed" });
  }
});

// 4. URL Structure
app.get("/seo/url", async (req, res) => {
  try {
    let { url } = req.query;
    const issues = [];
    if (url.length > 75) issues.push("URL too long");
    if (url.includes("?")) issues.push("Dynamic parameters in URL");
    res.json({ issues });
  } catch {
    res.status(500).json({ error: "URL structure failed" });
  }
});

// 5. Mobile Friendliness (viewport check)
app.get("/seo/mobile", async (req, res) => {
  try {
    let { url } = req.query;
    if (!url.startsWith("http")) url = "https://" + url;
    const response = await fetch(url);
    const html = await response.text();
    const $ = cheerio.load(html);
    let viewport = $("meta[name=viewport]").attr("content");
    let issues = [];
    if (!viewport) issues.push("Missing viewport meta tag");
    res.json({ issues });
  } catch {
    res.status(500).json({ error: "Mobile friendliness failed" });
  }
});

// 6. Broken Links
app.get("/seo/broken", async (req, res) => {
  try {
    let { url } = req.query;
    if (!url.startsWith("http")) url = "https://" + url;
    const response = await fetch(url);
    const html = await response.text();
    const $ = cheerio.load(html);
    let links = $("a[href]").map((i, el) => $(el).attr("href")).get();
    let issues = [];
    for (let link of links.slice(0, 10)) { // limit 10
      try {
        const r = await fetch(link.startsWith("http") ? link : new URL(link, url).href, { method: "HEAD" });
        if (r.status >= 400) issues.push(`Broken link: ${link}`);
      } catch {
        issues.push(`Invalid link: ${link}`);
      }
    }
    res.json({ issues });
  } catch {
    res.status(500).json({ error: "Broken link check failed" });
  }
});

// 7. Image Optimization
app.get("/seo/images", async (req, res) => {
  try {
    let { url } = req.query;
    if (!url.startsWith("http")) url = "https://" + url;
    const response = await fetch(url);
    const html = await response.text();
    const $ = cheerio.load(html);
    let issues = [];
    $("img").each((i, el) => {
      if (!$(el).attr("alt")) issues.push("Image missing alt attribute");
    });
    res.json({ issues });
  } catch {
    res.status(500).json({ error: "Image optimization failed" });
  }
});

// 8. Sitemap & Robots.txt
app.get("/seo/sitemap", async (req, res) => {
  try {
    let { url } = req.query;
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
  } catch {
    res.status(500).json({ error: "Sitemap/robots check failed" });
  }
});

// 9. Backlink Profile (stub, since needs external APIs)
app.get("/seo/backlinks", async (req, res) => {
  try {
    // Normally you’d query Google Search Console / Ahrefs API etc.
    res.json({ issues: ["Backlink data requires external SEO API integration"] });
  } catch {
    res.status(500).json({ error: "Backlink check failed" });
  }
});

// 10. Crawl Errors (basic: fetch homepage status)
app.get("/seo/crawl", async (req, res) => {
  try {
    let { url } = req.query;
    if (!url.startsWith("http")) url = "https://" + url;
    const response = await fetch(url);
    let issues = [];
    if (response.status >= 400) issues.push(`Homepage returned ${response.status}`);
    res.json({ issues });
  } catch {
    res.status(500).json({ error: "Crawl error check failed" });
  }
});


// Import history routes
require("./script")(app);


// ✅ Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

