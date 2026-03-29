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
const multer = require("multer");
const FormData = require("form-data");
const fs = require("fs");
const axios = require("axios");

// VirusTotal API Key — set via env var on Render, falls back to hardcoded key
const VT_API_KEY = process.env.VT_API_KEY || "f33d710ead9145561ea5957e8fba7ac0556dad010bd8e369c410d9c9e924e5c1";

// Ensure uploads temp folder exists
if (!fs.existsSync("./uploads")) fs.mkdirSync("./uploads");
const upload = multer({ dest: "uploads/" });

const app = express();
app.use(express.json());
app.use(cors());

// ✅ Serve static files including manifest and service worker
app.use(express.static(path.join(__dirname)));

// Serve manifest.json with correct content type
app.get('/manifest.json', (req, res) => {
  res.type('application/manifest+json');
  res.sendFile(path.join(__dirname, 'manifest.json'));
});

// Serve service worker
app.get('/sw.js', (req, res) => {
  res.type('application/javascript');
  res.sendFile(path.join(__dirname, 'sw.js'));
});

// ✅ MongoDB Connection
mongoose.connect("mongodb+srv://nss:nss@nss.otjxidx.mongodb.net/?retryWrites=true&w=majority&appName=nss")
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ MongoDB error:", err));

// ✅ User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  language: { type: String, default: 'en' }
});
const User = mongoose.model("User", userSchema);

// ✅ History Schema for detailed scan results
const historySchema = new mongoose.Schema({
  email: String,
  url: String,
  type: String, // 'url_scan', 'message_analysis', 'ssl_check', etc
  results: mongoose.Schema.Types.Mixed,
  timestamp: { type: Date, default: Date.now },
  verdict: String,
  score: Number
});
const History = mongoose.model("History", historySchema);

app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; " +
    "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; " +
    "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; " +
    "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; " +
    "connect-src 'self' https://api.openrouter.ai https://openrouter.ai https://api.ssllabs.com https://api.cdnjs.com https://ossindex.sonatype.org https://www.virustotal.com https://api.virustotal.com; " +
    "img-src 'self' data: https:; " +
    "media-src 'self';"
  );
  next();
});

// ------------------- AUTH ROUTES -------------------
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ message: "Email already registered" });
    const user = new User({ name, email, password, language: 'en' });
    await user.save();
    res.json({ message: "Registration successful", user });
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

app.post("/user/language", async (req, res) => {
  try {
    const { email, language } = req.body;
    await User.updateOne({ email }, { language });
    res.json({ message: "Language updated" });
  } catch (err) {
    res.status(500).json({ error: "Failed to update language" });
  }
});

// ✅ Default routes
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/ayu.html", (req, res) => res.sendFile(path.join(__dirname, "ayu.html")));

// ------------------- SECURITY SCANNER ROUTES -------------------

// SSL Check with improved error handling
app.get("/scan/ssl", async (req, res) => {
  let { url } = req.query;
  if (!url) return res.status(400).json({ error: "Missing ?url parameter" });
  url = url.replace(/^https?:\/\//, "").replace(/\/$/, "");

  async function poll(retries = 0) {
    try {
      const response = await fetch(`https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(url)}&all=done&ignoreMismatch=on`);
      const data = await response.json();
      
      if (!data.status) {
        throw new Error(data.errors?.[0]?.message || "API error");
      }
      
      if (data.status !== "READY" && data.status !== "ERROR") {
        if (retries < 10) {
          await new Promise(r => setTimeout(r, 5000));
          return poll(retries + 1);
        }
      }
      return data;
    } catch (err) {
      console.error("SSL Poll error:", err);
      throw err;
    }
  }

  try {
    const result = await poll();
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: "SSL Labs scan failed: " + err.message, url });
  }
});

// Headers scan with better feedback
app.get("/scan/headers", async (req, res) => {
  let { url } = req.query;
  if (!url.startsWith("http")) url = "https://" + url;
  try {
    const response = await fetch(url, { 
      headers: { "User-Agent": "Mozilla/5.0" },
      timeout: 10000
    });
    const headers = {};
    response.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });
    
    const securityHeaders = {
      "content-security-policy": headers["content-security-policy"] || "❌ Missing",
      "strict-transport-security": headers["strict-transport-security"] || "❌ Missing",
      "x-frame-options": headers["x-frame-options"] || "❌ Missing",
      "x-content-type-options": headers["x-content-type-options"] || "❌ Missing",
      "referrer-policy": headers["referrer-policy"] || "❌ Missing",
      "permissions-policy": headers["permissions-policy"] || "⚠️ Missing"
    };
    
    res.json({ headers: securityHeaders, allHeaders: headers });
  } catch (err) {
    res.status(500).json({ error: "Header fetch failed: " + err.message });
  }
});

// Library scan
app.get("/scan/libs", async (req, res) => {
  let { url } = req.query;
  if (!url.startsWith("http")) url = "https://" + url;
  try {
    const response = await fetch(url, { timeout: 10000 });
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
          const cdnRes = await fetch(`https://api.cdnjs.com/libraries/${libName}?fields=version`, { timeout: 5000 });
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
            body: JSON.stringify({ coordinates: [`pkg:npm/${libName}@${libVersion}`] }),
            timeout: 5000
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

        results.push({ 
          library: libName, 
          current: libVersion, 
          latest: latestVersion, 
          outdated, 
          vulnerabilities,
          severity: vulnerabilities.length > 0 ? "HIGH" : outdated ? "MEDIUM" : "LOW"
        });
      }
    }
    res.json(results.length ? results : { message: "No libraries found" });
  } catch (err) {
    res.status(500).json({ error: "Library scan failed: " + err.message });
  }
});

// XSS scan
app.get("/scan/xss", async (req, res) => {
  try {
    const { url } = req.query;
    const response = await fetch(url, { timeout: 10000 });
    const html = await response.text();
    const findings = [];
    const severity = [];

    if (/<script[^>]*>/.test(html)) {
      findings.push("⚠️ Inline <script> tags found");
      severity.push("medium");
    }
    if (/on\w+=/i.test(html)) {
      findings.push("⚠️ Event handlers detected");
      severity.push("high");
    }
    if (/javascript:/i.test(html)) {
      findings.push("⚠️ JavaScript links found");
      severity.push("high");
    }
    if (/{{.*}}/.test(html)) {
      findings.push("⚠️ Unescaped template variables detected");
      severity.push("medium");
    }

    res.json({ 
      url, 
      findings, 
      verdict: findings.length > 2 ? "DANGER" : findings.length > 0 ? "WARNING" : "SAFE",
      score: 100 - (findings.length * 25)
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to scan for XSS: " + err.message });
  }
});

// Port & Admin Panel scan
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
      const r = await fetch(url.origin + path, { method: "HEAD", timeout: 5000 });
      if (r.status < 400) panelHits.push(url.origin + path);
    } catch {}
  }
  
  res.json({ 
    host, 
    openPorts: open, 
    adminPanels: panelHits,
    verdict: open.length > 3 ? "WARNING" : "SAFE"
  });
});

// CSRF scan
app.get("/scan/csrf", async (req, res) => {
  try {
    const url = req.query.url;
    const response = await fetch(url, { timeout: 10000 });
    const html = await response.text();
    const $ = cheerio.load(html);
    
    const forms = [];
    let issues = 0;
    
    $("form").each((i, el) => {
      const tokens = $(el).find("input[name*='csrf'], input[name*='token'], input[name*='_token']").length;
      const hasToken = tokens > 0;
      forms.push({
        action: $(el).attr("action"),
        method: $(el).attr("method"),
        hasToken
      });
      if (!hasToken) issues++;
    });

    res.json({ 
      forms, 
      vulnerability: issues > 0 ? "POSSIBLE CSRF VULNERABILITY" : "Protected",
      score: 100 - (issues * 30)
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to scan for CSRF: " + err.message });
  }
});

// ------------------- PERFORMANCE ROUTES -------------------
app.get("/perf/check", async (req, res) => {
  try {
    const { url } = req.query;
    const response = await fetch(url, { timeout: 15000 });
    const html = await response.text();
    const $ = cheerio.load(html);

    const metrics = {
      htmlSize: html.length,
      scripts: $("script").length,
      stylesheets: $("link[rel='stylesheet']").length,
      images: $("img").length,
      externalRequests: $("script[src], link[href], img[src]").length,
      recommendedOptimizations: []
    };

    if (metrics.images > 10) metrics.recommendedOptimizations.push("Too many images - use lazy loading");
    if (metrics.scripts > 15) metrics.recommendedOptimizations.push("Too many scripts - consider bundling");
    if (metrics.htmlSize > 500000) metrics.recommendedOptimizations.push("HTML too large - optimize content");

    res.json(metrics);
  } catch (err) {
    res.status(500).json({ error: "Performance check failed" });
  }
});

// ------------------- SEO ROUTES -------------------
app.get("/seo/metadata", async (req, res) => {
  try {
    const { url } = req.query;
    const response = await fetch(url, { timeout: 10000 });
    const html = await response.text();
    const $ = cheerio.load(html);

    const metadata = {
      title: $("title").text(),
      description: $("meta[name='description']").attr("content"),
      keywords: $("meta[name='keywords']").attr("content"),
      ogTitle: $("meta[property='og:title']").attr("content"),
      ogDescription: $("meta[property='og:description']").attr("content"),
      hasH1: $("h1").length > 0,
      headings: { h1: $("h1").length, h2: $("h2").length, h3: $("h3").length }
    };

    res.json(metadata);
  } catch (err) {
    res.status(500).json({ error: "Metadata extraction failed" });
  }
});

app.get("/seo/broken", async (req, res) => {
  try {
    let { url } = req.query;
    if (!url.startsWith("http")) url = "https://" + url;
    const response = await fetch(url, { timeout: 10000 });
    const html = await response.text();
    const $ = cheerio.load(html);
    
    let links = $("a[href]").map((i, el) => $(el).attr("href")).get();
    let issues = [];
    
    for (let link of links.slice(0, 20)) {
      try {
        const r = await fetch(link.startsWith("http") ? link : new URL(link, url).href, { method: "HEAD", timeout: 5000 });
        if (r.status >= 400) issues.push(`Broken link: ${link} (${r.status})`);
      } catch (e) {
        issues.push(`Invalid link: ${link}`);
      }
    }
    
    res.json({ issues, totalChecked: links.length });
  } catch (err) {
    res.status(500).json({ error: "Broken link check failed" });
  }
});

// Image optimization check
app.get("/seo/images", async (req, res) => {
  try {
    let { url } = req.query;
    if (!url.startsWith("http")) url = "https://" + url;
    const response = await fetch(url, { timeout: 10000 });
    const html = await response.text();
    const $ = cheerio.load(html);
    
    let issues = [];
    let totalImages = 0;
    
    $("img").each((i, el) => {
      totalImages++;
      if (!$(el).attr("alt")) {
        issues.push(`Image missing alt attribute`);
      }
      if (!$(el).attr("width") || !$(el).attr("height")) {
        issues.push(`Image missing dimensions`);
      }
    });
    
    res.json({ issues, totalImages, missingAlt: issues.length });
  } catch (err) {
    res.status(500).json({ error: "Image optimization check failed" });
  }
});

app.get("/seo/sitemap", async (req, res) => {
  try {
    let { url } = req.query;
    if (!url.startsWith("http")) url = "https://" + url;
    const base = new URL(url).origin;
    let issues = [];
    
    try {
      const sm = await fetch(base + "/sitemap.xml", { timeout: 5000 });
      if (sm.status >= 400) issues.push("❌ Missing sitemap.xml");
    } catch { 
      issues.push("❌ Missing sitemap.xml"); 
    }
    
    try {
      const rb = await fetch(base + "/robots.txt", { timeout: 5000 });
      if (rb.status >= 400) issues.push("❌ Missing robots.txt");
    } catch { 
      issues.push("❌ Missing robots.txt"); 
    }
    
    res.json({ issues });
  } catch (err) {
    res.status(500).json({ error: "Sitemap/robots check failed" });
  }
});

// ------------------- HISTORY ROUTES -------------------
app.post("/save-history", async (req, res) => {
  try {
    const { email, url, type, results, verdict, score } = req.body;
    if (!email) return res.status(400).json({ error: "Missing email" });

    const entry = new History({
      email,
      url,
      type: type || 'general_scan',
      results,
      verdict,
      score
    });

    await entry.save();
    res.json({ message: "History saved successfully" });
  } catch (err) {
    console.error("Error saving history:", err);
    res.status(500).json({ error: "Failed to save history" });
  }
});

app.get("/history", async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) return res.status(400).json({ error: "Missing email" });

    const history = await History.find({ email }).sort({ timestamp: -1 }).limit(50);
    res.json(history);
  } catch (err) {
    console.error("Error fetching history:", err);
    res.status(500).json({ error: "Failed to fetch history" });
  }
});

app.delete("/history/:id", async (req, res) => {
  try {
    await History.findByIdAndDelete(req.params.id);
    res.json({ message: "History deleted" });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete history" });
  }
});

// =================== SCAM SHIELD ROUTES ===================

const scamReportSchema = new mongoose.Schema({
  type: String,
  identifier: String,
  desc: String,
  email: String,
  timestamp: { type: Date, default: Date.now }
});
const ScamReport = mongoose.model("ScamReport", scamReportSchema);

const fakeUrlSchema = new mongoose.Schema({
  url: String,
  issues: Number,
  timestamp: { type: Date, default: Date.now }
});
const FakeUrl = mongoose.model("FakeUrl", fakeUrlSchema);

// OpenRouter API Key
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || "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";

async function callOpenRouter(systemPrompt, userPrompt, maxTokens = 400) {
  try {
    const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${OPENROUTER_API_KEY}`,
        "Content-Type": "application/json",
        "HTTP-Referer": "https://scamshield.app",
        "X-Title": "ScamShield"
      },
      body: JSON.stringify({
        model: "openai/gpt-4o-mini",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt }
        ],
        max_tokens: maxTokens
      })
    });
    
    const data = await response.json();
    if (!response.ok) {
      console.error("OpenRouter error:", data);
      return null;
    }
    
    return data.choices?.[0]?.message?.content || null;
  } catch (err) {
    console.error("API call error:", err);
    return null;
  }
}

// Message Analysis
app.post("/analyze/message", async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: "Missing message" });
  
  try {
    const systemPrompt = `You are an expert scam detection AI trained on Indian cyber fraud patterns.
Analyze the given message and respond ONLY with valid JSON (no markdown, no backticks):
{
  "verdict": "SCAM DETECTED" | "SUSPICIOUS" | "LIKELY SAFE",
  "score": <0-100 integer>,
  "summary": "<1-2 sentence verdict>",
  "flags": [
    { "type": "bad" | "warn" | "good" | "info", "text": "<specific finding>" }
  ]
}
Focus on: OTP requests (80+), fake bank calls, TRAI threats, urgency language, prize fraud, advance fees, courier scams, UPI phishing.`;
    
    const raw = await callOpenRouter(systemPrompt, `Analyze this message:\n\n"${message}"`, 500);
    
    if (!raw) {
      return res.status(500).json({ 
        error: "AI analysis unavailable",
        verdict: "UNABLE_TO_ANALYZE",
        score: 50,
        summary: "Please check the message manually"
      });
    }
    
    const clean = raw.replace(/```json|```/gi, "").trim();
    const parsed = JSON.parse(clean);
    res.json(parsed);
  } catch (err) {
    console.error("Analysis error:", err);
    res.status(500).json({ 
      error: "Analysis failed",
      verdict: "SUSPICIOUS",
      score: 60,
      summary: "Unable to analyze - treat with caution"
    });
  }
});

// AI Chat
app.post("/ai-chat", async (req, res) => {
  const { prompt, username } = req.body;
  if (!prompt) return res.status(400).json({ error: "Missing prompt" });
  
  try {
    const systemPrompt = `You are ScamShield AI, an expert assistant helping users identify and avoid digital scams.
Specialize in: phishing links, fake calls, UPI fraud, WhatsApp scams, impersonation attacks.
Be concise, practical, and clear. User: ${username || "User"}.`;
    
    const reply = await callOpenRouter(systemPrompt, prompt, 300);
    res.json({ reply: reply || "Unable to generate response. Try rephrasing your question." });
  } catch (err) {
    console.error("Chat error:", err);
    res.status(500).json({ reply: "AI service unavailable. Try again later." });
  }
});

// Scam Report
app.post("/report/scam", async (req, res) => {
  try {
    const { type, identifier, desc, email } = req.body;
    if (!identifier) return res.status(400).json({ error: "Missing identifier" });
    
    const report = new ScamReport({ type, identifier, desc, email });
    await report.save();
    res.json({ message: "Report submitted successfully" });
  } catch (err) {
    res.status(500).json({ error: "Failed to submit report" });
  }
});

// Scam Feed
app.get("/feed/scams", async (req, res) => {
  try {
    const reports = await ScamReport.find({}).sort({ timestamp: -1 }).limit(30);
    res.json(reports);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch feed" });
  }
});

// Fake URL Management
app.post("/save-fake", async (req, res) => {
  try {
    const { url, issues } = req.body;
    await FakeUrl.create({ url, issues });
    res.json({ message: "Saved" });
  } catch (err) {
    res.status(500).json({ error: "Failed to save" });
  }
});

app.get("/fake-urls", async (req, res) => {
  try {
    const urls = await FakeUrl.find({}).sort({ timestamp: -1 }).limit(50);
    res.json(urls);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch fake urls" });
  }
});

// =================== END SCAM SHIELD ROUTES ===================

// =================== FILE SCANNER — VirusTotal ===================
app.post("/scan", upload.single("document"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });

  const filePath = req.file.path;
  const cleanup = () => { try { fs.unlinkSync(filePath); } catch {} };

  try {
    console.log(`> GuardScan: processing "${req.file.originalname}" (${req.file.size} bytes)`);

    // 1. Upload file to VirusTotal
    const form = new FormData();
    form.append("file", fs.createReadStream(filePath), { filename: req.file.originalname });

    const uploadRes = await axios.post("https://www.virustotal.com/api/v3/files", form, {
      headers: { ...form.getHeaders(), "x-apikey": VT_API_KEY },
      maxContentLength: Infinity,
      maxBodyLength: Infinity,
      timeout: 60000
    });

    const analysisId = uploadRes.data.data.id;
    console.log(`> Analysis ID: ${analysisId} — polling...`);

    // 2. Poll every 3s, up to 8 attempts (~24s max)
    let attempts = 0;
    const result = await new Promise((resolve, reject) => {
      const interval = setInterval(async () => {
        attempts++;
        try {
          const report = await axios.get(
            `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
            { headers: { "x-apikey": VT_API_KEY }, timeout: 15000 }
          );
          const status = report.data.data.attributes.status;
          console.log(`> Poll #${attempts}: ${status}`);

          if (status === "completed" || attempts >= 8) {
            clearInterval(interval);
            const stats = report.data.data.attributes.stats || {};
            const mal  = stats.malicious   || 0;
            const sus  = stats.suspicious  || 0;
            const har  = stats.harmless    || 0;
            const und  = stats.undetected  || 0;
            const total = mal + sus + har + und;
            const score = total > 0 ? Math.round(((har + und) / total) * 100) : 50;
            resolve({
              status: (mal > 0 || sus > 0) ? "unsafe" : "safe",
              score,
              stats,
              explanation: `${mal} engine${mal !== 1 ? "s" : ""} flagged malicious, ${sus} suspicious, ${har} confirmed safe out of ${total} total.`
            });
          }
        } catch (pollErr) {
          clearInterval(interval);
          reject(pollErr);
        }
      }, 3000);
    });

    cleanup();
    console.log(`> Scan done — status: ${result.status}, score: ${result.score}%`);
    res.json(result);

  } catch (err) {
    cleanup();
    console.error("VirusTotal error:", err.response?.data || err.message);
    res.status(500).json({
      status: "error",
      score: 0,
      stats: {},
      explanation: "VirusTotal API error. Check your API key or try again later."
    });
  }
});
// =================== END FILE SCANNER ===================

// ✅ Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));