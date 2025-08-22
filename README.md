🔐 Security, ⚡ Performance & 🌐 SEO Scanner

A full-stack web application to analyze websites for security vulnerabilities, performance bottlenecks, and SEO issues.
Includes AI-powered fix suggestions, downloadable PDF reports, and user history tracking.

✅ Features

Security Scans

SSL/TLS Validation

Security Headers Check

Outdated JS Libraries Detection

XSS & CSRF Vulnerability Detection

Open Ports & Admin Panel Check

Sensitive Data Exposure

Performance Analysis

Page Load Time

Server Response (TTFB)

Image Optimization

JS/CSS Blocking Detection

Resource Loading Time

SEO Audit

Meta Tags & Headings Check

URL Structure Analysis

Mobile Friendliness

Broken Links Detection

Sitemap & Robots.txt Validation

Image Alt Attributes Check

AI Suggestions

One-line fixes for detected issues

Reports

Downloadable PDF Reports with charts

User System

Login & Register

Scan History Stored in MongoDB

🛠 Tech Stack

Frontend: HTML, TailwindCSS, Vanilla JS, Chart.js

Backend: Node.js, Express.js

Database: MongoDB (Mongoose)

Other: Cheerio, QuickChart, PDFKit, OpenAI API

🚀 Installation & Setup

Clone the repository

git clone https://github.com/your-username/your-repo.git
cd your-repo


Install dependencies

npm install


Configure MongoDB

Update MongoDB connection string in server.js
(currently uses MongoDB Atlas in the code)

Run the server

node server.js


Open in browser

http://localhost:3000

📄 Usage

Go to the Login/Register page (index.html).

After login, you will be redirected to Dashboard (ayu.html).

Enter a website URL → Click Run All Scans.

Download Security / Performance / SEO Reports in PDF.

View previous scans in History Sidebar.

🖼 Screenshots

(Add screenshots here if available)

✅ GitHub Topics
full-stack
nodejs
expressjs
mongodb
website-scanner
security-analysis
performance-testing
seo-audit
ai-integration
pdf-report
tailwindcss
chartjs

🌍 Future Deployment

You can deploy:

Frontend on Vercel/Netlify

Backend on Render/Heroku

Database on MongoDB Atlas

🔗 Author

Developed for Website Security, Performance, and SEO Analysis.
