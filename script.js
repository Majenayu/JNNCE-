// script.js
const mongoose = require("mongoose");

// Convert email into safe MongoDB collection name
function getUserCollection(email) {
  const safeName = email.replace(/[@.]/g, "_");
  return mongoose.connection.collection(safeName);
}

module.exports = (app) => {
  // ================= SAVE HISTORY =================
  app.post("/save-history", async (req, res) => {
    try {
      const { email, url, scanResults, perfResults, seoResults } = req.body;
      if (!email) return res.status(400).json({ error: "Missing email" });

      // ---- Save to user-specific collection ----
      const collection = getUserCollection(email);
      const entry = {
        timestamp: new Date(),
        url,
        scanResults,
        perfResults,
        seoResults,
      };
      await collection.insertOne(entry);

      // ---- Check total issues ----
      const totalIssues =
        Object.values(scanResults || {}).reduce((a, b) => a + (b?.length || 0), 0) +
        Object.values(perfResults || {}).reduce((a, b) => a + (b?.length || 0), 0) +
        Object.values(seoResults || {}).reduce((a, b) => a + (b?.length || 0), 0);

      // ---- If issues > 10, save to global "fake" collection ----
      if (totalIssues > 10) {
        const fakeCollection = mongoose.connection.collection("fake");
        await fakeCollection.insertOne({
          timestamp: new Date(),
          url,
          totalIssues,
          scanResults,
          perfResults,
          seoResults,
        });
      }

      res.json({ message: "History saved successfully" });
    } catch (err) {
      console.error("❌ Error saving history:", err);
      res.status(500).json({ error: "Failed to save history" });
    }
  });

  // ================= FETCH USER HISTORY =================
  app.get("/history", async (req, res) => {
    try {
      const { email } = req.query;
      if (!email) return res.status(400).json({ error: "Missing email" });

      const collection = getUserCollection(email);
      const history = await collection.find({}).sort({ timestamp: -1 }).toArray();
      res.json(history);
    } catch (err) {
      console.error("❌ Error fetching history:", err);
      res.status(500).json({ error: "Failed to fetch history" });
    }
  });

  // ================= FETCH FAKE HISTORY =================
  app.get("/fake-history", async (req, res) => {
    try {
      const fakeCollection = mongoose.connection.collection("fake");
      const flagged = await fakeCollection.find({}).sort({ timestamp: -1 }).toArray();
      res.json(flagged);
    } catch (err) {
      console.error("❌ Error fetching fake history:", err);
      res.status(500).json({ error: "Failed to fetch fake history" });
    }
  });
};
