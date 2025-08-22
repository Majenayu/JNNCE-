// script.js
const mongoose = require("mongoose");

// Convert email into safe MongoDB collection name
function getUserCollection(email) {
  const safeName = email.replace(/[@.]/g, "_");
  return mongoose.connection.collection(safeName);
}

module.exports = (app) => {
  // Save history entry
app.post("/save-history", async (req, res) => {
  try {
    const { email, url, scanResults, perfResults, seoResults } = req.body;
    if (!email) return res.status(400).json({ error: "Missing email" });

    const collection = getUserCollection(email);
    const entry = {
      timestamp: new Date(),
      url,   // ✅ save url
      scanResults,
      perfResults,
      seoResults,
    };

    await collection.insertOne(entry);
    res.json({ message: "History saved successfully" });
  } catch (err) {
    console.error("❌ Error saving history:", err);
    res.status(500).json({ error: "Failed to save history" });
  }
});


  // Fetch history
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
};
