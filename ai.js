document.addEventListener("DOMContentLoaded", () => {
  const chatBtn = document.getElementById("chatbot-btn");
  const chatWindow = document.getElementById("chat-window");
  const sendBtn = document.getElementById("send-btn");
  const chatInput = document.getElementById("chat-input");
  const chatMessages = document.getElementById("chat-messages");

  let isOpen = false;
  const email = localStorage.getItem("email");
  const username = localStorage.getItem("username");
  const userIdentifier = email || username; // Prefer email if available

  if (!userIdentifier) {
    console.warn("No logged-in user found. AI chat disabled.");
    return;
  }

  // --- Toggle chatbot visibility ---
  chatBtn.addEventListener("click", () => {
    isOpen = !isOpen;
    chatWindow.style.height = isOpen ? "360px" : "0";
  });

  // --- Load previous chat history ---
  async function loadHistory() {
    try {
      const res = await fetch(`/ai-history?email=${encodeURIComponent(userIdentifier)}`);
      const history = await res.json();

      chatMessages.innerHTML = "";
      history.forEach(item => {
        addMessage("You", item.prompt);
        addMessage("AI", item.response);
      });
    } catch (err) {
      console.error("Failed to load AI history:", err);
    }
  }

  // --- Add a message to the chat UI ---
  function addMessage(sender, text) {
    const div = document.createElement("div");
    div.style.marginBottom = "8px";
    div.innerHTML = `<strong>${sender}:</strong> ${text}`;
    chatMessages.appendChild(div);
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }

  // --- Send a new message to AI ---
  async function sendMessage() {
    const prompt = chatInput.value.trim();
    if (!prompt) return;

    addMessage("You", prompt);
    chatInput.value = "";

    try {
      const res = await fetch("/chat-ai", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: userIdentifier, prompt })
      });

      const data = await res.json();
      addMessage("AI", data.reply || "No response from AI.");
    } catch (err) {
      addMessage("AI", "Error: Could not connect to AI.");
      console.error(err);
    }
  }

  // --- Event listeners ---
  sendBtn.addEventListener("click", sendMessage);
  chatInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      sendMessage();
    }
  });

  // Load history on page load
  loadHistory();
});
