document.addEventListener("DOMContentLoaded", () => {
  const chatbotBtn = document.getElementById("chatbot-btn");
  const chatWindow = document.getElementById("chat-window");
  const chatMessages = document.getElementById("chat-messages");
  const chatInput = document.getElementById("chat-input");
  const sendBtn = document.getElementById("send-btn");
  const email = localStorage.getItem("email");

  if (!email) {
    console.warn("User not logged in, chatbot disabled.");
    return;
  }

  let isOpen = false;

  // Toggle chatbot visibility
  chatbotBtn.addEventListener("click", () => {
    isOpen = !isOpen;
    chatWindow.style.height = isOpen ? "320px" : "0";
  });

  // Add message to chat
  function addMessage(sender, text) {
    const msg = document.createElement("div");
    msg.style.marginBottom = "8px";
    msg.style.padding = "8px";
    msg.style.borderRadius = "8px";
    msg.style.background = sender === "user" ? "#E0E0E0" : "#F3E8FF";
    msg.textContent = `${sender === "user" ? "You" : "AI"}: ${text}`;
    chatMessages.appendChild(msg);
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }

  // Load chat history
  async function loadHistory() {
    try {
      const res = await fetch(`/ai-history?email=${encodeURIComponent(email)}`);
      const history = await res.json();
      chatMessages.innerHTML = "";
      history.forEach(item => {
        addMessage("user", item.prompt);
        addMessage("ai", item.response);
      });
    } catch (err) {
      console.error("Failed to load chat history:", err);
    }
  }

  // Send a new message
  async function sendMessage() {
    const prompt = chatInput.value.trim();
    if (!prompt) return;

    addMessage("user", prompt);
    chatInput.value = "";

    try {
      const res = await fetch("/chat-ai", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, prompt })
      });

      const data = await res.json();
      addMessage("ai", data.reply || "No response received.");
    } catch (err) {
      addMessage("ai", "Error: Unable to get response.");
      console.error(err);
    }
  }

  // Handle send button and Enter key
  sendBtn.addEventListener("click", sendMessage);
  chatInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      sendMessage();
    }
  });

  loadHistory();
});
