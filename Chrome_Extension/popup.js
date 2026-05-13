document.addEventListener('DOMContentLoaded', async () => {
    const resultElement = document.getElementById("result");
    const urlDisplay = document.getElementById("urlDisplay");
    const reportBtn = document.getElementById("reportBtn");

    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    urlDisplay.innerText = tab.url;

    try {
        let formData = new FormData();
        formData.append("url", tab.url); 
        let response = await fetch("https://phishing-url-detector-0y93.onrender.com/", { method: "POST", body: formData });
        let text = await response.text();
        
        let match = text.match(/let x = "([^"]+)"/);
        let score = match ? parseFloat(match[1]) : -1;
        
        if (score >= 0.5) {
            resultElement.innerText = "✅ SAFE";
            resultElement.className = "safe";
        } else if (score !== -1) {
            resultElement.innerText = "🚨 RISK";
            resultElement.className = "phishing";
        } else {
            resultElement.innerText = "⚠️ Unscannable";
            resultElement.className = "scanning";
        }

        reportBtn.style.display = "block";
        reportBtn.onclick = () => {
            chrome.tabs.create({ url: `https://phishing-url-detector-0y93.onrender.com/?url=${encodeURIComponent(tab.url)}` });
        };
    } catch (error) {
        resultElement.innerText = "⚠️ Server Error";
        resultElement.className = "phishing";
    }
});