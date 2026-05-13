chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        chrome.action.setBadgeText({ text: "...", tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#FFA500", tabId: tabId });

        try {
            let formData = new FormData();
            formData.append("url", tab.url);
            let res = await fetch("https://phishing-url-detector-0y93.onrender.com/", { method: "POST", body: formData });
            let text = await res.text();
            
            // Extract the exact numerical score from the HTML
            let match = text.match(/let x = "([^"]+)"/);
            let score = match ? parseFloat(match[1]) : -1;

            if (score >= 0.5) {
                chrome.action.setBadgeText({ text: "SAFE", tabId: tabId });
                chrome.action.setBadgeBackgroundColor({ color: "#28a745", tabId: tabId });
            } else if (score !== -1) {
                chrome.action.setBadgeText({ text: "RISK", tabId: tabId });
                chrome.action.setBadgeBackgroundColor({ color: "#dc3545", tabId: tabId });
            }
        } catch (e) {
            chrome.action.setBadgeText({ text: "ERR", tabId: tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#6c757d", tabId: tabId });
        }
    }
});