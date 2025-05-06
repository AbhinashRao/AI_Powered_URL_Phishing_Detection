// ==UserScript==
// @name         TrustLink Security
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  Advanced malicious website detection using blocklists and AI analysis
// @author       Ujjawal Saini, Divyanshu Shukla
// @match        *://*/*
// @grant        GM_xmlhttpRequest
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        GM_addStyle
// @connect      127.0.0.1
// @connect      localhost
// @run-at       document-start
// ==/UserScript==

(function() {
    'use strict';

    // Configuration
    const API_URL = 'http://127.0.0.1:5000/predict';
    const CACHE_KEY = 'TrustLinkCache';
    const CACHE_DURATION = 6 * 60 * 60 * 1000; // 6 hours cache
    const BLOCK_THRESHOLD = 0.85; // 85% confidence threshold
    const WARNING_THRESHOLD = 0.65; // 65% confidence threshold

    // Add warning styles
    GM_addStyle(`
        .trustlink-warning {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            padding: 15px;
            background-color: #ff6b6b;
            color: white;
            text-align: center;
            z-index: 999999;
            box-shadow: 0 2px 10px rgba(0,0,0,0.2);
            font-family: Arial, sans-serif;
        }
        .trustlink-warning h3 {
            margin: 0 0 10px 0;
            font-size: 18px;
        }
        .trustlink-warning p {
            margin: 5px 0;
            font-size: 14px;
        }
        .trustlink-warning button {
            background: white;
            color: #ff6b6b;
            border: none;
            padding: 8px 15px;
            margin: 10px 5px 0;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
        }
        .trustlink-warning button:hover {
            background: #f0f0f0;
        }
        .trustlink-warning .risk-level {
            font-weight: bold;
            font-size: 16px;
        }
        .trustlink-warning .high-risk {
            color: #ff0000;
        }
        .trustlink-warning .medium-risk {
            color: #ff9900;
        }
    `);

    // Show warning message with options
    function showWarning(threatData) {
        // Don't show multiple warnings
        if (document.getElementById('trustlink-warning')) return;

        const threatType = threatData.label;
        const confidence = threatData.score;
        const source = threatData.source || 'AI analysis';

        let riskLevel = 'Medium';
        let riskClass = 'medium-risk';
        if (confidence >= BLOCK_THRESHOLD) {
            riskLevel = 'High';
            riskClass = 'high-risk';
        }

        const warningDiv = document.createElement('div');
        warningDiv.id = 'trustlink-warning';
        warningDiv.className = 'trustlink-warning';
        warningDiv.innerHTML = `
            <h3>⚠️ Security Warning</h3>
            <p>This website has been identified as potentially harmful.</p>
            <p><strong>Threat type:</strong> ${threatType} | <strong>Source:</strong> ${source}</p>
            <p><strong>Confidence:</strong> ${(confidence * 100).toFixed(1)}%</p>
            <p class="risk-level ${riskClass}">Risk level: ${riskLevel}</p>
            <div>
                <button id="trustlink-leave">Leave this site</button>
                <button id="trustlink-continue">Continue anyway</button>
            </div>
        `;

        document.body.prepend(warningDiv);

        // Add event listeners
        document.getElementById('trustlink-leave').addEventListener('click', () => {
            window.location.href = 'https://www.google.com';
        });

        document.getElementById('trustlink-continue').addEventListener('click', () => {
            warningDiv.remove();
            // Cache this decision for this session
            sessionStorage.setItem(`trustlink-allowed-${window.location.hostname}`, 'true');
        });
    }

    // Block the page completely for high-confidence threats
    function blockPage(threatData) {
        // Check if user has already chosen to continue
        if (sessionStorage.getItem(`trustlink-allowed-${window.location.hostname}`) === 'true') {
            return;
        }

        // Replace entire page with warning
        document.documentElement.innerHTML = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>Security Warning</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        text-align: center;
                        padding: 50px;
                        background-color: #ffebee;
                        color: #b71c1c;
                    }
                    .container {
                        max-width: 600px;
                        margin: 0 auto;
                    }
                    h1 {
                        font-size: 28px;
                        margin-bottom: 20px;
                    }
                    p {
                        font-size: 16px;
                        margin-bottom: 25px;
                    }
                    .threat-info {
                        background: white;
                        padding: 15px;
                        border-radius: 5px;
                        margin: 20px 0;
                        text-align: left;
                    }
                    button {
                        background: #b71c1c;
                        color: white;
                        border: none;
                        padding: 10px 20px;
                        margin: 10px;
                        border-radius: 4px;
                        cursor: pointer;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>⚠️ Security Alert</h1>
                    <p>This website has been blocked because it appears to be dangerous.</p>
                    
                    <div class="threat-info">
                        <p><strong>Threat type:</strong> ${threatData.label}</p>
                        <p><strong>Confidence:</strong> ${(threatData.score * 100).toFixed(1)}%</p>
                        <p><strong>Source:</strong> ${threatData.source || 'AI analysis'}</p>
                    </div>
                    
                    <p>We strongly recommend you do not continue to this website.</p>
                    
                    <div>
                        <button onclick="window.location.href='https://www.google.com'">Back to safety</button>
                        <button onclick="document.getElementById('continue-warning').style.display='block';this.style.display='none'">I understand the risks</button>
                    </div>
                    
                    <div id="continue-warning" style="display:none; margin-top:20px;">
                        <p>You are about to proceed to a potentially harmful website.</p>
                        <button onclick="sessionStorage.setItem('trustlink-allowed-${window.location.hostname}', 'true'); window.location.reload();">Continue at my own risk</button>
                    </div>
                </div>
            </body>
            </html>
        `;
    }

    // Check URL against API
    function checkUrl(url) {
        // Check cache first
        const cached = GM_getValue(CACHE_KEY, {});
        const cachedResult = cached[url];
        
        if (cachedResult && (Date.now() - cachedResult.timestamp < CACHE_DURATION)) {
            processResult(cachedResult.data);
            return;
        }

        GM_xmlhttpRequest({
            method: 'POST',
            url: API_URL,
            headers: { 'Content-Type': 'application/json' },
            data: JSON.stringify({ url }),
            onload: function(response) {
                try {
                    const result = JSON.parse(response.responseText);
                    
                    // Update cache
                    const cache = GM_getValue(CACHE_KEY, {});
                    cache[url] = {
                        data: result,
                        timestamp: Date.now()
                    };
                    GM_setValue(CACHE_KEY, cache);
                    
                    processResult(result);
                } catch (error) {
                    console.error('TrustLink: Error parsing API response', error);
                }
            },
            onerror: function(error) {
                console.error('TrustLink: API request failed', error);
            }
        });
    }

    // Process API response
    function processResult(result) {
        // Handle blocklist response
        if (result.source === 'blocklist') {
            blockPage({
                label: 'Known malicious domain',
                score: 0.95,
                source: 'Blocklist'
            });
            return;
        }

        // Convert to array format if needed
        const results = Array.isArray(result) ? result : Object.entries(result).map(([label, score]) => ({ label, score }));

        // Find highest threat
        const highestThreat = results.reduce((max, curr) => 
            curr.score > max.score ? curr : max, { score: 0 });

        // Take action based on threat level
        if (highestThreat.score >= BLOCK_THRESHOLD) {
            blockPage(highestThreat);
        } else if (highestThreat.score >= WARNING_THRESHOLD) {
            showWarning(highestThreat);
        }
    }

    // Main execution
    const currentUrl = window.location.href;
    checkUrl(currentUrl);

})();