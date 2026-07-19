let html5QrcodeScanner = null;

async function analyzePayload(payload) {
    const btnText = document.getElementById("btnText");
    const btnAnalyze = document.getElementById("btnAnalyze");
    
    // Step 14 Stage Animation Sequence
    btnAnalyze.disabled = true;
    btnText.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Checking URL...`;

    setTimeout(async () => {
        btnText.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Running Security Rules...`;
        
        setTimeout(async () => {
            btnText.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Generating Report...`;
            
            try {
                const response = await fetch("/analyze", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ payload: payload })
                });
                
                const data = await response.json();
                
                btnText.innerHTML = `<i class="fa-solid fa-check-double"></i> Analysis Complete`;
                displayResult(data);
            } catch (error) {
                alert("Network communication issue encountered while analyzing threat arrays.");
                btnText.innerHTML = `<i class="fa-solid fa-magnifying-glass"></i> Analyze`;
            } finally {
                btnAnalyze.disabled = false;
            }
        }, 400);
    }, 400);
}

function analyzeURL() {
    const urlInput = document.getElementById("urlInput");
    const url = urlInput.value.trim();
    if (url === "") {
        alert("Please target a valid string context parameter URL.");
        return;
    }
    analyzePayload(url);
}

function displayResult(data) {
    const analysis = data.analysis;
    const score = analysis.score;

    let verdictClass = "badge-safe";
    let verdictIcon = "fa-circle-check";
    let threatLevel = "LOW";
    let barColor = "#10B981"; // Premium Green

    if (analysis.verdict === "Suspicious") {
        verdictClass = "badge-suspicious";
        verdictIcon = "fa-triangle-exclamation";
        threatLevel = "MEDIUM";
        barColor = "#F59E0B"; // Premium Orange
    } else if (analysis.verdict === "Malicious") {
        verdictClass = "badge-malicious";
        verdictIcon = "fa-radiation";
        threatLevel = "HIGH";
        barColor = "#EF4444"; // Premium Red
    }

    // Creating safe metrics arrays for Passed vs Failed items
    const checkDefinitions = [
        { key: "uses_http", label: "HTTPS Protocol Enforced", inverted: true },
        { key: "uses_ip", label: "No Domain IP Addresses Address", inverted: true },
        { key: "url_shortener", label: "No System URL Shortener Links", inverted: true },
        { key: "suspicious_keywords", label: "No Suspicious Domain Keywords", inverted: true },
        { key: "long_url", label: "Standard Length Structure Profile", inverted: true }
    ];

    let triggeredRulesHTML = "";
    let passedRulesHTML = "";

    checkDefinitions.forEach(item => {
        const failedCondition = analysis.checks[item.key];
        if (failedCondition) {
            triggeredRulesHTML += `<li><i class="fa-solid fa-circle-xmark text-red"></i> ${item.label.replace("No ", "").replace("Enforced","Bypassed")}</li>`;
        } else {
            passedRulesHTML += `<li><i class="fa-solid fa-circle-check text-green"></i> ${item.label}</li>`;
        }
    });

    if(!triggeredRulesHTML) {
        triggeredRulesHTML = `<li class="text-muted"><i class="fa-solid fa-shield"></i> Clean Profile Match</li>`;
    }

    const html = `
        <div class="result-card animate-fade-in">
            <div class="result-header">
                <h3>Security Report</h3>
                <span class="verdict-badge ${verdictClass}"><i class="fa-solid ${verdictIcon}"></i> ${analysis.verdict.toUpperCase()}</span>
            </div>

            <!-- Meta metrics layout -->
            <div class="metrics-grid">
                <div class="metric-box">
                    <span class="lbl">Threat Level</span>
                    <span class="val ${threatLevel.toLowerCase()}-text">${threatLevel}</span>
                </div>
                <div class="metric-box">
                    <span class="lbl">Payload Type</span>
                    <span class="val text-blue">${data.payload_type}</span>
                </div>
                <div class="metric-box">
                    <span class="lbl">Protocol</span>
                    <span class="val">${analysis.protocol}</span>
                </div>
            </div>

            <!-- Decoded payload viewing card layout panel -->
            <div class="payload-display">
                <span class="lbl"><i class="fa-solid fa-code"></i> Decoded Target Content:</span>
                <div class="payload-text-box">${data.payload}</div>
                <div class="domain-info-node"><i class="fa-solid fa-network-wired"></i> Domain Host Context Target: <strong>${analysis.domain}</strong></div>
            </div>

            <!-- Risk Progress Indicator Meters -->
            <div class="meter-container">
                <div class="meter-labels">
                    <span class="lbl"><i class="fa-solid fa-gauge-high"></i> Risk Vulnerability Assessment Score</span>
                    <span class="val font-mono">${score} / 100</span>
                </div>
                <div class="meter-bar-track">
                    <div class="meter-bar-fill" style="width: ${Math.max(score, 5)}%; background-color: ${barColor};"></div>
                </div>
            </div>

            <!-- Advanced Rule Processing Matrices -->
            <div class="rule-tables-grid">
                <div class="rule-column">
                    <h4><i class="fa-solid fa-circle-exclamation text-orange"></i> Triggered Threat Profiles</h4>
                    <ul class="rule-list-nodes">${triggeredRulesHTML}</ul>
                </div>
                <div class="rule-column">
                    <h4><i class="fa-solid fa-circle-check text-green"></i> Passed Engine Verifications</h4>
                    <ul class="rule-list-nodes">${passedRulesHTML}</ul>
                </div>
            </div>
        </div>
    `;

    const container = document.getElementById("result-placeholder");
    container.className = "result-panel-active";
    container.innerHTML = html;
}

function toggleScanner() {
    const readerContainer = document.getElementById("reader-container");
    const btnCamera = document.getElementById("btnCamera");


    if (html5QrcodeScanner) {
        html5QrcodeScanner.stop().then(() => {
            html5QrcodeScanner = null;
            readerContainer.classList.add("hidden");
            btnCamera.innerHTML = `<i class="fa-solid fa-video"></i> Start Camera`;
            // Reset to default button style
            btnCamera.style.background = "#FFFFFF";
            btnCamera.style.color = "#111827";
        });
    } else {
        readerContainer.classList.remove("hidden");
        btnCamera.innerHTML = `<i class="fa-solid fa-video-slash"></i> Close Camera`;
        // Make the close button a soft red for the light theme
        btnCamera.style.background = "#FEE2E2"; 
        btnCamera.style.color = "#B91C1C";
        btnCamera.style.border = "1px solid #FCA5A5";
    }
    
}