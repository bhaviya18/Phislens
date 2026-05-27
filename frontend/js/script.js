const analyzeBtn = document.getElementById("analyzeBtn");

const exportBtn = document.getElementById("exportBtn");

const loadCasesBtn = document.getElementById("loadCasesBtn");

const resultText = document.getElementById("resultText");

const casesContainer = document.getElementById("casesContainer");

let latestReport = "";


analyzeBtn.addEventListener("click", async () => {

    const fileInput = document.getElementById("emailFile");

    const file = fileInput.files[0];

    if (!file) {

        resultText.innerText =
            "Please select an email file.";

        return;
    }

    resultText.innerText =
        "Running phishing investigation...";

    const formData = new FormData();

    formData.append("file", file);

    try {

        const response = await fetch(
            "http://127.0.0.1:8000/analyze",
            {
                method: "POST",
                body: formData
            }
        );

        const data = await response.json();

        let headerOutput = "";

        data.header_analysis.forEach(item => {

            headerOutput += `• ${item}\n`;

        });

        let keywordOutput = "";

        data.keywords_detected.forEach(item => {

            keywordOutput += `• ${item}\n`;

        });

        let urlOutput = "";

        data.urls_detected.forEach(item => {

            urlOutput += `• ${item}\n`;

        });

        let psychologyOutput = "";

        data.psychology_analysis.forEach(item => {

            psychologyOutput += `• ${item}\n`;

        });

        let reputationOutput = "";

        data.url_reputation_analysis.forEach(item => {

            reputationOutput +=
`
━━━━━━━━━━━━━━━━━━━━━━━━━━

URL:
${item.url}

Reputation:
${item.reputation}

Reasons:

${item.reasons.map(reason => `• ${reason}`).join("\n")}
`;
        });

        let iocOutput = `
DOMAINS
${data.iocs.domains.map(domain => `• ${domain}`).join("\n")}

EMAIL ADDRESSES
${data.iocs.email_addresses.map(email => `• ${email}`).join("\n")}
`;

        latestReport =
`
╔══════════════════════════════════════╗
              PHISHLENS REPORT
╚══════════════════════════════════════╝


CASE INFORMATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Filename:
${data.filename}


EMAIL METADATA
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Sender:
${data.sender}

Receiver:
${data.receiver}

Subject:
${data.subject}


RISK ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Risk Level:
${data.risk_level}

Phishing Score:
${data.phishing_score}/100

Threat Classification:
${data.classification}

Confidence Level:
${data.confidence}


HEADER ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${headerOutput}


DETECTED PHISHING KEYWORDS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${keywordOutput}


EXTRACTED URLS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${urlOutput}


IOC EXTRACTION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${iocOutput}


URL REPUTATION ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${reputationOutput}


AI PSYCHOLOGICAL ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${psychologyOutput}


RECOMMENDED ACTION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${data.recommended_action}


FINAL ANALYST VERDICT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${data.classification}

This email demonstrates phishing-related
behavioral, technical, and social
engineering characteristics consistent
with malicious credential harvesting
activity.
`;

        resultText.innerText = latestReport;

    }

    catch (error) {

        resultText.innerText =
`
Backend connection failed.

${error}
`;
    }

});


exportBtn.addEventListener("click", () => {

    if (!latestReport) {

        alert("No report available to export.");

        return;
    }

    const blob = new Blob(
        [latestReport],
        { type: "text/plain" }
    );

    const url = window.URL.createObjectURL(blob);

    const a = document.createElement("a");

    a.href = url;

    a.download =
        `PhishLens_Report_${Date.now()}.txt`;

    document.body.appendChild(a);

    a.click();

    document.body.removeChild(a);

    window.URL.revokeObjectURL(url);

});


loadCasesBtn.addEventListener("click", async () => {

    casesContainer.innerHTML =
        "Loading investigation history...";

    try {

        const response = await fetch(
            "http://127.0.0.1:8000/cases"
        );

        const cases = await response.json();

        if (cases.length === 0) {

            casesContainer.innerHTML =
                "<p>No stored investigations found.</p>";

            return;
        }

        casesContainer.innerHTML = "";

        cases.reverse().forEach(caseItem => {

            let riskClass = "low-risk";

            if (caseItem.risk_level === "HIGH RISK") {
                riskClass = "high-risk";
            }

            else if (caseItem.risk_level === "MEDIUM RISK") {
                riskClass = "medium-risk";
            }

            const caseCard = document.createElement("div");

            caseCard.classList.add("case-card");

            caseCard.innerHTML =
`
<h3>${caseItem.subject}</h3>

<p>
<strong>Classification:</strong>
${caseItem.classification}
</p>

<p>
<strong>Confidence:</strong>
${caseItem.confidence}
</p>

<p>
<strong>Sender:</strong>
${caseItem.sender}
</p>

<p class="${riskClass}">
<strong>Risk Level:</strong>
${caseItem.risk_level}
</p>

<p>
<strong>Phishing Score:</strong>
${caseItem.phishing_score}/100
</p>

<p>
<strong>Timestamp:</strong>
${caseItem.timestamp}
</p>
`;

            casesContainer.appendChild(caseCard);

        });

    }

    catch (error) {

        casesContainer.innerHTML =
`
Failed to load investigation history.

${error}
`;
    }

});