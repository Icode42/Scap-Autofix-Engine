const http = require("http");
const { exec } = require("child_process");

const PORT = 3001;

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "http://localhost:5173",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
};

function runPowerShell(command) {
  return new Promise((resolve) => {
    // Write command to a temp file to avoid escaping issues
    const tmpFile = `C:\\Windows\\Temp\\scap_fix_${Date.now()}.ps1`;
    const fs = require("fs");
    
    const script = `
try {
  $result = & {
    ${command}
  } 2>&1
  $output = ($result | Out-String).Trim()
  if ($output -match "MANUAL") {
    Write-Output $output
  } elseif ($output -match "ERROR") {
    Write-Output "ERROR: $output"
  } else {
    Write-Output "SUCCESS"
  }
} catch {
  Write-Output "ERROR: $_"
}
`;
    try {
      fs.writeFileSync(tmpFile, script, "utf8");
    } catch(e) {
      resolve({ success: false, output: "Failed to write temp script: " + e.message });
      return;
    }

    const psCmd = `powershell.exe -NonInteractive -NoProfile -ExecutionPolicy Bypass -File "${tmpFile}"`;

    exec(psCmd, { timeout: 30000 }, (error, stdout, stderr) => {
      // Clean up temp file
      try { fs.unlinkSync(tmpFile); } catch(e) {}
      
      const output = (stdout || "").trim();
      const errOut = (stderr || "").trim();

      if (output.includes("ERROR:")) {
        resolve({ success: false, output: output.replace("ERROR: ", "") });
      } else if (output.includes("MANUAL:") || output.includes("MANUAL REVIEW REQUIRED")) {
        resolve({ success: false, output: output, manual: true });
      } else if (output.includes("SUCCESS") || output.length > 0) {
        resolve({ success: true, output: output.replace("SUCCESS", "").trim() || "Command completed." });
      } else if (error) {
        resolve({ success: false, output: errOut || error.message });
      } else {
        resolve({ success: true, output: "Command completed." });
      }
    });
  });
}

const server = http.createServer(async (req, res) => {
  if (req.method === "OPTIONS") {
    res.writeHead(204, CORS_HEADERS);
    res.end();
    return;
  }

  if (req.method === "POST" && req.url === "/remediate") {
    let body = "";
    req.on("data", chunk => { body += chunk; });
    req.on("end", async () => {
      try {
        const { ruleId, title, remediation } = JSON.parse(body);
        console.log(`[EXEC] ${ruleId} - ${title}`);
        console.log(`  PS> ${remediation.split("\n")[0].slice(0, 80)}`);
        const result = await runPowerShell(remediation);
        console.log(result.success ? `  OK: ${result.output}` : `  FAIL: ${result.output}`);
        res.writeHead(200, CORS_HEADERS);
        res.end(JSON.stringify({ success: result.success, output: result.output, ruleId }));
      } catch (e) {
        res.writeHead(400, CORS_HEADERS);
        res.end(JSON.stringify({ success: false, output: e.message }));
      }
    });
    return;
  }

  if (req.method === "POST" && req.url === "/ping") {
    res.writeHead(200, CORS_HEADERS);
    res.end(JSON.stringify({ status: "ok", message: "SCAP AutoFix backend running" }));
    return;
  }

  res.writeHead(404, CORS_HEADERS);
  res.end(JSON.stringify({ error: "Not found" }));
});

server.listen(PORT, "127.0.0.1", () => {
  console.log("============================================");
  console.log("  SCAP AutoFix Backend - PowerShell Engine");
  console.log(`  Listening on http://127.0.0.1:${PORT}`);
  console.log("  IMPORTANT: Must run as Administrator");
  console.log("============================================\n");
});

server.on("error", (e) => {
  if (e.code === "EADDRINUSE") {
    console.error(`Port ${PORT} already in use. Close other instances first.`);
  } else {
    console.error("Server error:", e.message);
  }
  process.exit(1);
});
