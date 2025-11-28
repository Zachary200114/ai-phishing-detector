import { useState, useEffect } from "react";

function App() {
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [rawHeaders, setRawHeaders] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [history, setHistory] = useState([]);

  const [rewriteResult, setRewriteResult] = useState(null);
  const [rewriteLoading, setRewriteLoading] = useState(false);
  const [rewriteError, setRewriteError] = useState("");

  // Load analysis history from backend
  async function loadHistory() {
    try {
      const response = await fetch("http://localhost:8000/history");
      if (!response.ok) {
        throw new Error(
          "History request failed with status " + response.status
        );
      }
      const data = await response.json();
      setHistory(data);
    } catch (err) {
      console.error("Failed to load history:", err);
    }
  }

  // Load history once when the app starts
  useEffect(function () {
    loadHistory();
  }, []);

  // Handle analysis submit
  async function handleSubmit(e) {
    e.preventDefault();
    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch("http://localhost:8000/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          subject: subject,
          body: body,
          raw_headers: rawHeaders,
        }),
      });

      if (!response.ok) {
        throw new Error("Request failed with status " + response.status);
      }

      const data = await response.json();
      setResult(data);

      // Refresh history after a new analysis is saved
      await loadHistory();
    } catch (err) {
      setError(err.message || "Something went wrong");
    } finally {
      setLoading(false);
    }
  }

  // Handle safe rewrite
  async function handleRewrite() {
    setRewriteLoading(true);
    setRewriteError("");
    setRewriteResult(null);

    try {
      const response = await fetch("http://localhost:8000/rewrite-safe", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          subject: subject,
          body: body,
        }),
      });

      if (!response.ok) {
        throw new Error(
          "Rewrite request failed with status " + response.status
        );
      }

      const data = await response.json();
      setRewriteResult(data);
    } catch (err) {
      setRewriteError(err.message || "Something went wrong during rewrite");
    } finally {
      setRewriteLoading(false);
    }
  }

  function getScoreColor(score) {
    if (score <= 30) return "green";
    if (score <= 69) return "orange";
    return "red";
  }

  return (
    <div style={{ maxWidth: "900px", margin: "0 auto", padding: "1rem" }}>
      <h1>AI-Powered Phishing Email Detector (Prototype)</h1>
      <p>
        Paste an email and I will guess if it is phishing, and I can also
        rewrite it as a safe, legitimate email.
      </p>

      <form onSubmit={handleSubmit} style={{ display: "grid", gap: "1rem" }}>
        <div>
          <label>
            Subject:
            <input
              type="text"
              value={subject}
              onChange={function (e) {
                setSubject(e.target.value);
              }}
              style={{ width: "100%", padding: "0.5rem", marginTop: "0.25rem" }}
              placeholder="e.g. Important: Reset Your Password Now"
              required
            />
          </label>
        </div>

        <div>
          <label>
            Email Body:
            <textarea
              value={body}
              onChange={function (e) {
                setBody(e.target.value);
              }}
              style={{
                width: "100%",
                height: "180px",
                padding: "0.5rem",
                marginTop: "0.25rem",
              }}
              placeholder="Paste the email content here..."
              required
            />
          </label>
        </div>

        <details>
          <summary>Advanced: Raw Headers (optional)</summary>
          <textarea
            value={rawHeaders}
            onChange={function (e) {
              setRawHeaders(e.target.value);
            }}
            style={{
              width: "100%",
              height: "140px",
              padding: "0.5rem",
              marginTop: "0.5rem",
            }}
            placeholder="Paste full email headers if you have them..."
          />
        </details>

        <div
          style={{
            display: "flex",
            gap: "1rem",
            flexWrap: "wrap",
            marginTop: "0.5rem",
          }}
        >
          <button
            type="submit"
            disabled={loading}
            style={{
              padding: "0.75rem 1.25rem",
              fontSize: "1rem",
              cursor: "pointer",
            }}
          >
            {loading ? "Analyzing..." : "Analyze Email"}
          </button>

          <button
            type="button"
            disabled={rewriteLoading || body.trim() === ""}
            onClick={handleRewrite}
            style={{
              padding: "0.75rem 1.25rem",
              fontSize: "1rem",
              cursor:
                rewriteLoading || body.trim() === "" ? "default" : "pointer",
            }}
          >
            {rewriteLoading ? "Rewriting..." : "Rewrite as Safe Email"}
          </button>
        </div>
      </form>

      {error && (
        <div
          style={{
            marginTop: "1rem",
            padding: "0.75rem",
            border: "1px solid red",
          }}
        >
          <strong>Error:</strong> {error}
        </div>
      )}

      {result && (
        <div
          style={{
            marginTop: "1.5rem",
            padding: "1rem",
            border: "1px solid #ccc",
            borderRadius: "8px",
          }}
        >
          <h2>Analysis Result</h2>

          <p>
            <strong>Risk Score: </strong>
            <span
              style={{
                fontWeight: "bold",
                color: getScoreColor(result.risk_score),
              }}
            >
              {result.risk_score} / 100
            </span>
          </p>

          <p>
            <strong>Verdict: </strong>
            {result.verdict}
          </p>

          <p>
            <strong>Model: </strong>
            {result.model_name}
          </p>

          <p>
            <strong>Analyzed At: </strong>
            {result.created_at}
          </p>

          <h3>Reasons</h3>
          <ul>
            {result.reasons && result.reasons.length > 0 ? (
              result.reasons.map(function (reason, index) {
                return <li key={index}>{reason}</li>;
              })
            ) : (
              <li>No reasons provided.</li>
            )}
          </ul>

          <h3>Header Analysis</h3>
          {result.header_analysis ? (
            <ul>
              <li>SPF Pass: {String(result.header_analysis.spf_pass)}</li>
              <li>DKIM Pass: {String(result.header_analysis.dkim_pass)}</li>
              <li>DMARC Pass: {String(result.header_analysis.dmarc_pass)}</li>
              <li>
                Suspicious Flags:
                {result.header_analysis.suspicious_flags &&
                result.header_analysis.suspicious_flags.length > 0 ? (
                  <ul>
                    {result.header_analysis.suspicious_flags.map(function (
                      flag,
                      index
                    ) {
                      return <li key={index}>{flag}</li>;
                    })}
                  </ul>
                ) : (
                  " None"
                )}
              </li>
            </ul>
          ) : (
            <p>No header info.</p>
          )}
        </div>
      )}

      {/* Safe Rewrite Section */}
      {(rewriteResult || rewriteError) && (
        <div
          style={{
            marginTop: "1.5rem",
            padding: "1rem",
            border: "1px solid #ccc",
            borderRadius: "8px",
          }}
        >
          <h2>Safe Email Rewrite</h2>

          {rewriteError && (
            <div
              style={{
                marginTop: "0.5rem",
                padding: "0.5rem",
                border: "1px solid red",
              }}
            >
              <strong>Error:</strong> {rewriteError}
            </div>
          )}

          {rewriteResult && (
            <>
              <p>
                <strong>Safe Subject:</strong> {rewriteResult.safe_subject}
              </p>

              <h3>Safe Body</h3>
              <pre
                style={{
                  whiteSpace: "pre-wrap",
                  backgroundColor: "#111",
                  padding: "0.75rem",
                  borderRadius: "4px",
                }}
              >
                {rewriteResult.safe_body}
              </pre>

              <h3>Changes Highlighted</h3>
              <p style={{ fontSize: "0.9rem" }}>
                <span
                  style={{
                    backgroundColor: "#8b0000",
                    color: "white",
                    padding: "0 4px",
                    marginRight: "0.5rem",
                  }}
                >
                  Removed
                </span>
                <span
                  style={{
                    backgroundColor: "#006400",
                    color: "white",
                    padding: "0 4px",
                  }}
                >
                  Added
                </span>
              </p>
              <div
                style={{
                  marginTop: "0.5rem",
                  padding: "0.75rem",
                  backgroundColor: "#111",
                  borderRadius: "4px",
                }}
                dangerouslySetInnerHTML={{ __html: rewriteResult.diff_html }}
              />
            </>
          )}
        </div>
      )}

      {/* Analysis History Section */}
      <div
        style={{
          marginTop: "2rem",
          padding: "1rem",
          border: "1px solid #ccc",
          borderRadius: "8px",
        }}
      >
        <h2>Analysis History</h2>
        <p>Most recent scans (stored in SQLite on the backend).</p>

        {history.length === 0 ? (
          <p>No analyses yet.</p>
        ) : (
          <table
            style={{
              width: "100%",
              borderCollapse: "collapse",
              marginTop: "0.75rem",
            }}
          >
            <thead>
              <tr>
                <th
                  style={{
                    borderBottom: "1px solid #666",
                    textAlign: "left",
                    padding: "0.25rem",
                  }}
                >
                  Time
                </th>
                <th
                  style={{
                    borderBottom: "1px solid #666",
                    textAlign: "left",
                    padding: "0.25rem",
                  }}
                >
                  Subject
                </th>
                <th
                  style={{
                    borderBottom: "1px solid #666",
                    textAlign: "left",
                    padding: "0.25rem",
                  }}
                >
                  Score
                </th>
                <th
                  style={{
                    borderBottom: "1px solid #666",
                    textAlign: "left",
                    padding: "0.25rem",
                  }}
                >
                  Verdict
                </th>
              </tr>
            </thead>
            <tbody>
              {history.map(function (item) {
                return (
                  <tr key={item.id}>
                    <td
                      style={{
                        borderBottom: "1px solid #333",
                        padding: "0.25rem",
                        fontSize: "0.85rem",
                      }}
                    >
                      {new Date(item.created_at).toLocaleString()}
                    </td>
                    <td
                      style={{
                        borderBottom: "1px solid #333",
                        padding: "0.25rem",
                        fontSize: "0.9rem",
                      }}
                    >
                      {item.subject}
                    </td>
                    <td
                      style={{
                        borderBottom: "1px solid #333",
                        padding: "0.25rem",
                      }}
                    >
                      {item.risk_score}
                    </td>
                    <td
                      style={{
                        borderBottom: "1px solid #333",
                        padding: "0.25rem",
                      }}
                    >
                      {item.verdict}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

export default App;
