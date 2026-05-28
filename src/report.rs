use serde_json::Value;
use chrono::Utc;

#[derive(Clone, Debug)]
pub struct SecurityReport {
    pub scan_id: String,
    pub service: String,
    pub timestamp: String,
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub iso_27001_controls: Vec<ControlAssessment>,
    pub recommendations: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ControlAssessment {
    pub control_id: String,
    pub control_name: String,
    pub description: String,
    pub status: String, // "Compliant", "Non-Compliant", "Partial"
    pub findings: Vec<String>,
    pub remediation: String,
}

pub fn generate_iso_report(
    scan_id: &str,
    service: &str,
    findings: &[Value],
) -> SecurityReport {
    let critical_count = findings.iter()
        .filter(|f| f.get("severity").and_then(|s| s.as_str()) == Some("Critical"))
        .count();
    let high_count = findings.iter()
        .filter(|f| f.get("severity").and_then(|s| s.as_str()) == Some("High"))
        .count();
    let medium_count = findings.iter()
        .filter(|f| f.get("severity").and_then(|s| s.as_str()) == Some("Medium"))
        .count();
    let low_count = findings.iter()
        .filter(|f| f.get("severity").and_then(|s| s.as_str()) == Some("Low"))
        .count();

    let controls = map_to_iso_controls(findings);
    let recommendations = generate_recommendations(&controls);

    SecurityReport {
        scan_id: scan_id.to_string(),
        service: service.to_string(),
        timestamp: Utc::now().to_rfc3339(),
        total_findings: findings.len(),
        critical: critical_count,
        high: high_count,
        medium: medium_count,
        low: low_count,
        iso_27001_controls: controls,
        recommendations,
    }
}

fn map_to_iso_controls(findings: &[Value]) -> Vec<ControlAssessment> {
    let mut controls: std::collections::HashMap<&str, ControlAssessment> = std::collections::HashMap::new();

    for finding in findings {
        let title = finding.get("title").and_then(|t| t.as_str()).unwrap_or("");
        let owasp = finding.get("owasp").and_then(|o| o.as_str()).unwrap_or("");

        // Map OWASP to ISO 27001 controls
        let (control_id, control_name, description) = match owasp {
            "A01:2021" => ("A.9.2.1", "User Registration & Access Management", "Access control violations - A01"),
            "A02:2021" => ("A.10.1.1", "Cryptographic Controls", "Cryptographic failures - A02"),
            "A03:2021" => ("A.12.4.1", "Logging & Monitoring", "Injection attacks - A03"),
            "A04:2021" => ("A.14.2.1", "Secure Development", "Insecure design - A04"),
            "A05:2021" => ("A.13.1.1", "Network Security", "Security misconfiguration - A05"),
            "A06:2021" => ("A.12.6.1", "Management of Technical Vulnerabilities", "Vulnerable components - A06"),
            "A07:2021" => ("A.9.4.3", "Password Management", "Authentication failures - A07"),
            "A08:2021" => ("A.14.1.2", "Change Management", "Data integrity failures - A08"),
            "A09:2021" => ("A.12.4.1", "Event Logging", "Logging failures - A09"),
            "A10:2021" => ("A.13.1.3", "Segregation of Networks", "SSRF - A10"),
            _ if title.to_lowercase().contains("xss") => ("A.12.2.1", "Access to Programs & Data", "XSS vulnerability"),
            _ => ("A.12.2.1", "General Security", "General finding"),
        };

        controls.entry(control_id)
            .or_insert_with(|| ControlAssessment {
                control_id: control_id.to_string(),
                control_name: control_name.to_string(),
                description: description.to_string(),
                status: "Non-Compliant".to_string(),
                findings: Vec::new(),
                remediation: String::new(),
            })
            .findings.push(title.to_string());
    }

    // Sort by control ID
    let mut result: Vec<_> = controls.into_values().collect();
    result.sort_by(|a, b| a.control_id.cmp(&b.control_id));

    // Add remediation guidance
    for control in &mut result {
        control.remediation = match control.control_id.as_str() {
            "A.9.2.1" => "Implement strong authentication (MFA), enforce access control policies, conduct access reviews".to_string(),
            "A.10.1.1" => "Use TLS 1.2+, implement strong encryption (AES-256), use secure key management".to_string(),
            "A.12.4.1" => "Implement comprehensive logging, monitor for injection patterns, use parameterized queries".to_string(),
            "A.14.2.1" => "Follow secure SDLC, threat modeling, secure code review, penetration testing".to_string(),
            "A.13.1.1" => "Use WAF, implement rate limiting, network segmentation, DDoS protection".to_string(),
            "A.12.6.1" => "Maintain vulnerability database, patch management process, dependency scanning".to_string(),
            "A.9.4.3" => "Enforce strong password policy (12+ chars), use password managers, enable MFA".to_string(),
            "A.14.1.2" => "Implement change control process, test in staging, maintain audit trail".to_string(),
            "A.13.1.3" => "Validate URLs, implement network segmentation, restrict outbound connections".to_string(),
            _ => "Review control and implement recommended mitigations".to_string(),
        };

        if control.findings.is_empty() {
            control.status = "Compliant".to_string();
        }
    }

    result
}

fn generate_recommendations(controls: &[ControlAssessment]) -> Vec<String> {
    let mut recs = Vec::new();

    let non_compliant: Vec<_> = controls
        .iter()
        .filter(|c| c.status == "Non-Compliant")
        .collect();

    if non_compliant.len() > 3 {
        recs.push(format!(
            "🔴 CRITICAL: {} ISO 27001 controls are non-compliant. Immediate remediation required.",
            non_compliant.len()
        ));
    }

    // High-priority recommendations
    if non_compliant.iter().any(|c| c.control_id.contains("A.10")) {
        recs.push("🔒 Priority 1: Implement cryptographic controls and TLS 1.2+ across all services".to_string());
    }
    if non_compliant.iter().any(|c| c.control_id.contains("A.9")) {
        recs.push("🔐 Priority 1: Strengthen authentication mechanisms (MFA, strong passwords)".to_string());
    }
    if non_compliant.iter().any(|c| c.control_id.contains("A.12")) {
        recs.push("📊 Priority 2: Enable comprehensive logging and monitoring (SIEM integration)".to_string());
    }
    if non_compliant.iter().any(|c| c.control_id.contains("A.14")) {
        recs.push("🔄 Priority 2: Implement secure SDLC and change management processes".to_string());
    }

    recs
}

pub fn render_html_report(report: &SecurityReport) -> String {
    let risk_level = if report.critical > 0 {
        "CRITICAL"
    } else if report.high > 0 {
        "HIGH"
    } else if report.medium > 0 {
        "MEDIUM"
    } else {
        "LOW"
    };

    let risk_color = match risk_level {
        "CRITICAL" => "#FF0000",
        "HIGH" => "#FF6600",
        "MEDIUM" => "#FFB800",
        _ => "#00AA00",
    };

    let controls_html = report.iso_27001_controls.iter().map(|c| {
        let status_color = if c.status == "Compliant" { "#00AA00" } else { "#FF0000" };
        let findings_html = c.findings.iter()
            .map(|f| format!("<li>{}</li>", f))
            .collect::<Vec<_>>()
            .join("");

        format!(
            r#"
            <div style="border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px;">
                <h4 style="margin: 0 0 10px 0; color: {};">{} - {}</h4>
                <p style="margin: 5px 0; color: #666;">{}</p>
                <p style="margin: 5px 0;"><strong>Status:</strong> <span style="color: {}; font-weight: bold;">{}</span></p>
                {}
                <p style="margin: 5px 0; background: #f5f5f5; padding: 10px; border-radius: 3px;"><strong>Remediation:</strong> {}</p>
            </div>
            "#,
            if c.status == "Compliant" { "#00AA00" } else { "#FF0000" },
            c.control_id,
            c.control_name,
            c.description,
            status_color,
            c.status,
            if !c.findings.is_empty() {
                format!("<p><strong>Findings:</strong><ul style=\"margin: 5px 0;\">{}</ul></p>", findings_html)
            } else {
                String::new()
            },
            c.remediation
        )
    }).collect::<Vec<_>>().join("\n");

    let recommendations_html = report.recommendations.iter()
        .map(|r| format!("<li style=\"margin: 10px 0;\">{}</li>", r))
        .collect::<Vec<_>>()
        .join("");

    format!(
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>ISO 27001 Security Report - {}</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f9f9f9; }}
                .header {{ background: {}; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
                .header h1 {{ margin: 0; font-size: 28px; }}
                .header p {{ margin: 5px 0; }}
                .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px; }}
                .stat {{ background: white; padding: 15px; border-radius: 5px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .stat .number {{ font-size: 32px; font-weight: bold; }}
                .stat .label {{ color: #666; font-size: 14px; margin-top: 5px; }}
                .section {{ background: white; padding: 20px; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .section h2 {{ margin-top: 0; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
                .recommendations {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; border-radius: 3px; margin-bottom: 20px; }}
                .recommendations h3 {{ margin-top: 0; color: #856404; }}
                .recommendations ul {{ margin: 10px 0; padding-left: 25px; }}
                .footer {{ text-align: center; color: #666; font-size: 12px; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔒 ISO 27001 Security Assessment Report</h1>
                <p><strong>Service:</strong> {}</p>
                <p><strong>Scan ID:</strong> {}</p>
                <p><strong>Generated:</strong> {}</p>
                <p style="font-size: 18px; margin-top: 10px;"><strong>Overall Risk Level:</strong> <span style="color: {}; font-weight: bold; font-size: 24px;">{}</span></p>
            </div>

            <div class="summary">
                <div class="stat">
                    <div class="number" style="color: #FF0000;">{}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="stat">
                    <div class="number" style="color: #FF6600;">{}</div>
                    <div class="label">High</div>
                </div>
                <div class="stat">
                    <div class="number" style="color: #FFB800;">{}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="stat">
                    <div class="number" style="color: #00AA00;">{}</div>
                    <div class="label">Low</div>
                </div>
            </div>

            {}

            <div class="section">
                <h2>📋 ISO 27001 Control Assessment</h2>
                <p>The following controls have been evaluated based on discovered vulnerabilities:</p>
                {}
            </div>

            <div class="footer">
                <p>This report is generated automatically by Asgard Security Platform.</p>
                <p>For questions or to request a detailed audit, contact your security team.</p>
            </div>
        </body>
        </html>
        "#,
        report.service,
        risk_color,
        report.service,
        report.scan_id,
        report.timestamp,
        risk_color,
        risk_level,
        report.critical,
        report.high,
        report.medium,
        report.low,
        if !report.recommendations.is_empty() {
            format!(
                "<div class=\"recommendations\"><h3>⚡ Recommended Actions</h3><ul>{}</ul></div>",
                recommendations_html
            )
        } else {
            String::new()
        },
        controls_html
    )
}
