use serde_json::{json, Value};

use crate::core::types::{ScanResult, Severity};

pub fn to_sarif(result: &ScanResult) -> Value {
    let mut rules: Vec<Value> = Vec::new();
    let mut rule_indices: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut results: Vec<Value> = Vec::new();

    for f in &result.risk_score.findings {
        let rule_id = format!("{}/{}", f.category, f.rule_id);

        let rule_idx = if let Some(&idx) = rule_indices.get(&rule_id) {
            idx
        } else {
            let idx = rules.len();
            rules.push(json!({
                "id": rule_id,
                "shortDescription": { "text": f.title },
                "fullDescription": { "text": f.description },
                "defaultConfiguration": {
                    "level": severity_to_sarif_level(f.severity)
                },
                "properties": {
                    "category": f.category
                }
            }));
            rule_indices.insert(rule_id.clone(), idx);
            idx
        };

        let mut sarif_result = json!({
            "ruleId": rule_id,
            "ruleIndex": rule_idx,
            "level": severity_to_sarif_level(f.severity),
            "message": { "text": f.description },
            "properties": {
                "confidence": f.confidence,
                "regionType": format!("{:?}", f.region_type),
                "analysisPass": f.analysis_pass,
            }
        });

        if let Some(line) = f.line_number {
            sarif_result["locations"] = json!([{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": result.skill_path
                    },
                    "region": {
                        "startLine": line
                    }
                }
            }]);
        }

        if let Some(fix) = &f.fix {
            sarif_result["fixes"] = json!([{
                "description": { "text": fix }
            }]);
        }

        results.push(sarif_result);
    }

    json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ClawFortify",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/clawfortify/clawfortify",
                    "rules": rules
                }
            },
            "results": results,
            "properties": {
                "riskScore": result.risk_score.score,
                "grade": format!("{}", result.risk_score.grade)
            }
        }]
    })
}

pub fn print_sarif(result: &ScanResult) {
    let sarif = to_sarif(result);
    println!("{}", serde_json::to_string_pretty(&sarif).unwrap());
}

fn severity_to_sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}
