use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd, CodeBlockKind};

use crate::core::types::{
    CodeBlock, Frontmatter, ParsedSkill, Region, RegionType,
};

pub fn parse(content: &str) -> Result<ParsedSkill, String> {
    let (frontmatter, body_start_line) = extract_frontmatter(content);
    let body = strip_frontmatter(content);
    let regions = parse_regions(&body, body_start_line);
    let code_blocks = extract_code_blocks(&regions);

    let mut all_regions = Vec::new();
    if frontmatter.name.is_some() || frontmatter.description.is_some() {
        let fm_end = content.lines()
            .enumerate()
            .skip(1)
            .find(|(_, l)| l.trim() == "---")
            .map(|(i, _)| i + 1)
            .unwrap_or(0);
        if fm_end > 0 {
            let fm_content = content.lines()
                .take(fm_end + 1)
                .collect::<Vec<_>>()
                .join("\n");
            all_regions.push(Region {
                region_type: RegionType::Frontmatter,
                content: fm_content,
                language: None,
                line_start: 1,
                line_end: fm_end + 1,
            });
        }
    }
    all_regions.extend(regions);

    Ok(ParsedSkill {
        raw_content: content.to_string(),
        frontmatter,
        regions: all_regions,
        code_blocks,
    })
}

fn extract_frontmatter(content: &str) -> (Frontmatter, usize) {
    let trimmed = content.trim_start();
    if !trimmed.starts_with("---") {
        return (Frontmatter::default(), 0);
    }

    let after_first = &trimmed[3..];
    let after_first = after_first.trim_start_matches(['\r', '\n']);
    if let Some(end_idx) = after_first.find("\n---") {
        let yaml_str = &after_first[..end_idx];
        let fm: Frontmatter = serde_yaml::from_str(yaml_str).unwrap_or_default();
        let consumed_lines = content[..content.len() - after_first[end_idx..].len()]
            .lines()
            .count()
            + 1; // +1 for closing ---
        (fm, consumed_lines)
    } else {
        (Frontmatter::default(), 0)
    }
}

fn strip_frontmatter(content: &str) -> String {
    let trimmed = content.trim_start();
    if !trimmed.starts_with("---") {
        return content.to_string();
    }
    let after_first = &trimmed[3..];
    let after_first = after_first.trim_start_matches(['\r', '\n']);
    if let Some(end_idx) = after_first.find("\n---") {
        let rest = &after_first[end_idx + 4..]; // skip \n---
        rest.trim_start_matches(['\r', '\n']).to_string()
    } else {
        content.to_string()
    }
}

fn parse_regions(body: &str, line_offset: usize) -> Vec<Region> {
    let mut regions: Vec<Region> = Vec::new();
    let opts = Options::all();
    let parser = Parser::new_ext(body, opts);

    let mut current_code_lang: Option<String> = None;
    let mut current_code_content = String::new();
    let mut in_code_block = false;
    let mut in_heading = false;
    let mut heading_content = String::new();

    let line_starts = build_line_offsets(body);

    let mut last_byte_offset = 0;

    for (event, range) in parser.into_offset_iter() {
        let line_num = byte_offset_to_line(&line_starts, range.start) + line_offset;

        match event {
            Event::Start(Tag::CodeBlock(kind)) => {
                in_code_block = true;
                current_code_content.clear();
                current_code_lang = match kind {
                    CodeBlockKind::Fenced(lang) => {
                        let l = lang.to_string();
                        if l.is_empty() { None } else { Some(l) }
                    }
                    CodeBlockKind::Indented => None,
                };
            }
            Event::End(TagEnd::CodeBlock) => {
                let end_line = byte_offset_to_line(&line_starts, range.end) + line_offset;
                regions.push(Region {
                    region_type: RegionType::CodeBlock,
                    content: current_code_content.clone(),
                    language: current_code_lang.take(),
                    line_start: byte_offset_to_line(&line_starts, last_byte_offset) + line_offset,
                    line_end: end_line,
                });
                in_code_block = false;
                current_code_content.clear();
            }
            Event::Text(text) if in_code_block => {
                last_byte_offset = range.start;
                current_code_content.push_str(&text);
            }
            Event::Start(Tag::Heading { .. }) => {
                in_heading = true;
                heading_content.clear();
            }
            Event::End(TagEnd::Heading(_)) => {
                let end_line = byte_offset_to_line(&line_starts, range.end) + line_offset;
                regions.push(Region {
                    region_type: RegionType::Heading,
                    content: heading_content.clone(),
                    language: None,
                    line_start: line_num,
                    line_end: end_line,
                });
                in_heading = false;
                heading_content.clear();
            }
            Event::Text(text) if in_heading => {
                heading_content.push_str(&text);
            }
            Event::Code(code) => {
                regions.push(Region {
                    region_type: RegionType::InlineCode,
                    content: code.to_string(),
                    language: None,
                    line_start: line_num,
                    line_end: line_num,
                });
            }
            Event::Html(html) => {
                let html_str = html.to_string();
                if html_str.trim_start().starts_with("<!--") {
                    let end_line = byte_offset_to_line(&line_starts, range.end) + line_offset;
                    regions.push(Region {
                        region_type: RegionType::HtmlComment,
                        content: html_str,
                        language: None,
                        line_start: line_num,
                        line_end: end_line,
                    });
                }
            }
            Event::Start(Tag::Link { dest_url, .. }) => {
                regions.push(Region {
                    region_type: RegionType::Link,
                    content: dest_url.to_string(),
                    language: None,
                    line_start: line_num,
                    line_end: line_num,
                });
            }
            Event::Text(text) if !in_code_block && !in_heading => {
                let t = text.to_string();
                if !t.trim().is_empty() {
                    let end_line = byte_offset_to_line(&line_starts, range.end) + line_offset;
                    regions.push(Region {
                        region_type: RegionType::Prose,
                        content: t,
                        language: None,
                        line_start: line_num,
                        line_end: end_line,
                    });
                }
            }
            _ => {}
        }
    }

    regions
}

fn extract_code_blocks(regions: &[Region]) -> Vec<CodeBlock> {
    regions
        .iter()
        .filter(|r| r.region_type == RegionType::CodeBlock)
        .map(|r| CodeBlock {
            content: r.content.clone(),
            language: r.language.clone(),
            line_start: r.line_start,
            line_end: r.line_end,
        })
        .collect()
}

fn build_line_offsets(text: &str) -> Vec<usize> {
    let mut offsets = vec![0];
    for (i, byte) in text.bytes().enumerate() {
        if byte == b'\n' {
            offsets.push(i + 1);
        }
    }
    offsets
}

fn byte_offset_to_line(line_starts: &[usize], offset: usize) -> usize {
    match line_starts.binary_search(&offset) {
        Ok(line) => line + 1,
        Err(line) => line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_frontmatter() {
        let content = "---\nname: test-skill\ndescription: A test skill\nversion: 1.0.0\n---\n\n# Hello\n\nSome text.";
        let result = parse(content).unwrap();
        assert_eq!(result.frontmatter.name.as_deref(), Some("test-skill"));
        assert_eq!(result.frontmatter.description.as_deref(), Some("A test skill"));
        assert_eq!(result.frontmatter.version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn parse_code_blocks() {
        let content = "# Title\n\n```bash\necho hello\n```\n\n```python\nprint('hi')\n```\n";
        let result = parse(content).unwrap();
        assert_eq!(result.code_blocks.len(), 2);
        assert_eq!(result.code_blocks[0].language.as_deref(), Some("bash"));
        assert_eq!(result.code_blocks[0].content.trim(), "echo hello");
        assert_eq!(result.code_blocks[1].language.as_deref(), Some("python"));
    }

    #[test]
    fn parse_html_comments() {
        let content = "# Title\n\n<!-- hidden secret instructions -->\n\nSome text.";
        let result = parse(content).unwrap();
        let comments: Vec<_> = result.regions.iter()
            .filter(|r| r.region_type == RegionType::HtmlComment)
            .collect();
        assert_eq!(comments.len(), 1);
        assert!(comments[0].content.contains("hidden secret"));
    }

    #[test]
    fn parse_no_frontmatter() {
        let content = "# Just a heading\n\nSome text.";
        let result = parse(content).unwrap();
        assert!(result.frontmatter.name.is_none());
    }

    #[test]
    fn regions_include_multiple_types() {
        let content = "---\nname: test\n---\n\n# Heading\n\nSome prose text.\n\n```bash\nls -la\n```\n";
        let result = parse(content).unwrap();
        let types: Vec<_> = result.regions.iter().map(|r| r.region_type).collect();
        assert!(types.contains(&RegionType::Frontmatter));
        assert!(types.contains(&RegionType::Heading));
        assert!(types.contains(&RegionType::CodeBlock));
    }
}
