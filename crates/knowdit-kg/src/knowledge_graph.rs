use crate::error::Result;
use knowdit_kg_model::model::{
    audit_finding, audit_finding_category, category, finding_category, finding_merge, project,
    project_category, project_platform, semantic_finding_link, semantic_function, semantic_merge,
    semantic_node,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// In-memory representation of the full knowledge graph.
/// Built via `DatabaseGraph::load_knowledge_graph()`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnowledgeGraph {
    pub projects: Vec<project::Model>,
    pub project_platforms: Vec<project_platform::Model>,
    pub categories: Vec<category::Model>,
    pub nodes: Vec<semantic_node::Model>,
    pub semantic_functions: Vec<semantic_function::Model>,
    pub project_categories: Vec<project_category::Model>,
    pub semantic_merges: Vec<semantic_merge::Model>,
    pub findings: Vec<audit_finding::Model>,
    pub finding_categories: Vec<finding_category::Model>,
    pub audit_finding_categories: Vec<audit_finding_category::Model>,
    pub semantic_finding_links: Vec<semantic_finding_link::Model>,
    pub finding_merges: Vec<finding_merge::Model>,
}

impl KnowledgeGraph {
    /// Export the knowledge graph as a GraphViz DOT string.
    pub fn export_dot(&self) -> String {
        let merged_from_semantics: HashSet<i32> = self
            .semantic_merges
            .iter()
            .map(|merge| merge.from_semantic_id)
            .collect();
        let merged_from_findings: HashSet<i32> = self
            .finding_merges
            .iter()
            .map(|merge| merge.from_finding_id)
            .collect();

        let platform_labels: HashMap<i32, String> = self
            .project_platforms
            .iter()
            .map(|pp| (pp.project_id, pp.platform_id.clone()))
            .collect();
        let finding_category_by_id: HashMap<i32, finding_category::Model> = self
            .finding_categories
            .iter()
            .cloned()
            .map(|category| (category.id, category))
            .collect();
        let finding_category_for_finding: HashMap<i32, finding_category::Model> = self
            .audit_finding_categories
            .iter()
            .filter_map(|link| {
                finding_category_by_id
                    .get(&link.finding_category_id)
                    .cloned()
                    .map(|category| (link.audit_finding_id, category))
            })
            .collect();

        let mut dot = String::new();
        dot.push_str("digraph KnowledgeGraph {\n");
        dot.push_str("  rankdir=LR;\n");
        dot.push_str("  node [shape=box, style=filled];\n\n");

        for cat in &self.categories {
            let node_ids: Vec<i32> = self
                .nodes
                .iter()
                .filter(|node| node.category == cat.name)
                .map(|node| node.id)
                .filter(|id| !merged_from_semantics.contains(id))
                .collect();

            if node_ids.is_empty() {
                continue;
            }

            dot.push_str(&format!("  subgraph cluster_cat_{} {{\n", cat.id));
            dot.push_str(&format!(
                "    label=\"{}\";\n    style=filled;\n    color=lightblue;\n",
                escape_dot(&cat.name.to_string())
            ));

            for nid in &node_ids {
                if let Some(node) = self.nodes.iter().find(|n| n.id == *nid) {
                    dot.push_str(&format!(
                        "    sem_{} [label=\"{}\", fillcolor=lightyellow];\n",
                        node.id,
                        escape_dot(&node.name)
                    ));
                }
            }
            dot.push_str("  }\n\n");
        }

        let mut finding_categories = self
            .finding_categories
            .iter()
            .map(|category| category.category)
            .collect::<Vec<_>>();
        finding_categories.sort_by_key(|category| category.as_str().to_string());
        finding_categories.dedup();

        for category_name in finding_categories {
            let finding_ids: Vec<i32> = self
                .findings
                .iter()
                .filter(|finding| !merged_from_findings.contains(&finding.id))
                .filter(|finding| {
                    finding_category_for_finding
                        .get(&finding.id)
                        .map(|category| category.category == category_name)
                        .unwrap_or(false)
                })
                .map(|finding| finding.id)
                .collect();

            if finding_ids.is_empty() {
                continue;
            }

            let cluster_id = dot_identifier(category_name.as_str());
            dot.push_str(&format!("  subgraph cluster_vuln_{} {{\n", cluster_id));
            dot.push_str(&format!(
                "    label=\"Vulnerability: {}\";\n    style=filled;\n    color=mistyrose;\n",
                escape_dot(&category_name.to_string())
            ));

            for finding_id in &finding_ids {
                if let Some(finding) = self
                    .findings
                    .iter()
                    .find(|finding| finding.id == *finding_id)
                {
                    let subcategory = finding_category_for_finding
                        .get(&finding.id)
                        .map(|category| category.name.clone())
                        .unwrap_or_else(|| "Uncategorized".to_string());
                    let label =
                        format!("[{}] {}\\n{}", finding.severity, finding.title, subcategory);
                    dot.push_str(&format!(
                        "    finding_{} [label=\"{}\", shape=note, fillcolor={}];\n",
                        finding.id,
                        escape_dot(&label),
                        finding_fill_color(finding.severity)
                    ));
                }
            }

            dot.push_str("  }\n\n");
        }

        for proj in &self.projects {
            let label = if let Some(plat_label) = platform_labels.get(&proj.id) {
                format!("{} ({})", proj.name, plat_label)
            } else {
                proj.name.clone()
            };
            dot.push_str(&format!(
                "  proj_{} [label=\"{}\", shape=ellipse, fillcolor=lightgreen];\n",
                proj.id,
                escape_dot(&label)
            ));
        }
        dot.push('\n');

        for pc in &self.project_categories {
            dot.push_str(&format!(
                "  proj_{} -> cat_{} [style=dashed, color=gray];\n",
                pc.project_id, pc.category_id
            ));
        }

        for node in &self.nodes {
            if !merged_from_semantics.contains(&node.id) {
                dot.push_str(&format!(
                    "  proj_{} -> sem_{} [color=darkgreen];\n",
                    node.project_id, node.id
                ));
            }
        }

        for finding in &self.findings {
            if !merged_from_findings.contains(&finding.id) {
                dot.push_str(&format!(
                    "  proj_{} -> finding_{} [color=firebrick];\n",
                    finding.project_id, finding.id
                ));
            }
        }
        dot.push('\n');

        for merge in &self.semantic_merges {
            dot.push_str(&format!(
                "  sem_{} -> sem_{} [label=\"merged\", style=dotted, color=red];\n",
                merge.from_semantic_id, merge.to_semantic_id
            ));
        }

        for merge in &self.finding_merges {
            dot.push_str(&format!(
                "  finding_{} -> finding_{} [label=\"merged\", style=dotted, color=orangered];\n",
                merge.from_finding_id, merge.to_finding_id
            ));
        }

        for link in &self.semantic_finding_links {
            if merged_from_semantics.contains(&link.semantic_node_id)
                || merged_from_findings.contains(&link.audit_finding_id)
            {
                continue;
            }

            dot.push_str(&format!(
                "  sem_{} -> finding_{} [color=steelblue, penwidth=1.5];\n",
                link.semantic_node_id, link.audit_finding_id
            ));
        }

        for cat in &self.categories {
            dot.push_str(&format!(
                "  cat_{} [label=\"{}\", shape=diamond, fillcolor=lightblue, style=filled];\n",
                cat.id,
                escape_dot(&cat.name.to_string())
            ));
        }

        dot.push_str("}\n");
        dot
    }

    /// Export the knowledge graph as an interactive HTML page backed by
    /// vis-network. Node labels stay concise, while all details are embedded
    /// into the page and shown in a side panel when selected.
    pub fn export_html(
        &self,
        graph_data_script_url: &str,
        details_script_url: &str,
        viewport_edge_limit: usize,
        project_rows: usize,
        semantic_rows: usize,
        finding_rows: usize,
    ) -> Result<HtmlExportAssets> {
        let project_rows = project_rows.max(1);
        let semantic_rows = semantic_rows.max(1);
        let finding_rows = finding_rows.max(1);
        let merged_from_semantics: HashSet<i32> = self
            .semantic_merges
            .iter()
            .map(|merge| merge.from_semantic_id)
            .collect();
        let merged_from_findings: HashSet<i32> = self
            .finding_merges
            .iter()
            .map(|merge| merge.from_finding_id)
            .collect();
        let semantic_merge_targets: HashMap<i32, i32> = self
            .semantic_merges
            .iter()
            .map(|merge| (merge.from_semantic_id, merge.to_semantic_id))
            .collect();
        let finding_merge_targets: HashMap<i32, i32> = self
            .finding_merges
            .iter()
            .map(|merge| (merge.from_finding_id, merge.to_finding_id))
            .collect();

        let projects_by_id: HashMap<i32, &project::Model> = self
            .projects
            .iter()
            .map(|project| (project.id, project))
            .collect();
        let categories_by_id: HashMap<i32, &category::Model> = self
            .categories
            .iter()
            .map(|category| (category.id, category))
            .collect();
        let nodes_by_id: HashMap<i32, &semantic_node::Model> =
            self.nodes.iter().map(|node| (node.id, node)).collect();
        let findings_by_id: HashMap<i32, &audit_finding::Model> = self
            .findings
            .iter()
            .map(|finding| (finding.id, finding))
            .collect();

        let platform_labels: HashMap<i32, String> = self
            .project_platforms
            .iter()
            .map(|pp| (pp.project_id, pp.platform_id.clone()))
            .collect();
        let mut project_category_names: HashMap<i32, Vec<String>> = HashMap::new();
        for link in &self.project_categories {
            if let Some(category) = categories_by_id.get(&link.category_id) {
                project_category_names
                    .entry(link.project_id)
                    .or_default()
                    .push(category.name.to_string());
            }
        }
        for categories in project_category_names.values_mut() {
            categories.sort();
            categories.dedup();
        }

        let finding_category_by_id: HashMap<i32, &finding_category::Model> = self
            .finding_categories
            .iter()
            .map(|category| (category.id, category))
            .collect();
        let mut finding_category_for_finding: HashMap<i32, &finding_category::Model> =
            HashMap::new();
        for link in &self.audit_finding_categories {
            if let Some(category) = finding_category_by_id.get(&link.finding_category_id) {
                finding_category_for_finding.insert(link.audit_finding_id, *category);
            }
        }

        let mut semantic_functions_by_node: HashMap<i32, Vec<String>> = HashMap::new();
        for func in &self.semantic_functions {
            semantic_functions_by_node
                .entry(func.semantic_node_id)
                .or_default()
                .push(format!("{} — {}", func.contract_path, func.function_name));
        }
        for functions in semantic_functions_by_node.values_mut() {
            functions.sort();
            functions.dedup();
        }

        let project_ids = self
            .projects
            .iter()
            .map(|project| project.id)
            .collect::<Vec<_>>();
        let category_ids = self
            .categories
            .iter()
            .map(|category| category.id)
            .collect::<Vec<_>>();
        let semantic_ids = self.nodes.iter().map(|node| node.id).collect::<Vec<_>>();
        let finding_ids = self
            .findings
            .iter()
            .map(|finding| finding.id)
            .collect::<Vec<_>>();
        let project_positions = right_aligned_grid_node_positions(
            &project_ids,
            PROJECT_COLUMN_X,
            project_rows,
            PROJECT_ROW_SPACING,
            PROJECT_COLUMN_SPACING,
            0.0,
        );
        let category_positions =
            vertical_node_positions(&category_ids, CATEGORY_COLUMN_X, CATEGORY_ROW_SPACING);
        let semantic_positions = grid_node_positions(
            &semantic_ids,
            SEMANTIC_COLUMN_X,
            semantic_rows,
            SEMANTIC_ROW_SPACING,
            SEMANTIC_COLUMN_SPACING,
            0.0,
        );
        let finding_vertical_offset =
            grid_band_half_height(semantic_ids.len(), semantic_rows, SEMANTIC_ROW_SPACING)
                + grid_band_half_height(finding_ids.len(), finding_rows, FINDING_ROW_SPACING)
                + FINDING_VERTICAL_GAP;
        let finding_positions = grid_node_positions(
            &finding_ids,
            FINDING_COLUMN_X,
            finding_rows,
            FINDING_ROW_SPACING,
            FINDING_COLUMN_SPACING,
            finding_vertical_offset,
        );

        let mut nodes = Vec::new();
        let mut node_details = HashMap::new();
        let mut edge_details = HashMap::new();
        let mut node_type_counts: HashMap<&'static str, usize> = HashMap::new();
        let mut edge_type_counts: HashMap<&'static str, usize> = HashMap::new();

        for project in &self.projects {
            let mut fields = Vec::new();
            push_detail(&mut fields, "Project Name", Some(project.name.clone()));
            push_detail(
                &mut fields,
                "Platform ID",
                platform_labels.get(&project.id).cloned(),
            );
            push_detail(&mut fields, "Status", Some(project.status.clone()));
            push_detail(
                &mut fields,
                "Categories",
                project_category_names
                    .get(&project.id)
                    .map(|categories| categories.join(", ")),
            );

            let raw_semantic_count = self
                .nodes
                .iter()
                .filter(|node| node.project_id == project.id)
                .count();
            let raw_finding_count = self
                .findings
                .iter()
                .filter(|finding| finding.project_id == project.id)
                .count();
            push_detail(
                &mut fields,
                "Semantic Nodes",
                Some(raw_semantic_count.to_string()),
            );
            push_detail(
                &mut fields,
                "Audit Findings",
                Some(raw_finding_count.to_string()),
            );

            let node_id = format!("proj_{}", project.id);
            node_details.insert(
                node_id.clone(),
                HtmlSelectionDetails {
                    title: project.name.clone(),
                    subtitle: platform_labels.get(&project.id).cloned(),
                    fields,
                },
            );
            bump_node_type_count(&mut node_type_counts, NODE_TYPE_PROJECT);
            let position =
                project_positions
                    .get(&project.id)
                    .copied()
                    .unwrap_or(HtmlNodePosition {
                        x: PROJECT_COLUMN_X,
                        y: 0.0,
                    });
            nodes.push(HtmlGraphNode {
                id: node_id,
                label: wrap_label(&project.name, 22),
                node_type: NODE_TYPE_PROJECT.to_string(),
                is_merged: false,
                level: 0,
                shape: "ellipse".to_string(),
                color: HtmlNodeColor {
                    background: "#dcfce7".to_string(),
                    border: "#16a34a".to_string(),
                },
                border_width: 2,
                x: position.x,
                y: position.y,
                fixed: HtmlNodeFixed::locked(),
            });
        }

        for category in &self.categories {
            let project_count = self
                .project_categories
                .iter()
                .filter(|link| link.category_id == category.id)
                .count();
            let active_semantic_count = self
                .nodes
                .iter()
                .filter(|node| node.category == category.name)
                .filter(|node| !merged_from_semantics.contains(&node.id))
                .count();

            let node_id = format!("cat_{}", category.id);
            node_details.insert(
                node_id.clone(),
                HtmlSelectionDetails {
                    title: category.name.to_string(),
                    subtitle: Some("DeFi Category".to_string()),
                    fields: vec![
                        HtmlDetailField {
                            label: "Category".to_string(),
                            value: category.name.to_string(),
                        },
                        HtmlDetailField {
                            label: "Projects".to_string(),
                            value: project_count.to_string(),
                        },
                        HtmlDetailField {
                            label: "Active Semantic Nodes".to_string(),
                            value: active_semantic_count.to_string(),
                        },
                    ],
                },
            );
            bump_node_type_count(&mut node_type_counts, NODE_TYPE_CATEGORY);
            let position =
                category_positions
                    .get(&category.id)
                    .copied()
                    .unwrap_or(HtmlNodePosition {
                        x: CATEGORY_COLUMN_X,
                        y: 0.0,
                    });
            nodes.push(HtmlGraphNode {
                id: node_id,
                label: wrap_label(category.name.as_str(), 18),
                node_type: NODE_TYPE_CATEGORY.to_string(),
                is_merged: false,
                level: 1,
                shape: "diamond".to_string(),
                color: HtmlNodeColor {
                    background: "#dbeafe".to_string(),
                    border: "#2563eb".to_string(),
                },
                border_width: 2,
                x: position.x,
                y: position.y,
                fixed: HtmlNodeFixed::locked(),
            });
        }

        for node in &self.nodes {
            let is_merged = merged_from_semantics.contains(&node.id);
            let project_name = projects_by_id
                .get(&node.project_id)
                .map(|project| project.name.clone());
            let mut fields = Vec::new();
            push_detail(&mut fields, "Name", Some(node.name.clone()));
            push_detail(&mut fields, "Definition", Some(node.definition.clone()));
            push_detail(&mut fields, "Description", Some(node.description.clone()));
            push_detail(&mut fields, "Category", Some(node.category.to_string()));
            push_detail(&mut fields, "Project", project_name.clone());
            push_detail(
                &mut fields,
                "Functions",
                semantic_functions_by_node
                    .get(&node.id)
                    .map(|functions| functions.join("\n")),
            );
            if let Some(target_id) = semantic_merge_targets.get(&node.id) {
                let merged_into = nodes_by_id
                    .get(target_id)
                    .map(|target| format!("sem_{} — {}", target.id, target.name))
                    .unwrap_or_else(|| format!("sem_{}", target_id));
                push_detail(&mut fields, "Merged Into", Some(merged_into));
            }
            push_detail(
                &mut fields,
                "Status",
                Some(if is_merged {
                    "Merged".to_string()
                } else {
                    "Active".to_string()
                }),
            );

            let label_source = if node.definition.trim().is_empty() {
                node.name.as_str()
            } else {
                node.definition.as_str()
            };
            let node_id = format!("sem_{}", node.id);
            node_details.insert(
                node_id.clone(),
                HtmlSelectionDetails {
                    title: node.name.clone(),
                    subtitle: Some(format!(
                        "{} semantic{}",
                        node.category,
                        if is_merged { " (merged)" } else { "" }
                    )),
                    fields,
                },
            );
            bump_node_type_count(&mut node_type_counts, NODE_TYPE_SEMANTIC);
            let position = semantic_positions
                .get(&node.id)
                .copied()
                .unwrap_or(HtmlNodePosition {
                    x: SEMANTIC_COLUMN_X,
                    y: 0.0,
                });
            nodes.push(HtmlGraphNode {
                id: node_id,
                label: wrap_label(&truncate_text(label_source, 84), 24),
                node_type: NODE_TYPE_SEMANTIC.to_string(),
                is_merged: is_merged,
                level: 2,
                shape: "box".to_string(),
                color: semantic_node_color(is_merged),
                border_width: if is_merged { 1 } else { 2 },
                x: position.x,
                y: position.y,
                fixed: HtmlNodeFixed::locked(),
            });
        }

        for finding in &self.findings {
            let is_merged = merged_from_findings.contains(&finding.id);
            let project_name = projects_by_id
                .get(&finding.project_id)
                .map(|project| project.name.clone());
            let category = finding_category_for_finding.get(&finding.id).copied();
            let mut fields = Vec::new();
            push_detail(&mut fields, "Title", Some(finding.title.clone()));
            push_detail(&mut fields, "Severity", Some(finding.severity.to_string()));
            push_detail(
                &mut fields,
                "Category",
                category.map(|category| category.category.to_string()),
            );
            push_detail(
                &mut fields,
                "Subcategory",
                category.map(|category| category.name.clone()),
            );
            push_detail(&mut fields, "Root Cause", Some(finding.root_cause.clone()));
            push_detail(
                &mut fields,
                "Description",
                Some(finding.description.clone()),
            );
            push_detail(&mut fields, "Patterns", Some(finding.patterns.clone()));
            push_detail(&mut fields, "Exploits", Some(finding.exploits.clone()));
            push_detail(&mut fields, "Project", project_name.clone());
            if let Some(target_id) = finding_merge_targets.get(&finding.id) {
                let merged_into = findings_by_id
                    .get(target_id)
                    .map(|target| format!("finding_{} — {}", target.id, target.title))
                    .unwrap_or_else(|| format!("finding_{}", target_id));
                push_detail(&mut fields, "Merged Into", Some(merged_into));
            }
            push_detail(
                &mut fields,
                "Status",
                Some(if is_merged {
                    "Merged".to_string()
                } else {
                    "Active".to_string()
                }),
            );

            let node_id = format!("finding_{}", finding.id);
            node_details.insert(
                node_id.clone(),
                HtmlSelectionDetails {
                    title: finding.title.clone(),
                    subtitle: Some(format!(
                        "{} severity{}",
                        finding.severity,
                        if is_merged { " (merged)" } else { "" }
                    )),
                    fields,
                },
            );
            bump_node_type_count(&mut node_type_counts, NODE_TYPE_FINDING);
            let position =
                finding_positions
                    .get(&finding.id)
                    .copied()
                    .unwrap_or(HtmlNodePosition {
                        x: FINDING_COLUMN_X,
                        y: 0.0,
                    });
            nodes.push(HtmlGraphNode {
                id: node_id,
                label: wrap_label(&truncate_text(&finding.title, 84), 24),
                node_type: NODE_TYPE_FINDING.to_string(),
                is_merged: is_merged,
                level: 3,
                shape: "box".to_string(),
                color: finding_node_color(finding.severity, is_merged),
                border_width: if is_merged { 1 } else { 2 },
                x: position.x,
                y: position.y,
                fixed: HtmlNodeFixed::locked(),
            });
        }

        let mut edges = Vec::new();

        for link in &self.project_categories {
            if let (Some(project), Some(category)) = (
                projects_by_id.get(&link.project_id),
                categories_by_id.get(&link.category_id),
            ) {
                let edge_id = format!("proj-cat-{}-{}", link.project_id, link.category_id);
                edge_details.insert(
                    edge_id.clone(),
                    HtmlSelectionDetails {
                        title: "Project -> Category".to_string(),
                        subtitle: Some("Membership".to_string()),
                        fields: vec![
                            HtmlDetailField {
                                label: "Project".to_string(),
                                value: project.name.clone(),
                            },
                            HtmlDetailField {
                                label: "Category".to_string(),
                                value: category.name.to_string(),
                            },
                            HtmlDetailField {
                                label: "Relation".to_string(),
                                value: "Project belongs to DeFi category".to_string(),
                            },
                        ],
                    },
                );
                bump_edge_type_count(&mut edge_type_counts, EDGE_TYPE_PROJECT_CATEGORY);
                edges.push(HtmlGraphEdge {
                    id: edge_id,
                    from: format!("proj_{}", link.project_id),
                    to: format!("cat_{}", link.category_id),
                    edge_type: EDGE_TYPE_PROJECT_CATEGORY.to_string(),
                    arrows: "to".to_string(),
                    color: HtmlEdgeColor {
                        color: "#6b7280".to_string(),
                    },
                    dashes: true,
                    width: 1.2,
                });
            }
        }

        for node in &self.nodes {
            let is_merged = merged_from_semantics.contains(&node.id);
            if let Some(project) = projects_by_id.get(&node.project_id) {
                let edge_id = format!("proj-sem-{}-{}", node.project_id, node.id);
                let mut fields = vec![
                    HtmlDetailField {
                        label: "Project".to_string(),
                        value: project.name.clone(),
                    },
                    HtmlDetailField {
                        label: "Semantic".to_string(),
                        value: node.name.clone(),
                    },
                    HtmlDetailField {
                        label: "Definition".to_string(),
                        value: node.definition.clone(),
                    },
                    HtmlDetailField {
                        label: "Status".to_string(),
                        value: if is_merged {
                            "Merged".to_string()
                        } else {
                            "Active".to_string()
                        },
                    },
                ];
                if let Some(target_id) = semantic_merge_targets.get(&node.id) {
                    let merged_into = nodes_by_id
                        .get(target_id)
                        .map(|target| format!("sem_{} — {}", target.id, target.name))
                        .unwrap_or_else(|| format!("sem_{}", target_id));
                    fields.push(HtmlDetailField {
                        label: "Merged Into".to_string(),
                        value: merged_into,
                    });
                }
                edge_details.insert(
                    edge_id.clone(),
                    HtmlSelectionDetails {
                        title: "Project -> Semantic".to_string(),
                        subtitle: Some(if is_merged {
                            "Merged semantic still originates from this project".to_string()
                        } else {
                            "Contains active semantic node".to_string()
                        }),
                        fields,
                    },
                );
                bump_edge_type_count(&mut edge_type_counts, EDGE_TYPE_PROJECT_SEMANTIC);
                edges.push(HtmlGraphEdge {
                    id: edge_id,
                    from: format!("proj_{}", node.project_id),
                    to: format!("sem_{}", node.id),
                    edge_type: EDGE_TYPE_PROJECT_SEMANTIC.to_string(),
                    arrows: "to".to_string(),
                    color: HtmlEdgeColor {
                        color: if is_merged {
                            "#65a30d".to_string()
                        } else {
                            "#166534".to_string()
                        },
                    },
                    dashes: is_merged,
                    width: if is_merged { 1.5 } else { 1.8 },
                });
            }
        }

        for finding in &self.findings {
            let is_merged = merged_from_findings.contains(&finding.id);
            if let Some(project) = projects_by_id.get(&finding.project_id) {
                let edge_id = format!("proj-finding-{}-{}", finding.project_id, finding.id);
                let mut fields = vec![
                    HtmlDetailField {
                        label: "Project".to_string(),
                        value: project.name.clone(),
                    },
                    HtmlDetailField {
                        label: "Finding".to_string(),
                        value: finding.title.clone(),
                    },
                    HtmlDetailField {
                        label: "Severity".to_string(),
                        value: finding.severity.to_string(),
                    },
                    HtmlDetailField {
                        label: "Status".to_string(),
                        value: if is_merged {
                            "Merged".to_string()
                        } else {
                            "Active".to_string()
                        },
                    },
                ];
                if let Some(target_id) = finding_merge_targets.get(&finding.id) {
                    let merged_into = findings_by_id
                        .get(target_id)
                        .map(|target| format!("finding_{} — {}", target.id, target.title))
                        .unwrap_or_else(|| format!("finding_{}", target_id));
                    fields.push(HtmlDetailField {
                        label: "Merged Into".to_string(),
                        value: merged_into,
                    });
                }
                edge_details.insert(
                    edge_id.clone(),
                    HtmlSelectionDetails {
                        title: "Project -> Audit Finding".to_string(),
                        subtitle: Some(if is_merged {
                            "Merged finding still originates from this project".to_string()
                        } else {
                            "Active finding originates from project".to_string()
                        }),
                        fields,
                    },
                );
                bump_edge_type_count(&mut edge_type_counts, EDGE_TYPE_PROJECT_FINDING);
                edges.push(HtmlGraphEdge {
                    id: edge_id,
                    from: format!("proj_{}", finding.project_id),
                    to: format!("finding_{}", finding.id),
                    edge_type: EDGE_TYPE_PROJECT_FINDING.to_string(),
                    arrows: "to".to_string(),
                    color: HtmlEdgeColor {
                        color: if is_merged {
                            "#c2410c".to_string()
                        } else {
                            "#b91c1c".to_string()
                        },
                    },
                    dashes: is_merged,
                    width: if is_merged { 1.5 } else { 1.8 },
                });
            }
        }

        for merge in &self.semantic_merges {
            let from_label = nodes_by_id
                .get(&merge.from_semantic_id)
                .map(|node| node.name.clone())
                .unwrap_or_else(|| format!("sem_{}", merge.from_semantic_id));
            let to_label = nodes_by_id
                .get(&merge.to_semantic_id)
                .map(|node| node.name.clone())
                .unwrap_or_else(|| format!("sem_{}", merge.to_semantic_id));
            let edge_id = format!(
                "sem-merge-{}-{}",
                merge.from_semantic_id, merge.to_semantic_id
            );
            edge_details.insert(
                edge_id.clone(),
                HtmlSelectionDetails {
                    title: "Semantic Merge".to_string(),
                    subtitle: Some("Source semantic points to canonical semantic".to_string()),
                    fields: vec![
                        HtmlDetailField {
                            label: "Merged Node".to_string(),
                            value: from_label,
                        },
                        HtmlDetailField {
                            label: "Canonical Node".to_string(),
                            value: to_label,
                        },
                        HtmlDetailField {
                            label: "Relation".to_string(),
                            value: "Merged semantic redirects into the canonical semantic node"
                                .to_string(),
                        },
                    ],
                },
            );
            bump_edge_type_count(&mut edge_type_counts, EDGE_TYPE_SEMANTIC_MERGE);
            edges.push(HtmlGraphEdge {
                id: edge_id,
                from: format!("sem_{}", merge.from_semantic_id),
                to: format!("sem_{}", merge.to_semantic_id),
                edge_type: EDGE_TYPE_SEMANTIC_MERGE.to_string(),
                arrows: "to".to_string(),
                color: HtmlEdgeColor {
                    color: "#7c3aed".to_string(),
                },
                dashes: true,
                width: 2.8,
            });
        }

        for merge in &self.finding_merges {
            let from_label = findings_by_id
                .get(&merge.from_finding_id)
                .map(|finding| finding.title.clone())
                .unwrap_or_else(|| format!("finding_{}", merge.from_finding_id));
            let to_label = findings_by_id
                .get(&merge.to_finding_id)
                .map(|finding| finding.title.clone())
                .unwrap_or_else(|| format!("finding_{}", merge.to_finding_id));
            let edge_id = format!(
                "finding-merge-{}-{}",
                merge.from_finding_id, merge.to_finding_id
            );
            edge_details.insert(
                edge_id.clone(),
                HtmlSelectionDetails {
                    title: "Finding Merge".to_string(),
                    subtitle: Some("Source finding points to canonical finding".to_string()),
                    fields: vec![
                        HtmlDetailField {
                            label: "Merged Node".to_string(),
                            value: from_label,
                        },
                        HtmlDetailField {
                            label: "Canonical Node".to_string(),
                            value: to_label,
                        },
                        HtmlDetailField {
                            label: "Relation".to_string(),
                            value: "Merged finding redirects into the canonical finding node"
                                .to_string(),
                        },
                    ],
                },
            );
            bump_edge_type_count(&mut edge_type_counts, EDGE_TYPE_FINDING_MERGE);
            edges.push(HtmlGraphEdge {
                id: edge_id,
                from: format!("finding_{}", merge.from_finding_id),
                to: format!("finding_{}", merge.to_finding_id),
                edge_type: EDGE_TYPE_FINDING_MERGE.to_string(),
                arrows: "to".to_string(),
                color: HtmlEdgeColor {
                    color: "#ea580c".to_string(),
                },
                dashes: true,
                width: 2.8,
            });
        }

        for link in &self.semantic_finding_links {
            let semantic_label = nodes_by_id
                .get(&link.semantic_node_id)
                .map(|node| node.name.clone())
                .unwrap_or_else(|| format!("sem_{}", link.semantic_node_id));
            let finding_label = findings_by_id
                .get(&link.audit_finding_id)
                .map(|finding| finding.title.clone())
                .unwrap_or_else(|| format!("finding_{}", link.audit_finding_id));
            let edge_id = format!(
                "semantic-finding-{}-{}",
                link.semantic_node_id, link.audit_finding_id
            );
            edge_details.insert(
                edge_id.clone(),
                HtmlSelectionDetails {
                    title: "Semantic -> Finding".to_string(),
                    subtitle: Some("Linked concept".to_string()),
                    fields: vec![
                        HtmlDetailField {
                            label: "Semantic".to_string(),
                            value: semantic_label,
                        },
                        HtmlDetailField {
                            label: "Finding".to_string(),
                            value: finding_label,
                        },
                    ],
                },
            );
            bump_edge_type_count(&mut edge_type_counts, EDGE_TYPE_SEMANTIC_FINDING);
            edges.push(HtmlGraphEdge {
                id: edge_id,
                from: format!("sem_{}", link.semantic_node_id),
                to: format!("finding_{}", link.audit_finding_id),
                edge_type: EDGE_TYPE_SEMANTIC_FINDING.to_string(),
                arrows: "to".to_string(),
                color: HtmlEdgeColor {
                    color: "#2563eb".to_string(),
                },
                dashes: false,
                width: 2.2,
            });
        }

        let edge_count = edges.len();
        let large_graph_mode =
            nodes.len() > LARGE_GRAPH_NODE_THRESHOLD || edge_count > LARGE_GRAPH_EDGE_THRESHOLD;
        let node_filters = html_node_filters(&node_type_counts);
        let edge_filters = html_edge_filters(&edge_type_counts, large_graph_mode);
        let graph_payload = HtmlGraphPayload {
            nodes,
            edges,
            node_filters,
            edge_filters,
            viewport_edge_limit,
            stats: HtmlGraphStats {
                project_count: self.projects.len(),
                category_count: self.categories.len(),
                semantic_count: self.nodes.len(),
                active_semantic_count: self.nodes.len().saturating_sub(merged_from_semantics.len()),
                finding_count: self.findings.len(),
                active_finding_count: self
                    .findings
                    .len()
                    .saturating_sub(merged_from_findings.len()),
                edge_count,
                large_graph_mode,
            },
        };
        let details_payload = HtmlGraphDetailsPayload {
            node_details,
            edge_details,
        };
        let graph_payload_js = json_for_js(&graph_payload)?;
        let details_payload_js = json_for_js(&details_payload)?;
        let graph_data_script_url_json = json_for_js(&graph_data_script_url)?;
        let details_script_url_json = json_for_js(&details_script_url)?;

        let mut html = String::new();
        html.push_str(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Knowdit Knowledge Graph</title>
  <link rel="preconnect" href="https://unpkg.com">
  <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <style>
    :root {
      color-scheme: light;
      --bg: #f8fafc;
      --panel: #ffffff;
      --border: #cbd5e1;
      --text: #0f172a;
      --muted: #475569;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--text);
      background: var(--bg);
    }
    header {
      padding: 16px 20px;
      border-bottom: 1px solid var(--border);
      background: var(--panel);
      position: sticky;
      top: 0;
      z-index: 10;
    }
    .header-top {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 16px;
      flex-wrap: wrap;
    }
    .title-block {
      min-width: 0;
      flex: 1 1 320px;
    }
    h1 {
      margin: 0;
      font-size: 22px;
    }
    .subtitle {
      margin-top: 6px;
      color: var(--muted);
      font-size: 14px;
    }
    .toolbar {
      display: flex;
      gap: 12px;
      align-items: center;
      flex-wrap: wrap;
      margin-top: 14px;
    }
    button {
      border: 1px solid var(--border);
      background: #eff6ff;
      color: #1d4ed8;
      border-radius: 8px;
      padding: 8px 12px;
      font-weight: 600;
      cursor: pointer;
    }
    button:hover {
      background: #dbeafe;
    }
    .stats {
      color: var(--muted);
      font-size: 14px;
    }
    .layout {
      display: grid;
      grid-template-columns: minmax(0, 1fr) 380px;
      min-height: calc(100vh - 126px);
      align-items: stretch;
    }
    #graph {
      height: auto;
      min-height: 720px;
      border-right: 1px solid var(--border);
      background: linear-gradient(180deg, #f8fafc 0%, #eef2ff 100%);
      position: relative;
    }
    aside {
      background: var(--panel);
      padding: 18px;
      overflow: auto;
    }
    .panel-block + .panel-block {
      margin-top: 18px;
    }
    .legend {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 8px 12px;
    }
    .legend-item {
      display: flex;
      align-items: center;
      gap: 8px;
      color: var(--muted);
      font-size: 13px;
    }
    .legend-note {
      margin: 10px 0 0 0;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.5;
    }
    .panel-title {
      margin: 0;
      font-size: 16px;
    }
    .legend-swatch {
      width: 14px;
      height: 14px;
      border-radius: 4px;
      border: 1px solid rgba(15, 23, 42, 0.2);
      flex: 0 0 14px;
    }
    .graph-status {
      position: absolute;
      inset: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
      text-align: center;
      color: var(--muted);
      font-size: 15px;
      line-height: 1.6;
      background: rgba(248, 250, 252, 0.92);
      z-index: 2;
    }
    .graph-status.is-error {
      color: #b91c1c;
      background: rgba(254, 242, 242, 0.96);
    }
    .graph-warning {
      flex: 0 1 560px;
      max-width: min(560px, 100%);
      padding: 12px 14px;
      border: 1px solid #f59e0b;
      border-radius: 12px;
      background: rgba(255, 251, 235, 0.96);
      color: #92400e;
      font-size: 13px;
      line-height: 1.5;
      box-shadow: 0 12px 24px rgba(15, 23, 42, 0.12);
    }
    .graph-warning[hidden] {
      display: none;
    }
    .edge-limit-control {
      margin-top: 12px;
      padding: 12px;
      border: 1px solid var(--border);
      border-radius: 10px;
      background: #f8fafc;
    }
    .edge-limit-header {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 8px;
    }
    .edge-limit-label {
      font-size: 14px;
      font-weight: 600;
      color: var(--text);
    }
    .edge-limit-value {
      font-size: 12px;
      color: var(--muted);
      white-space: nowrap;
    }
    .edge-limit-slider {
      width: 100%;
      margin-top: 10px;
      accent-color: #2563eb;
    }
    .edge-limit-note {
      margin: 10px 0 0 0;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.5;
    }
    .edge-filter-list {
      margin-top: 12px;
      display: grid;
      gap: 10px;
    }
    .node-filter-list {
      margin-top: 12px;
      display: grid;
      gap: 10px;
    }
    .node-filter-option {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 10px 12px;
      border: 1px solid var(--border);
      border-radius: 10px;
      background: #f8fafc;
      cursor: pointer;
    }
    .node-filter-option.is-disabled {
      opacity: 0.55;
      cursor: not-allowed;
    }
    .node-filter-option input {
      margin: 0;
      cursor: pointer;
    }
    .node-filter-option.is-disabled input {
      cursor: not-allowed;
    }
    .node-filter-swatch {
      width: 14px;
      height: 14px;
      border-radius: 4px;
      border: 2px solid var(--node-border);
      background: var(--node-background);
      flex: 0 0 14px;
    }
    .edge-filter-option {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 10px 12px;
      border: 1px solid var(--border);
      border-radius: 10px;
      background: #f8fafc;
      cursor: pointer;
    }
    .edge-filter-option.is-disabled {
      opacity: 0.55;
      cursor: not-allowed;
    }
    .edge-filter-option input {
      margin: 0;
      cursor: pointer;
    }
    .edge-filter-option.is-disabled input {
      cursor: not-allowed;
    }
    .edge-filter-swatch {
      width: 28px;
      flex: 0 0 28px;
      border-top-width: 3px;
      border-top-style: solid;
      border-top-color: var(--edge-color);
    }
    .edge-filter-text {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 8px;
      width: 100%;
    }
    .edge-filter-name {
      font-size: 14px;
      color: var(--text);
    }
    .edge-filter-meta {
      font-size: 12px;
      color: var(--muted);
      white-space: nowrap;
    }
    .detail-title {
      margin: 0;
      font-size: 18px;
    }
    .detail-subtitle {
      margin-top: 4px;
      color: var(--muted);
      font-size: 14px;
    }
    .hint {
      margin: 0;
      color: var(--muted);
      font-size: 14px;
      line-height: 1.5;
    }
    dl {
      margin: 16px 0 0 0;
      display: grid;
      gap: 10px;
    }
    dt {
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.03em;
      color: var(--muted);
      margin: 0;
    }
    dd {
      margin: 2px 0 0 0;
      white-space: pre-wrap;
      line-height: 1.45;
      font-size: 14px;
    }
    @media (max-width: 1100px) {
      .header-top {
        align-items: stretch;
      }
      .graph-warning {
        max-width: 100%;
      }
      .layout {
        grid-template-columns: 1fr;
      }
      #graph {
        height: 60vh;
        min-height: 480px;
        border-right: none;
        border-bottom: 1px solid var(--border);
      }
    }
  </style>
</head>
<body>
  <header>
    <div class="header-top">
      <div class="title-block">
        <h1>Knowdit Knowledge Graph</h1>
        <div class="subtitle">
          Interactive HTML export. Node labels stay concise; click any node or edge to inspect the full details.
        </div>
      </div>
      <div id="graph-warning" class="graph-warning" hidden></div>
    </div>
    <div class="toolbar">
      <button id="fit-button" type="button">Fit graph</button>
      <button id="stabilize-button" type="button">Stabilize layout</button>
      <div id="summary-stats" class="stats"></div>
    </div>
  </header>
  <div class="layout">
    <div id="graph"></div>
    <aside>
      <section class="panel-block">
        <div class="legend">
          <div class="legend-item"><span class="legend-swatch" style="background:#dcfce7;border-color:#16a34a;"></span>Project</div>
          <div class="legend-item"><span class="legend-swatch" style="background:#dbeafe;border-color:#2563eb;"></span>DeFi Category</div>
          <div class="legend-item"><span class="legend-swatch" style="background:#fff4cc;border-color:#a67c00;"></span>Semantic</div>
          <div class="legend-item"><span class="legend-swatch" style="background:#fee2e2;border-color:#dc2626;"></span>High Finding</div>
          <div class="legend-item"><span class="legend-swatch" style="background:#fef3c7;border-color:#d97706;"></span>Medium Finding</div>
          <div class="legend-item"><span class="legend-swatch" style="background:#f5f5f4;border-color:#57534e;"></span>Low Finding</div>
        </div>
        <p class="legend-note">Dashed project edges mark merged source nodes. Thick dashed purple/orange edges show merged-to-canonical relationships.</p>
        <p id="performance-note" class="legend-note"></p>
      </section>
      <section class="panel-block">
        <h2 class="panel-title">Node filters</h2>
        <p class="hint">Hide or show whole node classes while keeping the remaining layout stable.</p>
        <div id="node-filters" class="node-filter-list"></div>
        <div id="merged-node-filters" class="node-filter-list"></div>
        <p id="node-filter-summary" class="legend-note"></p>
        <p id="merged-node-filter-summary" class="legend-note"></p>
      </section>
      <section class="panel-block">
        <h2 class="panel-title">Edge filters</h2>
        <p class="hint">Toggle relationship types on and off to reduce edge density without changing the node set.</p>
        <div class="edge-limit-control">
          <div class="edge-limit-header">
            <span class="edge-limit-label">Viewport edge limit</span>
            <span id="edge-limit-value" class="edge-limit-value"></span>
          </div>
          <input id="edge-limit-slider" class="edge-limit-slider" type="range" min="1" max="1" step="1">
          <p id="edge-limit-note" class="edge-limit-note"></p>
        </div>
        <div id="edge-filters" class="edge-filter-list"></div>
        <p id="edge-filter-summary" class="legend-note"></p>
      </section>
      <section id="details-panel" class="panel-block">
        <h2 class="detail-title">Selection details</h2>
        <p class="hint">Click a node or edge in the graph to inspect its full metadata. Large detail payloads load on demand.</p>
      </section>
    </aside>
  </div>
  <script>
    const graphDataScriptUrl = "#,
        );
        html.push_str(&graph_data_script_url_json);
        html.push_str(
            r#";
    const detailsScriptUrl = "#,
        );
        html.push_str(&details_script_url_json);
        html.push_str(
            r#";
    let detailsPayload = window.__KNOWDIT_GRAPH_DETAILS__ || null;
    let detailsLoadPromise = null;
    const container = document.getElementById('graph');
    const performanceNote = document.getElementById('performance-note');

    function renderGraphStatus(message, isError = false) {
      container.innerHTML = '';
      const status = document.createElement('div');
      status.className = isError ? 'graph-status is-error' : 'graph-status';
      status.textContent = message;
      container.appendChild(status);
    }

    function clearGraphStatus() {
      const status = container.querySelector('.graph-status');
      if (status) {
        status.remove();
      }
    }

    function loadScript(url) {
      return new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = url;
        script.async = true;
        script.onload = resolve;
        script.onerror = () => reject(new Error(`Failed to load ${url}. Keep the exported asset files together.`));
        document.head.appendChild(script);
      });
    }

    async function ensureGraphDataLoaded() {
      if (window.__KNOWDIT_GRAPH_DATA__) {
        return window.__KNOWDIT_GRAPH_DATA__;
      }
      await loadScript(graphDataScriptUrl);
      if (!window.__KNOWDIT_GRAPH_DATA__) {
        throw new Error('Graph data payload did not initialize correctly.');
      }
      return window.__KNOWDIT_GRAPH_DATA__;
    }

    async function ensureDetailsLoaded() {
      if (detailsPayload) {
        return detailsPayload;
      }
      if (!detailsLoadPromise) {
        detailsLoadPromise = loadScript(detailsScriptUrl).then(() => {
          if (!window.__KNOWDIT_GRAPH_DETAILS__) {
            throw new Error('Detail payload did not initialize correctly.');
          }
          detailsPayload = window.__KNOWDIT_GRAPH_DETAILS__;
          return detailsPayload;
        });
      }
      return detailsLoadPromise;
    }

    async function bootstrap() {
      renderGraphStatus('Loading graph data…');
      const graphData = await ensureGraphDataLoaded();
      clearGraphStatus();

      const nodes = new vis.DataSet(graphData.nodes);
      const nodeFilters = graphData.nodeFilters;
      const edgeFilters = graphData.edgeFilters;
    const nodeFiltersContainer = document.getElementById('node-filters');
      const mergedNodeFiltersContainer = document.getElementById('merged-node-filters');
      const nodeFilterSummary = document.getElementById('node-filter-summary');
      const mergedNodeFilterSummary = document.getElementById('merged-node-filter-summary');
      const edgeFiltersContainer = document.getElementById('edge-filters');
      const edgeFilterSummary = document.getElementById('edge-filter-summary');
      const edgeLimitWarning = document.getElementById('graph-warning');
      const edgeLimitSlider = document.getElementById('edge-limit-slider');
      const edgeLimitValue = document.getElementById('edge-limit-value');
      const edgeLimitNote = document.getElementById('edge-limit-note');
      const sidebar = document.querySelector('.layout > aside');
      const headerElement = document.querySelector('header');
      const nodeFilterState = new Map(nodeFilters.map((filter) => [filter.id, filter.enabledByDefault]));
      const mergedNodeFilters = [
        {
          id: 'merged-semantic',
          label: 'Merged Semantic Nodes',
          count: graphData.nodes.filter((node) => node.nodeType === 'semantic' && node.isMerged).length,
          color: { background: '#fef3c7', border: '#b45309' },
        },
        {
          id: 'merged-finding',
          label: 'Merged Finding Nodes',
          count: graphData.nodes.filter((node) => node.nodeType === 'finding' && node.isMerged).length,
          color: { background: '#fde68a', border: '#b45309' },
        },
      ];
      const mergedNodeFilterState = new Map(mergedNodeFilters.map((filter) => [filter.id, true]));
      const edgeFilterState = new Map(edgeFilters.map((filter) => [filter.id, filter.enabledByDefault]));
      const edgeFilterById = new Map(edgeFilters.map((filter) => [filter.id, filter]));
      const edgeFilterOrder = new Map(edgeFilters.map((filter, index) => [filter.id, index]));
      const nodeById = new Map(graphData.nodes.map((node) => [node.id, node]));
      const nodeTypeById = new Map();
      const nodeIdsByType = new Map();
      const defaultViewportEdgeLimit = Math.max(1, graphData.viewportEdgeLimit);
      const edgeLimitSliderMin = Math.min(defaultViewportEdgeLimit, 25);
      const edgeLimitSliderMax = Math.max(defaultViewportEdgeLimit, graphData.stats.edgeCount);
      const edgeLimitSliderStep = graphData.stats.edgeCount <= 500
        ? 10
        : graphData.stats.edgeCount <= 2000
          ? 25
          : graphData.stats.edgeCount <= 5000
            ? 50
            : 100;
      const lockedNodePositions = new Map(
        graphData.nodes
          .filter((node) => Number.isFinite(node.x) && Number.isFinite(node.y))
          .map((node) => [node.id, { x: node.x, y: node.y }])
      );
      const edgeOrderById = new Map(graphData.edges.map((edge, index) => [edge.id, index]));
      for (const node of graphData.nodes) {
        nodeTypeById.set(node.id, node.nodeType);
        if (!nodeIdsByType.has(node.nodeType)) {
          nodeIdsByType.set(node.nodeType, []);
        }
        nodeIdsByType.get(node.nodeType).push(node.id);
      }
      let layoutLocked = lockedNodePositions.size === graphData.nodes.length;
      let hiddenNodeIds = new Set();
      let viewportVisibleNodeIds = new Set(graphData.nodes.map((node) => node.id));
      let viewportSyncHandle = null;
      let eligibleVisibleEdgeCount = 0;
      let edgeLimitExceeded = false;
      let currentViewportEdgeLimit = defaultViewportEdgeLimit;
      let graphHeightSyncHandle = null;

      function edgeRenderPriority(edge) {
        const filter = edgeFilterById.get(edge.edgeType);
        return {
          viewportPenalty: filter && filter.viewportCulled ? 0 : 1,
          filterOrder: edgeFilterOrder.get(edge.edgeType) ?? Number.MAX_SAFE_INTEGER,
          edgeOrder: edgeOrderById.get(edge.id) ?? Number.MAX_SAFE_INTEGER,
        };
      }

      function clampViewportEdgeLimit(rawValue) {
        const nextValue = Number(rawValue);
        if (!Number.isFinite(nextValue) || nextValue <= 0) {
          return defaultViewportEdgeLimit;
        }
        return Math.min(edgeLimitSliderMax, Math.max(edgeLimitSliderMin, nextValue));
      }

      function updateEdgeLimitControls() {
        edgeLimitSlider.min = String(edgeLimitSliderMin);
        edgeLimitSlider.max = String(edgeLimitSliderMax);
        edgeLimitSlider.step = String(edgeLimitSliderStep);
        edgeLimitSlider.value = String(currentViewportEdgeLimit);
        edgeLimitValue.textContent =
          `${currentViewportEdgeLimit} current · ${defaultViewportEdgeLimit} exported default`;
        edgeLimitNote.textContent =
          `Adjust the per-view render cap for this page only. The exported default remains ${defaultViewportEdgeLimit}.`;
      }

      function limitEdgeRecords(candidateEdges) {
        const eligibleCount = candidateEdges.length;
        const activeViewportEdgeLimit = currentViewportEdgeLimit;
        if (eligibleCount <= activeViewportEdgeLimit) {
          return {
            edgeRecords: candidateEdges,
            eligibleCount,
            limitExceeded: false,
          };
        }

        const prioritized = candidateEdges.slice().sort((left, right) => {
          const leftPriority = edgeRenderPriority(left);
          const rightPriority = edgeRenderPriority(right);
          if (leftPriority.viewportPenalty !== rightPriority.viewportPenalty) {
            return leftPriority.viewportPenalty - rightPriority.viewportPenalty;
          }
          if (leftPriority.filterOrder !== rightPriority.filterOrder) {
            return leftPriority.filterOrder - rightPriority.filterOrder;
          }
          return leftPriority.edgeOrder - rightPriority.edgeOrder;
        });

        return {
          edgeRecords: prioritized.slice(0, activeViewportEdgeLimit),
          eligibleCount,
          limitExceeded: true,
        };
      }

      const initialEdgeSelection = limitEdgeRecords(
        graphData.edges.filter((edge) => edgeBoolean(edgeFilterState.get(edge.edgeType)))
      );
      eligibleVisibleEdgeCount = initialEdgeSelection.eligibleCount;
      edgeLimitExceeded = initialEdgeSelection.limitExceeded;
      const initialEdges = initialEdgeSelection.edgeRecords;
      const edges = new vis.DataSet(initialEdges);
    const network = new vis.Network(
      container,
      { nodes, edges },
      {
        autoResize: true,
        layout: {
          improvedLayout: false
        },
        interaction: {
          hover: true,
          navigationButtons: true,
          keyboard: true,
          multiselect: true,
          hideEdgesOnDrag: true
        },
        physics: false,
        nodes: {
          margin: 12,
          widthConstraint: { maximum: 260 },
          font: { size: 14, face: 'Inter, ui-sans-serif, system-ui, sans-serif' }
        },
        edges: {
          smooth: { type: 'cubicBezier', forceDirection: 'horizontal', roundness: 0.28 },
          arrows: { to: { enabled: true, scaleFactor: 0.65 } }
        }
      }
    );
    window.__knowditNetwork = network;
    window.__knowditNodeFilterState = nodeFilterState;
    window.__knowditEdgeFilterState = edgeFilterState;

    const summaryStats = document.getElementById('summary-stats');
    summaryStats.textContent =
      `${graphData.stats.projectCount} projects · ` +
      `${graphData.stats.categoryCount} categories · ` +
      `${graphData.stats.semanticCount} semantics (${graphData.stats.activeSemanticCount} active) · ` +
      `${graphData.stats.findingCount} findings (${graphData.stats.activeFindingCount} active) · ` +
      `${graphData.stats.edgeCount} edges`;

    const detailsPanel = document.getElementById('details-panel');
      let currentSelection = null;

    function mergedNodeFilterIdForNode(node) {
      if (!node || !node.isMerged) {
        return null;
      }
      if (node.nodeType === 'semantic') {
        return 'merged-semantic';
      }
      if (node.nodeType === 'finding') {
        return 'merged-finding';
      }
      return null;
    }

    function shouldHideNode(node) {
      if (!node) {
        return false;
      }
      if (!edgeBoolean(nodeFilterState.get(node.nodeType))) {
        return true;
      }
      const mergedFilterId = mergedNodeFilterIdForNode(node);
      if (mergedFilterId && !edgeBoolean(mergedNodeFilterState.get(mergedFilterId))) {
        return true;
      }
      return false;
    }

    function isNodeVisible(nodeId) {
      const node = nodeById.get(nodeId);
      return node ? !shouldHideNode(node) : true;
    }

    function edgeBoolean(value) {
      return value !== false;
    }

    function visibleNodeIds() {
      return graphData.nodes
        .filter((node) => !shouldHideNode(node))
        .map((node) => node.id);
    }

    function syncGraphHeight({ redraw = true } = {}) {
      if (graphHeightSyncHandle !== null) {
        window.cancelAnimationFrame(graphHeightSyncHandle);
      }

      graphHeightSyncHandle = window.requestAnimationFrame(() => {
        graphHeightSyncHandle = null;

        if (window.matchMedia('(max-width: 1100px)').matches) {
          container.style.height = '';
          if (redraw) {
            network.redraw();
            scheduleVisibleEdgeSync();
          }
          return;
        }

        const headerHeight = headerElement ? headerElement.getBoundingClientRect().height : 126;
        const minHeight = Math.max(720, window.innerHeight - headerHeight);
        const sidebarHeight = sidebar ? sidebar.scrollHeight : minHeight;
        const nextHeight = `${Math.ceil(Math.max(minHeight, sidebarHeight))}px`;
        const changed = container.style.height !== nextHeight;
        container.style.height = nextHeight;

        if (redraw || changed) {
          network.redraw();
          scheduleVisibleEdgeSync();
        }
      });
    }

    function updatePerformanceNote() {
      const viewportCullingActive = edgeFilters.some((filter) =>
        filter.viewportCulled && edgeBoolean(edgeFilterState.get(filter.id))
      );
      const baseMessage = graphData.stats.largeGraphMode
        ? 'Large graph mode: only lightweight edge classes start enabled, and full selection details load from a companion file on first click.'
        : 'Full selection details load from a companion file on first click to keep the page responsive.';
      const viewportMessage = viewportCullingActive
        ? ' Dense project relationship edges render only for nodes inside the current viewport.'
        : '';
      performanceNote.textContent =
        `${baseMessage}${viewportMessage} Each view currently renders at most ${currentViewportEdgeLimit} edges; the exported default is ${defaultViewportEdgeLimit}.`;
    }

    function updateEdgeLimitWarning() {
      if (!edgeLimitExceeded) {
        edgeLimitWarning.hidden = true;
        edgeLimitWarning.textContent = '';
        return;
      }

      edgeLimitWarning.hidden = false;
      edgeLimitWarning.textContent =
        `Too many edges in view (${eligibleVisibleEdgeCount} > ${currentViewportEdgeLimit} limit). ` +
        'Zoom in or raise the viewport edge limit in the right sidebar.';
    }

    function lockCurrentLayout() {
      if (layoutLocked) {
        return;
      }

      const updates = graphData.nodes
        .map((node) => {
          const position = network.getPosition(node.id);
          if (!Number.isFinite(position.x) || !Number.isFinite(position.y)) {
            return null;
          }
          lockedNodePositions.set(node.id, position);
          return {
            id: node.id,
            x: position.x,
            y: position.y,
            fixed: { x: true, y: true },
          };
        })
        .filter(Boolean);

      if (updates.length === 0) {
        return;
      }

      nodes.update(updates);
      network.setOptions({
        layout: { hierarchical: false },
        physics: false,
      });
      layoutLocked = true;
      reapplyLockedLayout();
    }

    function reapplyLockedLayout() {
      if (!layoutLocked) {
        return;
      }

      const updates = graphData.nodes
        .map((node) => {
          const position = lockedNodePositions.get(node.id);
          if (!position) {
            return null;
          }
          return {
            id: node.id,
            x: position.x,
            y: position.y,
            fixed: { x: true, y: true },
          };
        })
        .filter(Boolean);

      if (updates.length > 0) {
        nodes.update(updates);
      }
    }

    function getNodePosition(nodeId) {
      const locked = lockedNodePositions.get(nodeId);
      if (locked) {
        return locked;
      }
      const position = network.getPosition(nodeId);
      if (!Number.isFinite(position.x) || !Number.isFinite(position.y)) {
        return null;
      }
      return position;
    }

    function currentViewportBounds() {
      if (!layoutLocked) {
        return null;
      }
      const topLeft = network.DOMtoCanvas({ x: 0, y: 0 });
      const bottomRight = network.DOMtoCanvas({ x: container.clientWidth, y: container.clientHeight });
      const scale = Math.max(network.getScale(), 0.01);
      const canvasMargin = 180 / scale;
      return {
        minX: Math.min(topLeft.x, bottomRight.x) - canvasMargin,
        maxX: Math.max(topLeft.x, bottomRight.x) + canvasMargin,
        minY: Math.min(topLeft.y, bottomRight.y) - canvasMargin,
        maxY: Math.max(topLeft.y, bottomRight.y) + canvasMargin,
      };
    }

    function computeViewportVisibleNodeIds() {
      const bounds = currentViewportBounds();
      if (!bounds) {
        return new Set(visibleNodeIds());
      }

      const nextViewportNodeIds = new Set();
      for (const node of graphData.nodes) {
        if (hiddenNodeIds.has(node.id)) {
          continue;
        }
        const position = getNodePosition(node.id);
        if (!position) {
          nextViewportNodeIds.add(node.id);
          continue;
        }
        if (
          position.x >= bounds.minX &&
          position.x <= bounds.maxX &&
          position.y >= bounds.minY &&
          position.y <= bounds.maxY
        ) {
          nextViewportNodeIds.add(node.id);
        }
      }
      return nextViewportNodeIds;
    }

    function shouldRenderEdge(edge) {
      if (!edgeBoolean(edgeFilterState.get(edge.edgeType))) {
        return false;
      }
      if (hiddenNodeIds.has(edge.from) || hiddenNodeIds.has(edge.to)) {
        return false;
      }
      const filter = edgeFilterById.get(edge.edgeType);
      if (filter && filter.viewportCulled) {
        return viewportVisibleNodeIds.has(edge.from) && viewportVisibleNodeIds.has(edge.to);
      }
      return true;
    }

    function updateNodeFilterSummary() {
      const availableFilterCount = nodeFilters.filter((filter) => filter.count > 0).length;
      let enabledFilterCount = 0;
      for (const filter of nodeFilters) {
        if (filter.count === 0) {
          continue;
        }
        if (edgeBoolean(nodeFilterState.get(filter.id))) {
          enabledFilterCount += 1;
        }
      }
      const visibleNodeCount = graphData.nodes.filter((node) => !shouldHideNode(node)).length;
      nodeFilterSummary.textContent =
        `Showing ${visibleNodeCount} / ${graphData.nodes.length} nodes across ` +
        `${enabledFilterCount} / ${availableFilterCount} available node types.`;
    }

    function updateMergedNodeFilterSummary() {
      const hiddenMergedCount = mergedNodeFilters.reduce((count, filter) => {
        if (edgeBoolean(mergedNodeFilterState.get(filter.id))) {
          return count;
        }
        return count + filter.count;
      }, 0);
      const totalMergedCount = mergedNodeFilters.reduce((count, filter) => count + filter.count, 0);

      if (totalMergedCount === 0) {
        mergedNodeFilterSummary.textContent = 'No merged semantic or finding nodes are present in this export.';
        return;
      }

      if (hiddenMergedCount === 0) {
        mergedNodeFilterSummary.textContent = `Showing all ${totalMergedCount} merged semantic/finding nodes.`;
        return;
      }

      mergedNodeFilterSummary.textContent = `Hiding ${hiddenMergedCount} / ${totalMergedCount} merged semantic/finding nodes.`;
    }

    function updateEdgeFilterSummary() {
      const availableFilterCount = edgeFilters.filter((filter) => filter.count > 0).length;
      let enabledFilterCount = 0;
      const viewportCullingActive = edgeFilters.some((filter) =>
        filter.viewportCulled && edgeBoolean(edgeFilterState.get(filter.id))
      );
      for (const filter of edgeFilters) {
        if (filter.count === 0) {
          continue;
        }
        if (edgeBoolean(edgeFilterState.get(filter.id))) {
          enabledFilterCount += 1;
        }
      }
      edgeFilterSummary.textContent =
        `Rendering ${edges.getIds().length} / ${graphData.stats.edgeCount} edges across ` +
        `${enabledFilterCount} / ${availableFilterCount} available edge types.` +
        (viewportCullingActive
          ? ' Dense project relationship edges are limited to nodes in the current viewport.'
          : '') +
        (edgeLimitExceeded
          ? ` Current view matches ${eligibleVisibleEdgeCount} edges, so rendering is capped at ${currentViewportEdgeLimit}.`
          : '');
    }

    function syncVisibleEdges({ clearSelection = false } = {}) {
      viewportVisibleNodeIds = computeViewportVisibleNodeIds();
      const candidateEdges = [];
      for (const edge of graphData.edges) {
        if (shouldRenderEdge(edge)) {
          candidateEdges.push(edge);
        }
      }
      const edgeSelection = limitEdgeRecords(candidateEdges);
      eligibleVisibleEdgeCount = edgeSelection.eligibleCount;
      edgeLimitExceeded = edgeSelection.limitExceeded;
      const activeEdgeIds = new Set(edges.getIds());
      const nextEdgeIds = new Set(edgeSelection.edgeRecords.map((edge) => edge.id));
      const edgeIdsToRemove = [];
      const edgeRecordsToAdd = [];
      for (const edgeId of activeEdgeIds) {
        if (!nextEdgeIds.has(edgeId)) {
          edgeIdsToRemove.push(edgeId);
        }
      }
      for (const edge of edgeSelection.edgeRecords) {
        if (!activeEdgeIds.has(edge.id)) {
          edgeRecordsToAdd.push(edge);
        }
      }
      if (edgeIdsToRemove.length > 0) {
        edges.remove(edgeIdsToRemove);
      }
      if (edgeRecordsToAdd.length > 0) {
        edges.add(edgeRecordsToAdd);
      }
      if (clearSelection) {
        network.unselectAll();
        renderEmptyDetails();
        currentSelection = null;
      }
      reapplyLockedLayout();
      if (edgeIdsToRemove.length > 0 || edgeRecordsToAdd.length > 0) {
        network.redraw();
      }
      updateEdgeFilterSummary();
      updatePerformanceNote();
      updateEdgeLimitWarning();
    }

    function scheduleVisibleEdgeSync() {
      if (viewportSyncHandle !== null) {
        window.clearTimeout(viewportSyncHandle);
      }
      viewportSyncHandle = window.setTimeout(() => {
        viewportSyncHandle = null;
        syncVisibleEdges();
      }, 80);
    }

    function applyFilters({ clearSelection = true } = {}) {
      const nextHiddenNodeIds = new Set();
      const nodeUpdates = [];
      for (const node of graphData.nodes) {
        const hidden = shouldHideNode(node);
        nodeUpdates.push({ id: node.id, hidden });
        if (hidden) {
          nextHiddenNodeIds.add(node.id);
        }
      }
      hiddenNodeIds = nextHiddenNodeIds;
      if (nodeUpdates.length > 0) {
        nodes.update(nodeUpdates);
      }
      updateNodeFilterSummary();
      updateMergedNodeFilterSummary();
      syncVisibleEdges({ clearSelection });
    }

    function renderNodeFilters() {
      nodeFiltersContainer.innerHTML = '';
      for (const filter of nodeFilters) {
        const option = document.createElement('label');
        option.className = 'node-filter-option';
        if (filter.count === 0) {
          option.classList.add('is-disabled');
        }

        const input = document.createElement('input');
        input.type = 'checkbox';
        input.checked = edgeBoolean(nodeFilterState.get(filter.id));
        input.disabled = filter.count === 0;
        input.dataset.nodeType = filter.id;
        input.addEventListener('change', () => {
          nodeFilterState.set(filter.id, input.checked);
          applyFilters();
        });

        const swatch = document.createElement('span');
        swatch.className = 'node-filter-swatch';
        swatch.style.setProperty('--node-background', filter.color.background);
        swatch.style.setProperty('--node-border', filter.color.border);

        const text = document.createElement('span');
        text.className = 'edge-filter-text';

        const name = document.createElement('span');
        name.className = 'edge-filter-name';
        name.textContent = filter.label;

        const meta = document.createElement('span');
        meta.className = 'edge-filter-meta';
        meta.textContent = filter.count === 1 ? '1 node' : `${filter.count} nodes`;

        text.appendChild(name);
        text.appendChild(meta);
        option.appendChild(input);
        option.appendChild(swatch);
        option.appendChild(text);
        nodeFiltersContainer.appendChild(option);
      }

      updateNodeFilterSummary();
    }

    function renderMergedNodeFilters() {
      mergedNodeFiltersContainer.innerHTML = '';
      for (const filter of mergedNodeFilters) {
        const option = document.createElement('label');
        option.className = 'node-filter-option';
        if (filter.count === 0) {
          option.classList.add('is-disabled');
        }

        const input = document.createElement('input');
        input.type = 'checkbox';
        input.checked = edgeBoolean(mergedNodeFilterState.get(filter.id));
        input.disabled = filter.count === 0;
        input.dataset.mergedNodeType = filter.id;
        input.addEventListener('change', () => {
          mergedNodeFilterState.set(filter.id, input.checked);
          applyFilters();
        });

        const swatch = document.createElement('span');
        swatch.className = 'node-filter-swatch';
        swatch.style.setProperty('--node-background', filter.color.background);
        swatch.style.setProperty('--node-border', filter.color.border);

        const text = document.createElement('span');
        text.className = 'edge-filter-text';

        const name = document.createElement('span');
        name.className = 'edge-filter-name';
        name.textContent = filter.label;

        const meta = document.createElement('span');
        meta.className = 'edge-filter-meta';
        meta.textContent = filter.count === 1 ? '1 node' : `${filter.count} nodes`;

        text.appendChild(name);
        text.appendChild(meta);
        option.appendChild(input);
        option.appendChild(swatch);
        option.appendChild(text);
        mergedNodeFiltersContainer.appendChild(option);
      }

      updateMergedNodeFilterSummary();
    }

    function renderEdgeFilters() {
      edgeFiltersContainer.innerHTML = '';
      for (const filter of edgeFilters) {
        const option = document.createElement('label');
        option.className = 'edge-filter-option';
        if (filter.count === 0) {
          option.classList.add('is-disabled');
        }

        const input = document.createElement('input');
        input.type = 'checkbox';
        input.checked = edgeFilterState.get(filter.id);
        input.disabled = filter.count === 0;
        input.dataset.edgeType = filter.id;
        input.addEventListener('change', () => {
          edgeFilterState.set(filter.id, input.checked);
          applyFilters();
        });

        const swatch = document.createElement('span');
        swatch.className = 'edge-filter-swatch';
        swatch.style.setProperty('--edge-color', filter.color);
        swatch.style.borderTopStyle = filter.dashed ? 'dashed' : 'solid';

        const text = document.createElement('span');
        text.className = 'edge-filter-text';

        const name = document.createElement('span');
        name.className = 'edge-filter-name';
        name.textContent = filter.label;

        const meta = document.createElement('span');
        meta.className = 'edge-filter-meta';
        const edgeCountLabel = filter.count === 1 ? '1 edge total' : `${filter.count} edges total`;
        meta.textContent = filter.viewportCulled
          ? `${edgeCountLabel} · current view only`
          : edgeCountLabel;

        text.appendChild(name);
        text.appendChild(meta);
        option.appendChild(input);
        option.appendChild(swatch);
        option.appendChild(text);
        edgeFiltersContainer.appendChild(option);
      }

      updateEdgeFilterSummary();
    }

    edgeLimitSlider.addEventListener('input', () => {
      currentViewportEdgeLimit = clampViewportEdgeLimit(edgeLimitSlider.value);
      updateEdgeLimitControls();
      syncVisibleEdges();
    });

    function selectionKey(selection) {
      return selection ? `${selection.kind}:${selection.id}` : '';
    }

    function renderDetails(details) {
      if (!details) {
        renderEmptyDetails();
        return;
      }
      detailsPanel.innerHTML = '';

      const title = document.createElement('h2');
      title.className = 'detail-title';
      title.textContent = details.title;
      detailsPanel.appendChild(title);

      if (details.subtitle) {
        const subtitle = document.createElement('div');
        subtitle.className = 'detail-subtitle';
        subtitle.textContent = details.subtitle;
        detailsPanel.appendChild(subtitle);
      }

      if (!details.fields || details.fields.length === 0) {
        const empty = document.createElement('p');
        empty.className = 'hint';
        empty.textContent = 'No additional details available.';
        detailsPanel.appendChild(empty);
        return;
      }

      const list = document.createElement('dl');
      for (const field of details.fields) {
        const wrapper = document.createElement('div');
        const dt = document.createElement('dt');
        dt.textContent = field.label;
        const dd = document.createElement('dd');
        dd.textContent = field.value;
        wrapper.appendChild(dt);
        wrapper.appendChild(dd);
        list.appendChild(wrapper);
      }
      detailsPanel.appendChild(list);
      syncGraphHeight();
    }

    function renderLoadingDetails(selection) {
      detailsPanel.innerHTML = '';

      const title = document.createElement('h2');
      title.className = 'detail-title';
      title.textContent = selection.kind === 'node' ? 'Loading node details…' : 'Loading edge details…';
      detailsPanel.appendChild(title);

      const hint = document.createElement('p');
      hint.className = 'hint';
      hint.textContent = 'The full metadata lives in a companion details file and is being loaded now.';
      detailsPanel.appendChild(hint);
      syncGraphHeight();
    }

    function renderDetailsLoadError(error) {
      detailsPanel.innerHTML = '';

      const title = document.createElement('h2');
      title.className = 'detail-title';
      title.textContent = 'Could not load selection details';
      detailsPanel.appendChild(title);

      const hint = document.createElement('p');
      hint.className = 'hint';
      hint.textContent = `${error.message}. Keep the HTML, graph data, and details files together when opening the export.`;
      detailsPanel.appendChild(hint);
      syncGraphHeight();
    }

    function renderMissingDetails(selection) {
      detailsPanel.innerHTML = '';

      const title = document.createElement('h2');
      title.className = 'detail-title';
      title.textContent = selection.kind === 'node' ? 'Node details unavailable' : 'Edge details unavailable';
      detailsPanel.appendChild(title);

      const hint = document.createElement('p');
      hint.className = 'hint';
      hint.textContent = 'The selection exists in the graph, but no companion detail record was found for it.';
      detailsPanel.appendChild(hint);
      syncGraphHeight();
    }

    function renderEmptyDetails() {
      detailsPanel.innerHTML = '';

      const title = document.createElement('h2');
      title.className = 'detail-title';
      title.textContent = 'Selection details';
      detailsPanel.appendChild(title);

      const hint = document.createElement('p');
      hint.className = 'hint';
      hint.textContent = 'Click a node or edge to inspect the full metadata. Drag the canvas to pan, scroll to zoom, and use the toolbar to refit or restabilize the graph. Large detail payloads load on demand.';
      detailsPanel.appendChild(hint);
      syncGraphHeight();
    }

    async function showSelection(selection) {
      currentSelection = selection;
      renderLoadingDetails(selection);
      try {
        const payload = await ensureDetailsLoaded();
        if (selectionKey(currentSelection) !== selectionKey(selection)) {
          return;
        }
        const details = selection.kind === 'node'
          ? payload.nodeDetails[selection.id]
          : payload.edgeDetails[selection.id];
        if (details) {
          renderDetails(details);
        } else {
          renderMissingDetails(selection);
        }
      } catch (error) {
        if (selectionKey(currentSelection) === selectionKey(selection)) {
          renderDetailsLoadError(error);
        }
      }
    }

    window.__knowditShowSelection = showSelection;
    window.__knowditEnsureDetailsLoaded = ensureDetailsLoaded;
    window.__knowditSyncVisibleEdges = syncVisibleEdges;

    network.on('click', (params) => {
      if (params.nodes.length > 0) {
        void showSelection({ kind: 'node', id: params.nodes[0] });
        return;
      }
      if (params.edges.length > 0) {
        void showSelection({ kind: 'edge', id: params.edges[0] });
        return;
      }
      currentSelection = null;
      renderEmptyDetails();
    });

    function ensureReadableScale(animated) {
      const minReadableScale = 0.08;
      const currentScale = network.getScale();
      if (currentScale < minReadableScale) {
        network.moveTo({
          position: network.getViewPosition(),
          scale: minReadableScale,
          animation: animated ? { duration: 250, easingFunction: 'easeInOutQuad' } : false
        });
      }
    }

    function initialViewportTarget() {
      const projectNodes = graphData.nodes.filter((node) => node.nodeType === 'project');
      const categoryNodes = graphData.nodes.filter((node) => node.nodeType === 'category');
      const semanticNodes = graphData.nodes.filter((node) => node.nodeType === 'semantic');
      const findingNodes = graphData.nodes.filter((node) => node.nodeType === 'finding');

      const uniqueSemanticXs = Array.from(new Set(semanticNodes.map((node) => node.x))).sort((left, right) => left - right);
      const categoryMaxX = categoryNodes.length > 0
        ? Math.max(...categoryNodes.map((node) => node.x))
        : (projectNodes.length > 0 ? Math.max(...projectNodes.map((node) => node.x)) : 0);
      const semanticFocusX = uniqueSemanticXs.length > 0
        ? uniqueSemanticXs[Math.min(1, uniqueSemanticXs.length - 1)]
        : categoryMaxX;

      const semanticCenterY = semanticNodes.length > 0
        ? (Math.min(...semanticNodes.map((node) => node.y)) + Math.max(...semanticNodes.map((node) => node.y))) / 2
        : 0;
      const findingMinY = findingNodes.length > 0
        ? Math.min(...findingNodes.map((node) => node.y))
        : semanticCenterY;
      const findingCenterY = findingNodes.length > 0
        ? (findingMinY + Math.max(...findingNodes.map((node) => node.y))) / 2
        : semanticCenterY;

      return {
        position: {
          x: (categoryMaxX + semanticFocusX) / 2,
          y: findingNodes.length > 0 ? (semanticCenterY + findingMinY) / 2 : semanticCenterY,
        },
        scale: graphData.stats.largeGraphMode ? 0.28 : 0.42,
      };
    }

    function moveToInitialViewport() {
      const target = initialViewportTarget();
      network.moveTo({
        position: target.position,
        scale: target.scale,
        animation: false,
      });
    }

    function fitGraph(animated = true) {
      const nodesToFit = visibleNodeIds();
      if (nodesToFit.length === 0) {
        return;
      }
      if (animated) {
        network.once('animationFinished', () => ensureReadableScale(true));
        network.fit({
          nodes: nodesToFit,
          animation: { duration: 400, easingFunction: 'easeInOutQuad' },
        });
        return;
      }

      network.fit({ nodes: nodesToFit, animation: false });
      ensureReadableScale(false);
      scheduleVisibleEdgeSync();
    }

    network.on('dragEnd', () => {
      scheduleVisibleEdgeSync();
    });
    network.on('zoom', () => {
      scheduleVisibleEdgeSync();
    });
    network.on('animationFinished', () => {
      scheduleVisibleEdgeSync();
    });

    renderNodeFilters();
    renderMergedNodeFilters();
    renderEdgeFilters();
    updateEdgeLimitControls();
    if (!layoutLocked) {
      lockCurrentLayout();
    } else {
      reapplyLockedLayout();
    }
    moveToInitialViewport();
    applyFilters({ clearSelection: false });
    window.addEventListener('resize', () => {
      syncGraphHeight();
    });

    document.getElementById('fit-button').addEventListener('click', () => {
      fitGraph(true);
    });

    document.getElementById('stabilize-button').addEventListener('click', () => {
      network.redraw();
      fitGraph(true);
    });

    renderEmptyDetails();
  syncGraphHeight({ redraw: false });
    }

    bootstrap().catch((error) => {
      renderGraphStatus(`${error.message}. Keep the exported asset files together and ensure the browser can load local scripts.`, true);
      const detailsPanel = document.getElementById('details-panel');
      detailsPanel.innerHTML = '';
      const title = document.createElement('h2');
      title.className = 'detail-title';
      title.textContent = 'Could not initialize graph';
      detailsPanel.appendChild(title);
      const hint = document.createElement('p');
      hint.className = 'hint';
      hint.textContent = `${error.message}.`;
      detailsPanel.appendChild(hint);
    });
  </script>
</body>
</html>
"#,
        );

        Ok(HtmlExportAssets {
            html,
            graph_data_js: format!("window.__KNOWDIT_GRAPH_DATA__ = {};\n", graph_payload_js),
            details_js: format!(
                "window.__KNOWDIT_GRAPH_DETAILS__ = {};\n",
                details_payload_js
            ),
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HtmlGraphPayload {
    nodes: Vec<HtmlGraphNode>,
    edges: Vec<HtmlGraphEdge>,
    node_filters: Vec<HtmlNodeFilter>,
    edge_filters: Vec<HtmlEdgeFilter>,
    viewport_edge_limit: usize,
    stats: HtmlGraphStats,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HtmlGraphDetailsPayload {
    node_details: HashMap<String, HtmlSelectionDetails>,
    edge_details: HashMap<String, HtmlSelectionDetails>,
}

pub struct HtmlExportAssets {
    pub html: String,
    pub graph_data_js: String,
    pub details_js: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HtmlGraphStats {
    project_count: usize,
    category_count: usize,
    semantic_count: usize,
    active_semantic_count: usize,
    finding_count: usize,
    active_finding_count: usize,
    edge_count: usize,
    large_graph_mode: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HtmlGraphNode {
    id: String,
    label: String,
    node_type: String,
    is_merged: bool,
    level: u8,
    shape: String,
    color: HtmlNodeColor,
    border_width: u8,
    x: f64,
    y: f64,
    fixed: HtmlNodeFixed,
}

#[derive(Serialize)]
struct HtmlNodeFixed {
    x: bool,
    y: bool,
}

impl HtmlNodeFixed {
    fn locked() -> Self {
        Self { x: true, y: true }
    }
}

#[derive(Clone, Copy)]
struct HtmlNodePosition {
    x: f64,
    y: f64,
}

#[derive(Serialize)]
struct HtmlNodeColor {
    background: String,
    border: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HtmlNodeFilter {
    id: String,
    label: String,
    count: usize,
    enabled_by_default: bool,
    color: HtmlNodeColor,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HtmlGraphEdge {
    id: String,
    from: String,
    to: String,
    edge_type: String,
    arrows: String,
    color: HtmlEdgeColor,
    dashes: bool,
    width: f32,
}

#[derive(Serialize)]
struct HtmlEdgeColor {
    color: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HtmlEdgeFilter {
    id: String,
    label: String,
    count: usize,
    enabled_by_default: bool,
    viewport_culled: bool,
    color: String,
    dashed: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HtmlSelectionDetails {
    title: String,
    subtitle: Option<String>,
    fields: Vec<HtmlDetailField>,
}

#[derive(Serialize)]
struct HtmlDetailField {
    label: String,
    value: String,
}

const NODE_TYPE_PROJECT: &str = "project";
const NODE_TYPE_CATEGORY: &str = "category";
const NODE_TYPE_SEMANTIC: &str = "semantic";
const NODE_TYPE_FINDING: &str = "finding";

const EDGE_TYPE_PROJECT_CATEGORY: &str = "project-category";
const EDGE_TYPE_PROJECT_SEMANTIC: &str = "project-semantic";
const EDGE_TYPE_PROJECT_FINDING: &str = "project-finding";
const EDGE_TYPE_SEMANTIC_MERGE: &str = "semantic-merge";
const EDGE_TYPE_FINDING_MERGE: &str = "finding-merge";
const EDGE_TYPE_SEMANTIC_FINDING: &str = "semantic-finding";

const LARGE_GRAPH_NODE_THRESHOLD: usize = 2_000;
const LARGE_GRAPH_EDGE_THRESHOLD: usize = 4_000;

const PROJECT_COLUMN_X: f64 = 0.0;
const CATEGORY_COLUMN_X: f64 = 460.0;
const SEMANTIC_COLUMN_X: f64 = 1040.0;
const FINDING_COLUMN_X: f64 = 1840.0;

const PROJECT_ROW_SPACING: f64 = 180.0;
const CATEGORY_ROW_SPACING: f64 = 180.0;
const SEMANTIC_ROW_SPACING: f64 = 180.0;
const FINDING_ROW_SPACING: f64 = 180.0;

const PROJECT_COLUMN_SPACING: f64 = 280.0;
const SEMANTIC_COLUMN_SPACING: f64 = 380.0;
const FINDING_COLUMN_SPACING: f64 = 380.0;
const FINDING_VERTICAL_GAP: f64 = 360.0;

fn vertical_node_positions(
    ids: &[i32],
    column_x: f64,
    row_spacing: f64,
) -> HashMap<i32, HtmlNodePosition> {
    ids.iter()
        .enumerate()
        .map(|(index, id)| {
            (
                *id,
                HtmlNodePosition {
                    x: column_x,
                    y: centered_axis_offset(index, ids.len(), row_spacing),
                },
            )
        })
        .collect()
}

fn grid_node_positions(
    ids: &[i32],
    start_x: f64,
    rows: usize,
    row_spacing: f64,
    column_spacing: f64,
    center_y: f64,
) -> HashMap<i32, HtmlNodePosition> {
    if ids.is_empty() {
        return HashMap::new();
    }

    let row_count = ids.len().min(rows.max(1));
    ids.iter()
        .enumerate()
        .map(|(index, id)| {
            let column_index = index / row_count;
            let row_index = index % row_count;
            (
                *id,
                HtmlNodePosition {
                    x: start_x + column_index as f64 * column_spacing,
                    y: center_y + centered_axis_offset(row_index, row_count, row_spacing),
                },
            )
        })
        .collect()
}

fn right_aligned_grid_node_positions(
    ids: &[i32],
    anchor_x: f64,
    rows: usize,
    row_spacing: f64,
    column_spacing: f64,
    center_y: f64,
) -> HashMap<i32, HtmlNodePosition> {
    if ids.is_empty() {
        return HashMap::new();
    }

    let row_count = ids.len().min(rows.max(1));
    ids.iter()
        .enumerate()
        .map(|(index, id)| {
            let column_index = index / row_count;
            let row_index = index % row_count;
            (
                *id,
                HtmlNodePosition {
                    x: anchor_x - column_index as f64 * column_spacing,
                    y: center_y + centered_axis_offset(row_index, row_count, row_spacing),
                },
            )
        })
        .collect()
}

fn grid_band_half_height(item_count: usize, rows: usize, row_spacing: f64) -> f64 {
    let row_count = item_count.min(rows.max(1));
    if row_count <= 1 {
        0.0
    } else {
        (row_count.saturating_sub(1) as f64 / 2.0) * row_spacing
    }
}

fn centered_axis_offset(index: usize, count: usize, spacing: f64) -> f64 {
    if count <= 1 {
        return 0.0;
    }

    (index as f64 - (count.saturating_sub(1) as f64 / 2.0)) * spacing
}

fn bump_node_type_count(
    node_type_counts: &mut HashMap<&'static str, usize>,
    node_type: &'static str,
) {
    *node_type_counts.entry(node_type).or_insert(0) += 1;
}

fn bump_edge_type_count(
    edge_type_counts: &mut HashMap<&'static str, usize>,
    edge_type: &'static str,
) {
    *edge_type_counts.entry(edge_type).or_insert(0) += 1;
}

fn html_node_filters(node_type_counts: &HashMap<&'static str, usize>) -> Vec<HtmlNodeFilter> {
    vec![
        html_node_filter(
            NODE_TYPE_PROJECT,
            "Projects",
            HtmlNodeColor {
                background: "#dcfce7".to_string(),
                border: "#16a34a".to_string(),
            },
            node_type_counts,
        ),
        html_node_filter(
            NODE_TYPE_CATEGORY,
            "DeFi Categories",
            HtmlNodeColor {
                background: "#dbeafe".to_string(),
                border: "#2563eb".to_string(),
            },
            node_type_counts,
        ),
        html_node_filter(
            NODE_TYPE_SEMANTIC,
            "Semantic Nodes",
            HtmlNodeColor {
                background: "#fff4cc".to_string(),
                border: "#a67c00".to_string(),
            },
            node_type_counts,
        ),
        html_node_filter(
            NODE_TYPE_FINDING,
            "Audit Findings",
            HtmlNodeColor {
                background: "#fee2e2".to_string(),
                border: "#dc2626".to_string(),
            },
            node_type_counts,
        ),
    ]
}

fn html_node_filter(
    id: &'static str,
    label: &'static str,
    color: HtmlNodeColor,
    node_type_counts: &HashMap<&'static str, usize>,
) -> HtmlNodeFilter {
    HtmlNodeFilter {
        id: id.to_string(),
        label: label.to_string(),
        count: *node_type_counts.get(id).unwrap_or(&0),
        enabled_by_default: true,
        color,
    }
}

fn html_edge_filters(
    edge_type_counts: &HashMap<&'static str, usize>,
    large_graph_mode: bool,
) -> Vec<HtmlEdgeFilter> {
    vec![
        html_edge_filter(
            EDGE_TYPE_PROJECT_CATEGORY,
            "Project -> Category",
            "#6b7280",
            true,
            true,
            true,
            edge_type_counts,
        ),
        html_edge_filter(
            EDGE_TYPE_PROJECT_SEMANTIC,
            "Project -> Semantic",
            "#166534",
            false,
            !large_graph_mode,
            true,
            edge_type_counts,
        ),
        html_edge_filter(
            EDGE_TYPE_PROJECT_FINDING,
            "Project -> Finding",
            "#b91c1c",
            false,
            !large_graph_mode,
            true,
            edge_type_counts,
        ),
        html_edge_filter(
            EDGE_TYPE_SEMANTIC_MERGE,
            "Semantic Merge",
            "#7c3aed",
            true,
            !large_graph_mode,
            false,
            edge_type_counts,
        ),
        html_edge_filter(
            EDGE_TYPE_FINDING_MERGE,
            "Finding Merge",
            "#ea580c",
            true,
            !large_graph_mode,
            false,
            edge_type_counts,
        ),
        html_edge_filter(
            EDGE_TYPE_SEMANTIC_FINDING,
            "Semantic -> Finding",
            "#2563eb",
            false,
            !large_graph_mode,
            false,
            edge_type_counts,
        ),
    ]
}

fn html_edge_filter(
    id: &'static str,
    label: &'static str,
    color: &'static str,
    dashed: bool,
    enabled_by_default: bool,
    viewport_culled: bool,
    edge_type_counts: &HashMap<&'static str, usize>,
) -> HtmlEdgeFilter {
    HtmlEdgeFilter {
        id: id.to_string(),
        label: label.to_string(),
        count: *edge_type_counts.get(id).unwrap_or(&0),
        enabled_by_default,
        viewport_culled,
        color: color.to_string(),
        dashed,
    }
}

fn push_detail(fields: &mut Vec<HtmlDetailField>, label: &str, value: Option<String>) {
    let Some(value) = value else {
        return;
    };
    let compact = value.trim();
    if compact.is_empty() {
        return;
    }

    fields.push(HtmlDetailField {
        label: label.to_string(),
        value: compact.to_string(),
    });
}

fn semantic_node_color(is_merged: bool) -> HtmlNodeColor {
    if is_merged {
        HtmlNodeColor {
            background: "#fef3c7".to_string(),
            border: "#b45309".to_string(),
        }
    } else {
        HtmlNodeColor {
            background: "#fff4cc".to_string(),
            border: "#a67c00".to_string(),
        }
    }
}

fn finding_node_color(severity: audit_finding::FindingSeverity, is_merged: bool) -> HtmlNodeColor {
    match (severity, is_merged) {
        (audit_finding::FindingSeverity::High, false) => HtmlNodeColor {
            background: "#fee2e2".to_string(),
            border: "#dc2626".to_string(),
        },
        (audit_finding::FindingSeverity::High, true) => HtmlNodeColor {
            background: "#fecaca".to_string(),
            border: "#b91c1c".to_string(),
        },
        (audit_finding::FindingSeverity::Medium, false) => HtmlNodeColor {
            background: "#fef3c7".to_string(),
            border: "#d97706".to_string(),
        },
        (audit_finding::FindingSeverity::Medium, true) => HtmlNodeColor {
            background: "#fde68a".to_string(),
            border: "#b45309".to_string(),
        },
        (audit_finding::FindingSeverity::Low, false) => HtmlNodeColor {
            background: "#f5f5f4".to_string(),
            border: "#57534e".to_string(),
        },
        (audit_finding::FindingSeverity::Low, true) => HtmlNodeColor {
            background: "#e7e5e4".to_string(),
            border: "#44403c".to_string(),
        },
    }
}

fn truncate_text(value: &str, max_chars: usize) -> String {
    let compact = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars = compact.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{}…", truncated.trim_end())
    } else {
        compact
    }
}

fn wrap_label(value: &str, line_width: usize) -> String {
    let mut lines = Vec::new();
    let mut current = String::new();

    for word in value.split_whitespace() {
        let next_len = if current.is_empty() {
            word.len()
        } else {
            current.len() + 1 + word.len()
        };

        if next_len > line_width && !current.is_empty() {
            lines.push(current);
            current = word.to_string();
        } else {
            if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(word);
        }
    }

    if !current.is_empty() {
        lines.push(current);
    }

    if lines.is_empty() {
        value.to_string()
    } else {
        lines.join("\n")
    }
}

fn json_for_js<T: Serialize>(value: &T) -> Result<String> {
    Ok(serde_json::to_string(value)?)
}

fn escape_dot(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn dot_identifier(s: &str) -> String {
    let mut out = String::new();
    let mut last_was_sep = false;

    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_was_sep = false;
        } else if !last_was_sep {
            out.push('_');
            last_was_sep = true;
        }
    }

    let trimmed = out.trim_matches('_');
    if trimmed.is_empty() {
        "cluster".to_string()
    } else {
        trimmed.to_string()
    }
}

fn finding_fill_color(severity: audit_finding::FindingSeverity) -> &'static str {
    match severity {
        audit_finding::FindingSeverity::High => "lightcoral",
        audit_finding::FindingSeverity::Medium => "khaki",
        audit_finding::FindingSeverity::Low => "ghostwhite",
    }
}
