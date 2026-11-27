//! Read-only inventory from the connected Twingate tenant.

use super::{Credentials, Failure, graphql, graphql_data};
use serde::{Deserialize, Serialize};
use serde_json::json;

const PAGE_SIZE: usize = 50;
const MAX_PAGE_BYTES: u64 = 256 * 1024;
const RESOURCE_QUERY: &str = r#"
query LanewayResources($first: Int!, $after: String) {
  resources(first: $first, after: $after) {
    totalCount
    pageInfo { hasNextPage endCursor }
    edges {
      node {
        __typename id name alias isActive
        address { value }
        remoteNetwork { name }
        protocols {
          tcp { policy ports { start end } }
          udp { policy ports { start end } }
          allowIcmp
        }
      }
    }
  }
}
"#;

#[derive(Deserialize)]
struct ResourceConnection {
    resources: GraphqlPage,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphqlPage {
    total_count: usize,
    page_info: PageInfo,
    edges: Vec<ResourceEdge>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PageInfo {
    has_next_page: bool,
    end_cursor: Option<String>,
}

#[derive(Deserialize)]
struct ResourceEdge {
    node: Resource,
}

#[derive(Deserialize, Serialize)]
struct Resource {
    id: String,
    name: String,
    alias: Option<String>,
    #[serde(rename(deserialize = "__typename"))]
    kind: String,
    #[serde(rename(deserialize = "isActive"))]
    active: bool,
    address: Address,
    #[serde(rename(deserialize = "remoteNetwork"))]
    remote_network: RemoteNetwork,
    protocols: Protocols,
}

#[derive(Deserialize, Serialize)]
struct Address {
    value: String,
}

#[derive(Deserialize, Serialize)]
struct RemoteNetwork {
    name: String,
}

#[derive(Deserialize, Serialize)]
struct Protocols {
    tcp: Protocol,
    udp: Protocol,
    #[serde(rename(deserialize = "allowIcmp"))]
    allow_icmp: bool,
}

#[derive(Deserialize, Serialize)]
struct Protocol {
    policy: String,
    ports: Vec<PortRange>,
}

#[derive(Deserialize, Serialize)]
struct PortRange {
    start: u16,
    end: u16,
}

/// A bounded page of Twingate resource metadata.
#[derive(Serialize)]
pub struct ResourcePage {
    resources: Vec<Resource>,
    total_count: usize,
    next_cursor: Option<String>,
}

/// Twingate Relay cursors are opaque, bounded strings passed as variables.
pub fn valid_cursor(cursor: &str) -> bool {
    (1..=1024).contains(&cursor.len()) && cursor.bytes().all(|byte| byte.is_ascii_graphic())
}

/// Enumerate Twingate resources using the saved read-only connection.
pub async fn list_resources(
    credentials: &Credentials,
    after: Option<&str>,
) -> Result<ResourcePage, Failure> {
    let response = graphql(
        credentials,
        RESOURCE_QUERY,
        json!({ "first": PAGE_SIZE, "after": after }),
        MAX_PAGE_BYTES,
    )
    .await?;
    decode_page(&response, after)
}

fn decode_page(bytes: &[u8], after: Option<&str>) -> Result<ResourcePage, Failure> {
    let page = graphql_data::<ResourceConnection>(bytes)?.resources;
    if page.edges.len() > PAGE_SIZE {
        return Err(Failure::Unavailable);
    }
    let next_cursor = if page.page_info.has_next_page {
        let cursor = page
            .page_info
            .end_cursor
            .filter(|cursor| valid_cursor(cursor) && Some(cursor.as_str()) != after)
            .ok_or(Failure::Unavailable)?;
        Some(cursor)
    } else {
        None
    };
    Ok(ResourcePage {
        resources: page.edges.into_iter().map(|edge| edge.node).collect(),
        total_count: page.total_count,
        next_cursor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_resource_page_and_keeps_the_cursor_opaque() {
        let data = json!({"data": {"resources": {
            "totalCount": 2, "pageInfo": {"hasNextPage": true, "endCursor": "abc+/="},
            "edges": [{"node": {
                "__typename": "NetworkResource", "id": "opaque-id", "name": "Service", "alias": null,
                "isActive": true, "address": {"value": "service.example"},
                "remoteNetwork": {"name": "Lab"}, "protocols": {
                    "allowIcmp": false,
                    "tcp": {"policy": "RESTRICTED", "ports": [{"start": 443, "end": 443}]},
                    "udp": {"policy": "RESTRICTED", "ports": []}
                }
            }}]
        }}});
        let bytes = serde_json::to_vec(&data).unwrap();
        let page = decode_page(&bytes, None).unwrap();
        assert_eq!(page.next_cursor.as_deref(), Some("abc+/="));
        let value = serde_json::to_value(page).unwrap();
        assert_eq!(value["resources"][0]["remote_network"]["name"], "Lab");
        assert_eq!(
            value["resources"][0]["protocols"]["tcp"]["ports"][0]["start"],
            443
        );
        assert!(matches!(
            decode_page(&bytes, Some("abc+/=")),
            Err(Failure::Unavailable)
        ));
    }

    #[test]
    fn supports_empty_results_and_rejects_broken_pagination() {
        let response = br#"{"data":{"resources":{"totalCount":0,"pageInfo":{"hasNextPage":false,"endCursor":null},"edges":[]}}}"#;
        let page = decode_page(response, None).unwrap();
        assert!(page.resources.is_empty() && page.next_cursor.is_none());
        let broken = br#"{"data":{"resources":{"totalCount":1,"pageInfo":{"hasNextPage":true,"endCursor":null},"edges":[]}}}"#;
        assert!(matches!(
            decode_page(broken, None),
            Err(Failure::Unavailable)
        ));
    }
}
