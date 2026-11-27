//! Provision and clean up dedicated Twingate Service Accounts and Service Keys.

use std::{net::Ipv4Addr, time::Duration};

use base64::{Engine, engine::general_purpose};
use reqwest::{Client, StatusCode, header::HeaderValue, redirect::Policy};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json, value::RawValue};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

use super::{Credentials, token_header, validate_tenant};

const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const KEY_EXPIRATION_DAYS: u16 = 365;

const RESOURCE_QUERY: &str = r#"
query LanewayResource($id: ID!) {
  resource(id: $id) {
    __typename id isActive
    address { type value }
    protocols { tcp { policy ports { start end } } }
    ... on NetworkResource { routingMode }
  }
}"#;

const CREATE_ACCOUNT: &str = r#"
mutation LanewayServiceAccount($name: String!, $resourceIds: [ID]) {
  serviceAccountCreate(name: $name, resourceIds: $resourceIds) {
    ok error entity { id }
  }
}"#;

const FIND_ACCOUNT: &str = r#"
query LanewayFindServiceAccount($name: String!) {
  serviceAccounts(first: 2, filter: { name: { eq: $name } }) {
    totalCount edges { node { id name } }
  }
}"#;

const CHECK_ACCOUNT: &str = r#"
query LanewayCheckServiceAccount($id: ID!) {
  serviceAccount(id: $id) {
    id resources(first: 2) { totalCount edges { node { id } } }
  }
}"#;

const CREATE_KEY: &str = r#"
mutation LanewayServiceKey($serviceAccountId: ID!, $name: String, $expirationTime: Int!) {
  serviceAccountKeyCreate(serviceAccountId: $serviceAccountId, name: $name, expirationTime: $expirationTime) {
    ok error entity { id status expiresAt serviceAccount { id } } token
  }
}"#;

const REVOKE_KEY: &str = r#"
mutation LanewayRevokeServiceKey($id: ID!) {
  serviceAccountKeyRevoke(id: $id) { ok }
}"#;

const CHECK_KEY_STATUS: &str = r#"
query LanewayCheckServiceKey($id: ID!) {
  serviceAccountKey(id: $id) { id status }
}"#;

const DELETE_ACCOUNT: &str = r#"
mutation LanewayDeleteServiceAccount($id: ID!) {
  serviceAccountDelete(id: $id) { ok }
}"#;

const CHECK_ACCOUNT_EXISTS: &str = r#"
query LanewayCheckServiceAccountExists($id: ID!) {
  serviceAccount(id: $id) { id }
}"#;

/// Safe to present outside the provider boundary. Provider bodies and credentials are omitted.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProviderError {
    #[error("the Twingate network or API token is invalid")]
    InvalidConnection,
    #[error("the Twingate identifier or name is invalid")]
    InvalidInput,
    #[error("Twingate rejected the operation without identifying the cause")]
    Rejected,
    #[error(
        "Twingate denied access. Check the saved API token permissions. Issuing keys requires Read, Write & Provision"
    )]
    Unauthorized,
    #[error(
        "Twingate reported that this network's plan does not include the requested Service Account feature"
    )]
    Entitlement,
    #[error("Twingate reported that this network reached its Service Account or Service Key limit")]
    LimitReached,
    #[error("Twingate rejected the provisioning request parameters")]
    ValidationRejected,
    #[error("Twingate API rate limit reached")]
    RateLimited,
    #[error("Twingate API is unavailable or returned an unexpected response")]
    Unavailable,
    #[error(
        "Twingate could not confirm the create operation. Check the dedicated Service Account before retrying"
    )]
    AmbiguousCreate,
    #[error(
        "the Twingate resource is missing or does not route the requested TCP port to an active single IPv4 address through Twingate"
    )]
    ResourceMismatch,
    #[error(
        "the dedicated Twingate Service Account does not grant access exclusively to the selected resource"
    )]
    AccountScopeMismatch,
    #[error("Twingate returned conflicting accounts for the dedicated Service Account name")]
    AccountNameConflict,
}

impl ProviderError {
    pub fn is_ambiguous_create(self) -> bool {
        self == Self::AmbiguousCreate
    }

    fn during_create(self) -> Self {
        match self {
            Self::Unavailable => Self::AmbiguousCreate,
            _ => self,
        }
    }
}

/// Newly issued credentials. The token can only be read from the create response.
pub struct ServiceKey {
    pub id: String,
    pub json: Zeroizing<String>,
    pub expires_at_unix_seconds: u64,
}

/// Client for a single saved Twingate connection.
pub struct Provider {
    client: Client,
    endpoint: String,
    token: HeaderValue,
}

impl Provider {
    pub fn new(network: &str, token: &str) -> Result<Self, ProviderError> {
        validate_tenant(network).map_err(|_| ProviderError::InvalidConnection)?;
        let token = token_header(token).map_err(|_| ProviderError::InvalidConnection)?;
        let client = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| ProviderError::Unavailable)?;
        Ok(Self {
            client,
            endpoint: format!("https://{network}.twingate.com/api/graphql/"),
            token,
        })
    }

    pub fn from_credentials(credentials: &Credentials) -> Result<Self, ProviderError> {
        Self::new(&credentials.tenant, &credentials.api_token)
    }

    /// Read the current address directly by provider ID and validate the port policy.
    pub async fn resolve_resource(
        &self,
        resource_id: &str,
        port: u16,
    ) -> Result<Ipv4Addr, ProviderError> {
        validate_id(resource_id)?;
        let bytes = self
            .request(RESOURCE_QUERY, json!({ "id": resource_id }))
            .await?;
        decode_resource(&bytes, resource_id, port)
    }

    /// Create a service account with exactly one resource ID in the grant request.
    pub async fn create_service_account(
        &self,
        name: &str,
        resource_id: &str,
    ) -> Result<String, ProviderError> {
        validate_name(name)?;
        validate_id(resource_id)?;
        let bytes = self
            .request(
                CREATE_ACCOUNT,
                json!({ "name": name, "resourceIds": [resource_id] }),
            )
            .await
            .map_err(ProviderError::during_create)?;
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Data {
            service_account_create: Created<Id>,
        }
        let reply: Data = graphql_data(&bytes).map_err(ProviderError::during_create)?;
        created_id(mutation_entity(reply.service_account_create)?.id)
    }

    /// Recover a uniquely named account after an interrupted create. The caller
    /// supplies the collision-resistant name it persisted before issuing the write.
    pub async fn find_service_account(&self, name: &str) -> Result<Option<String>, ProviderError> {
        validate_name(name)?;
        let bytes = self.request(FIND_ACCOUNT, json!({ "name": name })).await?;
        #[derive(Deserialize)]
        struct NamedAccount {
            id: String,
            name: String,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Data {
            service_accounts: Connection<NamedAccount>,
        }
        let accounts = graphql_data::<Data>(&bytes)?.service_accounts;
        match (accounts.total_count, accounts.edges.as_slice()) {
            (0, []) => Ok(None),
            (1, [edge]) if edge.node.name == name => {
                validate_id(&edge.node.id).map_err(|_| ProviderError::Unavailable)?;
                Ok(Some(edge.node.id.clone()))
            }
            _ => Err(ProviderError::AccountNameConflict),
        }
    }

    /// Verify the saved account ID and grant before issuing a key.
    pub async fn verify_service_account(
        &self,
        account_id: &str,
        resource_id: &str,
    ) -> Result<(), ProviderError> {
        validate_id(account_id)?;
        validate_id(resource_id)?;
        let bytes = self
            .request(CHECK_ACCOUNT, json!({ "id": account_id }))
            .await?;

        #[derive(Deserialize)]
        struct Account {
            id: String,
            resources: Connection<Id>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Data {
            service_account: Option<Account>,
        }
        let account = graphql_data::<Data>(&bytes)?
            .service_account
            .ok_or(ProviderError::AccountScopeMismatch)?;
        if account.id == account_id
            && account.resources.total_count == 1
            && matches!(account.resources.edges.as_slice(), [edge] if edge.node.id == resource_id)
        {
            Ok(())
        } else {
            Err(ProviderError::AccountScopeMismatch)
        }
    }

    /// Create a key for the dedicated, verified account. Persist its ID and
    /// secret before revoking any older key.
    pub async fn create_service_key(
        &self,
        account_id: &str,
        name: &str,
    ) -> Result<ServiceKey, ProviderError> {
        validate_id(account_id)?;
        validate_name(name)?;
        let bytes = self
            .request(
                CREATE_KEY,
                json!({
                    "serviceAccountId": account_id,
                    "name": name,
                    "expirationTime": KEY_EXPIRATION_DAYS,
                }),
            )
            .await
            .map_err(ProviderError::during_create)?;
        decode_key(&bytes, account_id)
    }

    /// Revoke a key whose provider ID was recorded for this managed account.
    pub async fn revoke_service_key(&self, key_id: &str) -> Result<(), ProviderError> {
        validate_id(key_id)?;
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Revoked {
            service_account_key_revoke: MutationResult,
        }
        let revoked = async {
            let bytes = self.request(REVOKE_KEY, json!({ "id": key_id })).await?;
            graphql_data::<Revoked>(&bytes)?
                .service_account_key_revoke
                .confirm()
        }
        .await;
        if revoked.is_ok() {
            return revoked;
        }

        // Resolve a lost response or a previously revoked or expired key on retry.
        #[derive(Deserialize)]
        struct Status {
            id: String,
            status: String,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Key {
            #[serde(deserialize_with = "Deserialize::deserialize")]
            service_account_key: Option<Status>,
        }
        let bytes = self
            .request(CHECK_KEY_STATUS, json!({ "id": key_id }))
            .await?;
        match graphql_data::<Key>(&bytes)?.service_account_key {
            None => Ok(()),
            Some(key)
                if key.id == key_id && matches!(key.status.as_str(), "REVOKED" | "EXPIRED") =>
            {
                Ok(())
            }
            Some(_) => revoked,
        }
    }

    /// Delete only an account whose provider ID was recorded for this managed gateway.
    pub async fn delete_service_account(&self, account_id: &str) -> Result<(), ProviderError> {
        validate_id(account_id)?;
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Deleted {
            service_account_delete: MutationResult,
        }
        let deleted = async {
            let bytes = self
                .request(DELETE_ACCOUNT, json!({ "id": account_id }))
                .await?;
            graphql_data::<Deleted>(&bytes)?
                .service_account_delete
                .confirm()
        }
        .await;
        if deleted.is_ok() {
            return deleted;
        }

        // Treat an explicit null as absent. A missing field or failed read is an error.
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Account {
            #[serde(deserialize_with = "Deserialize::deserialize")]
            service_account: Option<Id>,
        }
        let bytes = self
            .request(CHECK_ACCOUNT_EXISTS, json!({ "id": account_id }))
            .await?;
        if graphql_data::<Account>(&bytes)?.service_account.is_none() {
            Ok(())
        } else {
            deleted
        }
    }

    async fn request(
        &self,
        query: &str,
        variables: Value,
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        let mut response = self
            .client
            .post(&self.endpoint)
            .header("x-api-key", self.token.clone())
            .header("content-type", "application/json")
            .body(json!({ "query": query, "variables": variables }).to_string())
            .send()
            .await
            .map_err(|_| ProviderError::Unavailable)?;
        check_response_status(response.status())?;

        let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_RESPONSE_BYTES));
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| ProviderError::Unavailable)?
        {
            if chunk.len() > MAX_RESPONSE_BYTES - bytes.len() {
                return Err(ProviderError::Unavailable);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

fn validate_id(id: &str) -> Result<(), ProviderError> {
    if (1..=1024).contains(&id.len()) && id.bytes().all(|byte| byte.is_ascii_graphic()) {
        Ok(())
    } else {
        Err(ProviderError::InvalidInput)
    }
}

fn validate_name(name: &str) -> Result<(), ProviderError> {
    if (1..=255).contains(&name.len()) && !name.chars().any(char::is_control) {
        Ok(())
    } else {
        Err(ProviderError::InvalidInput)
    }
}

fn check_response_status(status: StatusCode) -> Result<(), ProviderError> {
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(ProviderError::Unauthorized),
        StatusCode::PAYMENT_REQUIRED => Err(ProviderError::Entitlement),
        StatusCode::TOO_MANY_REQUESTS => Err(ProviderError::RateLimited),
        _ if status.is_success() => Ok(()),
        _ => Err(ProviderError::Unavailable),
    }
}

#[derive(Deserialize)]
struct Id {
    id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Connection<T> {
    total_count: usize,
    edges: Vec<Edge<T>>,
}

#[derive(Deserialize)]
struct Edge<T> {
    node: T,
}

#[derive(Deserialize)]
struct MutationResult {
    ok: bool,
}

impl MutationResult {
    fn confirm(self) -> Result<(), ProviderError> {
        self.ok.then_some(()).ok_or(ProviderError::Rejected)
    }
}

#[derive(Deserialize)]
struct Created<T> {
    ok: bool,
    entity: Option<T>,
    #[serde(default, deserialize_with = "deserialize_sensitive_text")]
    error: Option<Zeroizing<String>>,
}

fn mutation_entity<T>(created: Created<T>) -> Result<T, ProviderError> {
    match (created.ok, created.entity) {
        (true, Some(entity)) => Ok(entity),
        (false, None) => Err(provisioning_rejection(
            created.error.as_deref().map(String::as_str),
        )),
        _ => Err(ProviderError::AmbiguousCreate),
    }
}

fn deserialize_sensitive_text<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Zeroizing<String>>, D::Error> {
    Option::<String>::deserialize(deserializer).map(|value| value.map(Zeroizing::new))
}

fn provisioning_rejection(message: Option<&str>) -> ProviderError {
    let message = message.unwrap_or_default().as_bytes();
    let has_phrase = |phrases: &[&str]| {
        phrases.iter().any(|phrase| {
            message
                .windows(phrase.len())
                .any(|part| part.eq_ignore_ascii_case(phrase.as_bytes()))
        })
    };
    // Classify only explicit indications. Preserve generic provider failures as unknown.
    if has_phrase(&[
        "insufficient permissions",
        "permission denied",
        "does not have permission",
        "not authorized",
        "requires read, write & provision",
    ]) {
        ProviderError::Unauthorized
    } else if has_phrase(&[
        "service account limit",
        "service accounts limit",
        "service key limit",
        "maximum number of service accounts",
        "maximum number of service account keys",
        "maximum number of service keys",
    ]) {
        ProviderError::LimitReached
    } else if has_phrase(&[
        "not available on your current plan",
        "not included in your plan",
        "does not include service accounts",
        "service account feature is not enabled",
        "not entitled",
    ]) {
        ProviderError::Entitlement
    } else if has_phrase(&[
        "invalid resource id",
        "invalid service account id",
        "invalid expiration time",
        "invalid expirationtime",
        "invalid service account name",
        "invalid service key name",
    ]) {
        ProviderError::ValidationRejected
    } else {
        ProviderError::Rejected
    }
}

fn graphql_data<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ProviderError> {
    #[derive(Deserialize)]
    struct Reply<T> {
        data: Option<T>,
        errors: Option<Vec<GraphQlError>>,
    }
    #[derive(Deserialize)]
    struct GraphQlError {
        extensions: Option<Extensions>,
    }
    #[derive(Deserialize)]
    struct Extensions {
        code: Option<String>,
    }
    let reply: Reply<T> = serde_json::from_slice(bytes).map_err(|_| ProviderError::Unavailable)?;
    if let Some(errors) = reply.errors.filter(|errors| !errors.is_empty()) {
        // A partial response could reflect a write that executed before a resolver failed.
        if reply.data.is_none() {
            let code = |error: &GraphQlError| match error
                .extensions
                .as_ref()
                .and_then(|ext| ext.code.as_deref())
            {
                Some("UNAUTHENTICATED" | "FORBIDDEN") => ProviderError::Unauthorized,
                Some("GRAPHQL_VALIDATION_FAILED") => ProviderError::ValidationRejected,
                _ => ProviderError::Unavailable,
            };
            let first = code(&errors[0]);
            if errors.iter().all(|error| code(error) == first) {
                return Err(first);
            }
        }
        return Err(ProviderError::Unavailable);
    }
    reply.data.ok_or(ProviderError::Unavailable)
}

fn decode_resource(bytes: &[u8], requested_id: &str, port: u16) -> Result<Ipv4Addr, ProviderError> {
    #[derive(Deserialize)]
    struct Data {
        resource: Option<Resource>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Resource {
        #[serde(rename = "__typename")]
        kind: String,
        id: String,
        is_active: bool,
        address: Address,
        protocols: Protocols,
        routing_mode: Option<String>,
    }
    #[derive(Deserialize)]
    struct Address {
        #[serde(rename = "type")]
        kind: String,
        value: String,
    }
    #[derive(Deserialize)]
    struct Protocols {
        tcp: Tcp,
    }
    #[derive(Deserialize)]
    struct Tcp {
        policy: String,
        ports: Vec<PortRange>,
    }
    #[derive(Deserialize)]
    struct PortRange {
        start: u16,
        end: u16,
    }

    let resource = graphql_data::<Data>(bytes)?
        .resource
        .ok_or(ProviderError::ResourceMismatch)?;
    let tcp = resource.protocols.tcp;
    let allowed = match tcp.policy.as_str() {
        "ALLOW_ALL" => true,
        "RESTRICTED" => tcp
            .ports
            .iter()
            .any(|range| (range.start..=range.end).contains(&port)),
        _ => false,
    };
    if resource.kind != "NetworkResource"
        || resource.id != requested_id
        || !resource.is_active
        || resource.address.kind != "IP"
        || resource.routing_mode.as_deref() != Some("THROUGH_TWINGATE")
        || port == 0
        || !allowed
    {
        return Err(ProviderError::ResourceMismatch);
    }
    let address = resource.address.value.as_str();
    let address = address
        .strip_suffix("/32")
        .unwrap_or(address)
        .parse()
        .map_err(|_| ProviderError::ResourceMismatch)?;
    if valid_destination(address) {
        Ok(address)
    } else {
        Err(ProviderError::ResourceMismatch)
    }
}

fn valid_destination(address: Ipv4Addr) -> bool {
    let [first, second, third, _] = address.octets();
    !(matches!(first, 0 | 127 | 224..=255)
        || address.is_link_local()
        || address.is_documentation()
        // Shared-address space includes Twingate virtual addresses and cloud metadata.
        || first == 100 && (64..=127).contains(&second)
        || first == 198 && matches!(second, 18 | 19)
        || [first, second, third] == [192, 0, 0]
        || [first, second, third] == [192, 88, 99]
        || address == Ipv4Addr::new(168, 63, 129, 16))
}

fn decode_key(bytes: &[u8], account_id: &str) -> Result<ServiceKey, ProviderError> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Data {
        service_account_key_create: KeyResponse,
    }
    #[derive(Deserialize)]
    struct KeyResponse {
        ok: bool,
        entity: Option<Key>,
        #[serde(default, deserialize_with = "deserialize_sensitive_text")]
        token: Option<Zeroizing<String>>,
        #[serde(default, deserialize_with = "deserialize_sensitive_text")]
        error: Option<Zeroizing<String>>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Key {
        id: String,
        status: String,
        expires_at: Option<String>,
        service_account: Id,
    }
    let data = graphql_data::<Data>(bytes).map_err(ProviderError::during_create)?;
    let KeyResponse {
        ok,
        entity,
        token,
        error,
    } = data.service_account_key_create;
    if !ok && token.is_some() {
        return Err(ProviderError::AmbiguousCreate);
    }
    let key = mutation_entity(Created { ok, entity, error })?;
    if key.service_account.id != account_id || key.status != "ACTIVE" {
        return Err(ProviderError::AmbiguousCreate);
    }
    let expiry = key.expires_at.ok_or(ProviderError::AmbiguousCreate)?;
    let expiry =
        OffsetDateTime::parse(&expiry, &Rfc3339).map_err(|_| ProviderError::AmbiguousCreate)?;
    let now = OffsetDateTime::now_utc();
    let maximum_lifetime =
        time::Duration::days(i64::from(KEY_EXPIRATION_DAYS)) + time::Duration::minutes(5);
    if expiry <= now || expiry - now > maximum_lifetime {
        return Err(ProviderError::AmbiguousCreate);
    }
    let token = token.ok_or(ProviderError::AmbiguousCreate)?;
    Ok(ServiceKey {
        id: created_id(key.id)?,
        json: decode_key_token(token)?,
        expires_at_unix_seconds: u64::try_from(expiry.unix_timestamp())
            .map_err(|_| ProviderError::AmbiguousCreate)?,
    })
}

fn created_id(id: String) -> Result<String, ProviderError> {
    validate_id(&id).map_err(|_| ProviderError::AmbiguousCreate)?;
    Ok(id)
}

fn decode_key_token(token: Zeroizing<String>) -> Result<Zeroizing<String>, ProviderError> {
    // The headless client consumes the JSON document. The API documents the
    // token as a string and examples show both raw JSON and base64-wrapped JSON.
    if token.trim_start().starts_with('{') {
        validate_key_json(&token)?;
        return Ok(token);
    }
    let mut decoded = Zeroizing::new(vec![0; token.len()]);
    let written = general_purpose::STANDARD
        .decode_slice(&*token, &mut decoded)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode_slice(&*token, &mut decoded))
        .map_err(|_| ProviderError::AmbiguousCreate)?;
    let json =
        std::str::from_utf8(&decoded[..written]).map_err(|_| ProviderError::AmbiguousCreate)?;
    validate_key_json(json)?;
    Ok(Zeroizing::new(json.to_owned()))
}

fn validate_key_json(json: &str) -> Result<(), ProviderError> {
    // Borrow the raw value so private key fields are never deserialized into ordinary Strings.
    let object =
        serde_json::from_str::<&RawValue>(json).map_err(|_| ProviderError::AmbiguousCreate)?;
    object
        .get()
        .strip_prefix('{')
        .and_then(|object| object.strip_suffix('}'))
        .filter(|fields| !fields.trim().is_empty())
        .map(|_| ())
        .ok_or(ProviderError::AmbiguousCreate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    use http_body_util::{BodyExt, Full};
    use hyper::{Request, Response, body::Incoming, server::conn::http1, service::service_fn};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    fn active_resource(address: &str, policy: &str, ports: Value) -> Value {
        json!({"data": {"resource": {
            "__typename": "NetworkResource",
            "id": "resource-id",
            "isActive": true,
            "routingMode": "THROUGH_TWINGATE",
            "alias": "internal.example",
            "address": {"type": "IP", "value": address},
            "protocols": {"tcp": {"policy": policy, "ports": ports}},
        }}})
    }

    #[test]
    fn resolves_only_active_exact_ipv4_routes_with_an_allowed_tcp_port() {
        let ip = Ipv4Addr::new(192, 168, 57, 24);
        let allowed = active_resource("192.168.57.24/32", "ALLOW_ALL", json!([]));
        assert_eq!(
            decode_resource(allowed.to_string().as_bytes(), "resource-id", 443),
            Ok(ip)
        );

        let restricted = active_resource(
            "192.168.57.24",
            "RESTRICTED",
            json!([{"start": 8000, "end": 8002}]),
        );
        let body = restricted.to_string();
        assert_eq!(
            decode_resource(body.as_bytes(), "resource-id", 8000),
            Ok(ip)
        );
        assert_eq!(
            decode_resource(body.as_bytes(), "resource-id", 8002),
            Ok(ip)
        );
        for (id, port) in [
            ("resource-id", 7999),
            ("resource-id", 8003),
            ("other-id", 8000),
            ("resource-id", 0),
        ] {
            assert_eq!(
                decode_resource(body.as_bytes(), id, port),
                Err(ProviderError::ResourceMismatch)
            );
        }

        for invalid in [
            "192.168.57.24/24",
            "internal.example",
            "::1",
            "0.0.0.0",
            "127.0.0.3",
            "169.254.169.254",
            "100.100.100.200",
            "168.63.129.16",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            let body = active_resource(invalid, "ALLOW_ALL", json!([])).to_string();
            assert_eq!(
                decode_resource(body.as_bytes(), "resource-id", 80),
                Err(ProviderError::ResourceMismatch)
            );
        }

        for (property, value) in [
            ("__typename", json!("WebAppResource")),
            ("isActive", json!(false)),
            ("routingMode", json!("BYPASS_TWINGATE")),
            ("address", json!({"type": "DNS", "value": "192.168.57.24"})),
            (
                "protocols",
                json!({"tcp": {"policy": "RESTRICTED", "ports": []}}),
            ),
            (
                "protocols",
                json!({"tcp": {"policy": "MODIFIED_DEFAULT", "ports": []}}),
            ),
        ] {
            let mut invalid = allowed.clone();
            invalid["data"]["resource"][property] = value;
            assert_eq!(
                decode_resource(invalid.to_string().as_bytes(), "resource-id", 80),
                Err(ProviderError::ResourceMismatch)
            );
        }
    }

    #[test]
    fn treats_partial_creates_and_unusable_issued_tokens_as_ambiguous() {
        for body in [
            r#"{"data":{"serviceAccountKeyCreate":{"ok":true}}}"#,
            r#"{"data":{"serviceAccountKeyCreate":{"ok":false,"token":"secret"}}}"#,
            r#"{"errors":[{"message":"secret","extensions":{"code":"FORBIDDEN"}}],"data":{"serviceAccountKeyCreate":{"ok":false}}}"#,
            r#"{"errors":[{"message":"secret"}]}"#,
            "broken response secret",
        ] {
            let error = decode_key(body.as_bytes(), "account").err().unwrap();
            assert!(error.is_ambiguous_create());
            assert!(!format!("{error:?} {error}").contains("secret"));
        }
        for (body, expected) in [
            (
                r#"{"errors":[{"message":"secret","extensions":{"code":"FORBIDDEN"}}]}"#,
                ProviderError::Unauthorized,
            ),
            (
                r#"{"data":{"serviceAccountKeyCreate":{"ok":false,"error":"secret"}}}"#,
                ProviderError::Rejected,
            ),
            (
                r#"{"data":{"serviceAccountKeyCreate":{"ok":false,"error":"Permission denied: secret"}}}"#,
                ProviderError::Unauthorized,
            ),
            (
                r#"{"data":{"serviceAccountKeyCreate":{"ok":false,"error":"This feature is not available on your current plan: secret"}}}"#,
                ProviderError::Entitlement,
            ),
            (
                r#"{"data":{"serviceAccountKeyCreate":{"ok":false,"error":"Maximum number of service keys reached: secret"}}}"#,
                ProviderError::LimitReached,
            ),
            (
                r#"{"data":{"serviceAccountKeyCreate":{"ok":false,"error":"Invalid expiration time: secret"}}}"#,
                ProviderError::ValidationRejected,
            ),
        ] {
            let error = decode_key(body.as_bytes(), "account").err().unwrap();
            assert_eq!(error, expected);
            assert!(!format!("{error:?} {error}").contains("secret"));
        }
        for token in ["not base64", "aGVsbG8=", "W10=", "{}", "{   }"] {
            assert!(decode_key_token(Zeroizing::new(token.to_owned())).is_err());
        }
    }

    #[test]
    fn accepts_raw_headless_json_and_base64_wrapped_json() {
        let json = r#"{"version":"2","private_key":"fixture"}"#;
        for token in [
            json.to_owned(),
            general_purpose::STANDARD.encode(json),
            general_purpose::STANDARD_NO_PAD.encode(json),
        ] {
            assert_eq!(
                decode_key_token(Zeroizing::new(token)).unwrap().as_str(),
                json
            );
        }
    }

    #[tokio::test]
    async fn provisions_and_verifies_a_dedicated_account_then_confirms_cleanup() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service_fn(provisioning_fixture))
                .await
                .unwrap();
        });

        let provider = Provider {
            client: Client::builder().no_proxy().build().unwrap(),
            endpoint: format!("http://{address}/api/graphql/"),
            token: token_header("test-token").unwrap(),
        };
        let account_id = provider
            .create_service_account("laneway-managed-name", "resource-id")
            .await
            .unwrap();
        assert_eq!(account_id, "account");
        assert_eq!(
            provider
                .find_service_account("laneway-managed-name")
                .await
                .unwrap(),
            Some(account_id.clone())
        );
        provider
            .verify_service_account(&account_id, "resource-id")
            .await
            .unwrap();
        assert_eq!(
            provider
                .verify_service_account(&account_id, "different-resource")
                .await,
            Err(ProviderError::AccountScopeMismatch)
        );
        let key = provider
            .create_service_key(&account_id, "laneway-key")
            .await
            .unwrap();
        assert_eq!(key.id, "key");
        assert_eq!(
            key.json.as_str(),
            r#"{"version":"2","private_key":"fixture"}"#
        );
        assert!(
            key.expires_at_unix_seconds
                > u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).unwrap()
        );
        provider.revoke_service_key(&key.id).await.unwrap();
        provider.delete_service_account(&account_id).await.unwrap();
        drop(provider);
        server.await.unwrap();
    }

    async fn provisioning_fixture(
        request: Request<Incoming>,
    ) -> Result<Response<Full<bytes::Bytes>>, Infallible> {
        assert_eq!(request.uri().path(), "/api/graphql/");
        assert_eq!(request.headers()["x-api-key"], "test-token");
        let body = request.into_body().collect().await.unwrap().to_bytes();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        let variables = &payload["variables"];
        let response = match payload["query"].as_str().unwrap() {
            CREATE_ACCOUNT => {
                assert_eq!(
                    *variables,
                    json!({"name": "laneway-managed-name", "resourceIds": ["resource-id"]})
                );
                json!({"data":{"serviceAccountCreate":{"ok":true,"entity":{"id":"account"}}}})
            }
            FIND_ACCOUNT => {
                assert_eq!(*variables, json!({"name": "laneway-managed-name"}));
                json!({"data":{"serviceAccounts":{
                    "totalCount":1,"edges":[{"node":{"id":"account","name":"laneway-managed-name"}}],
                }}})
            }
            CHECK_ACCOUNT => {
                assert_eq!(*variables, json!({"id": "account"}));
                json!({"data":{"serviceAccount":{
                    "id":"account","resources":{"totalCount":1,"edges":[{"node":{"id":"resource-id"}}]},
                }}})
            }
            CREATE_KEY => {
                assert_eq!(
                    *variables,
                    json!({"serviceAccountId": "account", "name": "laneway-key", "expirationTime": 365})
                );
                let token =
                    general_purpose::STANDARD.encode(r#"{"version":"2","private_key":"fixture"}"#);
                let expires_at = OffsetDateTime::now_utc() + time::Duration::days(30);
                json!({"data":{"serviceAccountKeyCreate":{
                    "ok":true,
                    "entity":{"id":"key","status":"ACTIVE","expiresAt":expires_at.format(&Rfc3339).unwrap(),"serviceAccount":{"id":"account"}},
                    "token": token,
                }}})
            }
            REVOKE_KEY => {
                assert_eq!(*variables, json!({"id": "key"}));
                json!({"data":{"serviceAccountKeyRevoke":{"ok":false}}})
            }
            CHECK_KEY_STATUS => {
                assert_eq!(*variables, json!({"id": "key"}));
                json!({"data":{"serviceAccountKey":{"id":"key","status":"REVOKED"}}})
            }
            DELETE_ACCOUNT => {
                assert_eq!(*variables, json!({"id": "account"}));
                json!({"data":{"serviceAccountDelete":{"ok":false}}})
            }
            CHECK_ACCOUNT_EXISTS => {
                assert_eq!(*variables, json!({"id": "account"}));
                json!({"data":{"serviceAccount":null}})
            }
            _ => panic!("unexpected fixture GraphQL operation"),
        };
        Ok(Response::new(Full::new(bytes::Bytes::from(
            response.to_string(),
        ))))
    }
}
