//! Integration test: the spaces' CRDs are accepted by a real apiserver
//! (a CEL rule that doesn't compile fails the start), and each rule of
//! RFC 0007 §4.3 refuses what it must, with its message.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test helpers fail the test on purpose"
)]

use std::time::Duration;

use api::{
    OpenbaoAccessGrant, OpenbaoAccessLevel, OpenbaoNamespace, OpenbaoOrganization,
    OpenbaoSpaceLayout,
};
use kube::api::{Api, ApiResource, DynamicObject, Patch, PatchParams, PostParams};
use kube::{Client, Resource};
use serde_json::{Value, json};

const TIMEOUT: Duration = Duration::from_secs(20);

fn api<K: Resource<DynamicType = ()>>(client: &Client) -> (Api<DynamicObject>, ApiResource) {
    let kind = ApiResource::erase::<K>(&());
    (Api::all_with(client.clone(), &kind), kind)
}

fn object(kind: &ApiResource, name: &str, spec: Value) -> DynamicObject {
    serde_json::from_value(json!({
        "apiVersion": kind.api_version, "kind": kind.kind,
        "metadata": {"name": name}, "spec": spec,
    }))
    .unwrap()
}

/// Creates the object, retrying while the CRD's schema reaches the
/// handlers; the apiserver's refusal message when it is refused.
async fn create(api: &Api<DynamicObject>, obj: &DynamicObject) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    loop {
        match api.create(&PostParams::default(), obj).await {
            Ok(_) => return Ok(()),
            Err(kube::Error::Api(e)) if e.code == 422 => return Err(e.message),
            Err(e) if tokio::time::Instant::now() > deadline => panic!("creating: {e:?}"),
            Err(_) => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }
}

async fn refused(api: &Api<DynamicObject>, obj: &DynamicObject, message: &str) {
    let err = create(api, obj)
        .await
        .err()
        .unwrap_or_else(|| panic!("{} accepted", obj.metadata.name.as_deref().unwrap_or("?")));
    assert!(err.contains(message), "{message:?} not in {err:?}");
}

fn oidc(redirect: &str) -> Value {
    json!({
        "discoveryUrl": "https://auth.example/application/o/openbao/",
        "clientId": "openbao",
        "clientSecretRef": {"name": "openbao-oidc", "key": "client-secret"},
        "redirectUris": [redirect],
    })
}

#[tokio::test]
async fn the_spaces_crds_refuse_what_rfc_0007_refuses() {
    let cluster = testkit::envtest::start().await;
    let client: Client = cluster.client();

    // OpenbaoNamespace: the root stays the infra's, one method per backend,
    // redirect URIs in https (or localhost).
    let (namespaces, kind) = api::<OpenbaoNamespace>(&client);
    let ns = |name: &str, auth: Value| {
        object(
            &kind,
            name,
            json!({"instanceRef": {"name": "main"}, "types": ["orgs"], "auth": auth}),
        )
    };
    create(
        &namespaces,
        &ns(
            "prod",
            json!([{"name": "authentik", "oidc": oidc("http://localhost:8250/oidc/callback")}]),
        ),
    )
    .await
    .unwrap();
    refused(&namespaces, &ns("infra", json!([])), "").await;
    refused(
        &namespaces,
        &ns(
            "devenv",
            json!([{"name": "both", "oidc": oidc("https://a/cb"), "kubernetes": {}}]),
        ),
        "exactly one method",
    )
    .await;
    refused(
        &namespaces,
        &ns(
            "recette",
            json!([{"name": "authentik", "oidc": oidc("http://evil.example/cb")}]),
        ),
        "redirectUris",
    )
    .await;

    // OpenbaoAccessLevel: a level grants something.
    let (levels, kind) = api::<OpenbaoAccessLevel>(&client);
    create(
        &levels,
        &object(
            &kind,
            "read",
            json!({"data": ["read"], "metadata": ["read", "list"]}),
        ),
    )
    .await
    .unwrap();
    refused(
        &levels,
        &object(&kind, "nothing", json!({})),
        "at least one capability",
    )
    .await;

    // OpenbaoSpaceLayout: roles without `_`, a template naming both tokens.
    let (layouts, kind) = api::<OpenbaoSpaceLayout>(&client);
    let layout = |template: &str, role: &str| {
        object(
            &kind,
            "weebo",
            json!({
                "instanceRef": {"name": "main"},
                "groupAliasTemplate": template,
                "roles": {role: {"prod": "read"}},
            }),
        )
    };
    refused(
        &layouts,
        &layout("{org}_{role}", "dev_x"),
        "lowercase letters",
    )
    .await;
    refused(
        &layouts,
        &layout("{org}-only", "dev"),
        "both {org} and {role}",
    )
    .await;
    create(&layouts, &layout("{org}_{role}", "dev"))
        .await
        .unwrap();

    // OpenbaoOrganization: its name can't change.
    let (orgs, kind) = api::<OpenbaoOrganization>(&client);
    create(
        &orgs,
        &object(
            &kind,
            "acme",
            json!({"layoutRef": {"name": "weebo"}, "name": "acme"}),
        ),
    )
    .await
    .unwrap();
    let renamed = orgs
        .patch(
            "acme",
            &PatchParams::default(),
            &Patch::Merge(json!({"spec": {"name": "acme2"}})),
        )
        .await
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(renamed.contains("immutable"), "{renamed}");

    // OpenbaoAccessGrant: a broad subject is bounded by {sa.namespace},
    // {org} lists its organizations, no HCL can be smuggled in a path.
    let (grants, kind) = api::<OpenbaoAccessGrant>(&client);
    let grant = |name: &str, subject: Value, rule: Value| {
        object(
            &kind,
            name,
            json!({
                "instanceRef": {"name": "main"}, "namespace": "devenv", "auth": "kubernetes",
                "subjects": [subject], "rules": [rule],
            }),
        )
    };
    let broad = json!({"namespace": "*", "name": "*"});
    create(
        &grants,
        &grant(
            "own",
            broad.clone(),
            json!({"mount": "orgs", "path": "acme/{sa.namespace}/*", "level": "read"}),
        ),
    )
    .await
    .unwrap();
    refused(
        &grants,
        &grant(
            "wide",
            broad,
            json!({"mount": "orgs", "path": "acme/*", "level": "read"}),
        ),
        "broad subject",
    )
    .await;
    refused(
        &grants,
        &grant(
            "org",
            json!({"namespace": "ci", "name": "runner"}),
            json!({"mount": "orgs", "path": "{org}/ci", "level": "read"}),
        ),
        "lists its organizations",
    )
    .await;
    refused(
        &grants,
        &grant(
            "inject",
            json!({"namespace": "ci", "name": "runner"}),
            json!({"mount": "orgs", "path": "x\" { capabilities = [\"sudo\"] } path \"*", "level": "read"}),
        ),
        "path",
    )
    .await;
    refused(
        &grants,
        &grant(
            "selector",
            json!({"namespaceSelector": {}, "name": "*"}),
            json!({"mount": "orgs", "path": "acme/{sa.namespace}/*", "level": "read"}),
        ),
        "namespaceSelector",
    )
    .await;
}
