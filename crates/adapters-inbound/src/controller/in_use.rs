//! Who cites an `OpenbaoInstance` or an `OpenbaoAccessLevel` (decision 21):
//! their deletion waits until nobody does, so the finalizers of what cites
//! them can still log in and render.

use api::{OpenbaoAccessGrant, OpenbaoNamespace, OpenbaoSpaceLayout};
use kube::api::{Api, ListParams};
use kube::{Client, ResourceExt};

/// `Kind/name` of every CR naming `instance` as its instance.
pub async fn instance_citers(client: &Client, instance: &str) -> Result<Vec<String>, kube::Error> {
    let lp = ListParams::default();
    let mut citers = Vec::new();
    let namespaces: Api<OpenbaoNamespace> = Api::all(client.clone());
    for n in namespaces.list(&lp).await?.items {
        if n.spec.instance_ref.name == instance {
            citers.push(format!("OpenbaoNamespace/{}", n.name_any()));
        }
    }
    let layouts: Api<OpenbaoSpaceLayout> = Api::all(client.clone());
    for l in layouts.list(&lp).await?.items {
        if l.spec.instance_ref.name == instance {
            citers.push(format!("OpenbaoSpaceLayout/{}", l.name_any()));
        }
    }
    let grants: Api<OpenbaoAccessGrant> = Api::all(client.clone());
    for g in grants.list(&lp).await?.items {
        if g.spec.instance_ref.name == instance {
            citers.push(format!("OpenbaoAccessGrant/{}", g.name_any()));
        }
    }
    Ok(citers)
}

/// `Kind/name` of every layout cell's layout and grant citing `level`.
pub async fn level_citers(client: &Client, level: &str) -> Result<Vec<String>, kube::Error> {
    let lp = ListParams::default();
    let mut citers = Vec::new();
    let layouts: Api<OpenbaoSpaceLayout> = Api::all(client.clone());
    for l in layouts.list(&lp).await?.items {
        if l.spec
            .roles
            .values()
            .any(|cells| cells.values().any(|v| v == level))
        {
            citers.push(format!("OpenbaoSpaceLayout/{}", l.name_any()));
        }
    }
    let grants: Api<OpenbaoAccessGrant> = Api::all(client.clone());
    for g in grants.list(&lp).await?.items {
        if g.spec.rules.iter().any(|r| r.level == level) {
            citers.push(format!("OpenbaoAccessGrant/{}", g.name_any()));
        }
    }
    Ok(citers)
}
