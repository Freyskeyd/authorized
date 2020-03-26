use authorized::prelude::*;
// use serde::{Serialize};

// #[derive(Debug, Serialize, Authorized)]
#[derive(Debug, Authorized)]
#[authorized(scope = "admin")]
struct MyResource {
    id: i32,
    #[authorized(scope = "read:title")]
    // #[serde(skip_serializing_if = "String::is_empty")]
    title: String,
    // #[serde(rename = "truc")]
    description: Option<String>,
}

impl Authorized for MyResource {}

fn main() {
    let resource = MyResource {
        id: 1,
        title: "Some title".into(),
        description: Some("description".into()),
    };

    let resource2 = MyResource {
        id: 2,
        title: "Some title2".into(),
        description: Some("description".into()),
    };

    let resources = vec![&resource, &resource2];
    let json = Authorizor::authorize(&resources, &"admin").unwrap();
    // let json = serde_json::to_string(&authorized).unwrap();
    println!("{:#?}", json);
}
