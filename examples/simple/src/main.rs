extern crate authorized;

use authorized::prelude::*;

#[derive(Debug, Authorized)]
struct SimpleStruct {
    #[authorized(scope = "reader", default = "default_name")]
    name: String,
}

fn default_name() -> String {
    "Simple".into()
}

fn main() -> Result<(), AuthorizedError> {
    let simple = SimpleStruct {
        name: "A simple struct".into(),
    };

    println!("The Struct: {:?}", simple);

    let result = Authorizor::authorize(&simple, &"reader")?;

    assert_eq!(result.status, AuthorizationStatus::Authorized);

    println!("=> authorized with reader scope: {:?}", result);

    let result = Authorizor::authorize(&simple, &"failling")?;

    assert_eq!(result.status, AuthorizationStatus::Authorized);
    assert_eq!(result.inner.name, "Simple");

    println!("=> authorized without reader scope: {:?}", result);

    Ok(())
}
