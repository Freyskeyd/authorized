extern crate authorized;

use authorized::prelude::*;

#[derive(Debug, Authorized)]
#[authorized(scope = "")]
struct SimpleStruct {
    #[authorized(scope = "reader", default = "String::from("Simple")")]
    name: String
}

fn main() {

}
