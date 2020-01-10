# Authorized

Authorized allows you to prevent leaking informations on your structs based on scopes.
Imagine a system which have users, some are admins, others are regular users. You don't want regular users to see
everyones email so you need to filter every users structs to remove or clean every email based on the current user. Authorized allow you to easly define scope on each fields of the user struct preventing data leak.

Scope are composed of keywords defining behaviour for your application. These scopes are used to filter and authorized
struct instance.

See more in usage part.

Other things to include:

  - **Status**:  Alpha. See [CHANGELOG](CHANGELOG.md) for more informations.
  - **Documentation**:  See [docs.rs](CHANGELOG.md).

## Dependencies

This crate have no dependencies for the `default` feature.
But a `serde` feature is available to have a nice compatibility with `serde` allowing you to serialize structs with every authorized rules defined.

## Installation

Simply add the authorized crate to your dependencies.

```toml
[dependencies]
authorized = "0.1"
```

You can also define the `serde` feature if you want to have the `serde` integration.

```toml
[dependencies]
authorized = { version = "0.1", features = ["with_serde"] }
```

## Configuration

Authorized is mostly derive based, you can use it without derive but it can be really verbosed.

Here's how to configure a user struct that filter the email for every non admin scope.

```rust
use authorized::prelude::*;

#[derive(Authorized)]
struct User {
  id: i32,
  username: String,
  #[authorized(scope = "admin")]
  email: String,
}
```

## Usage

Authorized can be use with any sort of application (api, worker, ...). The basic
concept is to define scopes for entities (or fields inside entities) and make an
assessment between an input scope which can be a user one.

As an example we will use an API which exposes users to authenticated API users.
We will not cover the authentication process which is completely out of scope
but we will assume that the authentication provides enough informations to build
a `Scope`.

Our Authentication process can handle three kind of role:

- `Guest` which is an unauthenticated API user without any access
- `AuthenticatedUser` which is a normal user
- `Admin` which is a super user with extended permissions and access


Our API will expose `User` which is composed with an `id`, an `email`, a `name`
and a `password`. We will define rules on the `User` to restrict access to
informations.

Rules are:

- `id` and `name` can be seen by `AuthenticatedUser` and `Admin`
- `email` can be seen by `Admin`
- `Guest` are not authorized to request this structure

```rust
#[derive(Authorized)]
#[authorized(scope = "read:user")]
struct User {
  id: i32,
  name: String,
  #[authorized(scope = "read:user:email")]
  email: String
}
```

As you can see we can define scope for the global structure and for particular
fields.

Next we can authorize this structure against any scope:

```rust
fn main() {
  let user = User {
    id: 1,
    name: "some_name".into(),
    email: "some_email".into()
  };

  let guest = "guest"
  let authorizedUser = "read:user"
  let admin = "read:user read:user:email"

  let authorized_guest: AuthorizedResult<User> = Authorizor::authorize(&user, guest);
  let authorized_user: AuthorizedResult<User> = Authorizor::authorize(&user, authauthorizedUser);
  let authorized_admin: AuthorizedResult<User> = Authorizor::authorize(&user, admin);

  assert(authorized_guest.status == AuthorizationStatus::UnAuthorized);
  assert(authorized_user.status == AuthorizationStatus::Authorized);
  assert(authorized_admin.status == AuthorizationStatus::Authorized);

  assert(authorized_user.inner.email == "");
  assert(authorized_admin.inner.email == "some_email");

  assert(authorized_user.unauthorized_fields == vec!["email"]);
  assert(authorized_admin.unauthorized_fields == vec![]);
}
```

More examples can be found in the examples directory.


## How to test the software

To test the software you just need to run `cargo test` inside each crate.

## Known issues

- Authorized doesn't allow multiple global scope or multiple scope for a field.

## Getting help

If you have questions, concerns, bug reports, etc, please file an issue in this repository's Issue Tracker.

## Getting involved

General instructions on _how_ to contribute should be stated with a link to [CONTRIBUTING](CONTRIBUTING.md).


----

## Open source licensing info
1. [TERMS](TERMS.md)
2. [LICENSE](LICENSE)
3. [CFPB Source Code Policy](https://github.com/cfpb/source-code-policy/)

