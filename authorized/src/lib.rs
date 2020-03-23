
//! Authorized is a library helping you authorize behaviour on struct by defining allowed or denied
//! scopes.
//!
//! You can use this to only expose field's value to authorized scopes

#![warn(
    clippy::all,
    // clippy::restriction,
    clippy::pedantic,
    // clippy::nursery,
    // clippy::cargo
)]
#![recursion_limit = "256"]


pub mod scope;

mod error;
mod result;
#[cfg(feature = "with_serde")]
mod serde;

pub mod prelude;

use scope::IntoScope;
use scope::Scope;

use error::*;
use result::*;

pub type UnAuthorizedFields = Vec<String>;

pub trait Authorizable {
    type Authorized;

    fn builder_authorized_struct<S: std::cmp::PartialEq + AsRef<str>>(input: &Self, unauthorized_fields: &[S]) -> Result<Self::Authorized, AuthorizedError>;
    fn filter_unauthorized_fields(input: &Self, scope: &Scope) -> UnAuthorizedFields;
    fn authorize(
        input: &Self,
        authorizer: &Scope,
    ) -> Result<AuthorizedResult<Self::Authorized>, AuthorizedError>;
}


/// Authorizor exposed mthods to help you authorize structures which implement
/// [Authorizable](trait.Authorizable.html) trait.
pub struct Authorizor {}

impl Authorizor {
    /// Create an authorized version of the input structure validated by the scope implementing
    /// [`IntoScope`](scope/trait.IntoScope.html).
    ///
    /// It returns an [`AuthorizedResult`](struct.AuthorizedResult.html) which allow you to know
    /// which fields have been secured and if the whole structure is authorized or not.
    pub fn authorize<A: Authorizable, T: IntoScope>(
        inner: &A,
        scope: T,
    ) -> Result<AuthorizedResult<A::Authorized>, AuthorizedError> {
        let scope: Scope = scope.into_scope()?;

        A::authorize(inner, &scope)
    }
}

impl<T> Authorizable for Vec<T> where T: Authorizable {
    type Authorized = Vec<AuthorizedResult<T::Authorized>>;

    fn builder_authorized_struct<S: std::cmp::PartialEq + AsRef<str>>(_input: &Self, _unauthorized_fields: &[S]) -> Result<Self::Authorized, AuthorizedError>
    {
        Ok(vec![])
    }

    fn filter_unauthorized_fields(_input: &Self, _scope: &Scope) -> UnAuthorizedFields
    {
        vec![]
    }

    fn authorize(
        input: &Self,
        authorizer: &Scope,
    ) -> Result<AuthorizedResult<Self::Authorized>, AuthorizedError>
    {
        let (inner, _errors): (Vec<Result<AuthorizedResult<_>, AuthorizedError>>, Vec<_>) = input
                              .iter()
                              .map(|v| {
                                  Authorizable::authorize(v, authorizer)
                              })
        .partition(Result::is_ok);

        let inner: Self::Authorized = inner.into_iter().filter_map(Result::ok).collect();
        Ok(AuthorizedResult {
            inner,
            input_scope: authorizer.clone(),
            status: AuthorizationStatus::Authorized,
            unauthorized_fields: vec![]
        })
    }
}

impl<T> Authorizable for &T where T: Authorizable {
    type Authorized = T::Authorized;

    fn builder_authorized_struct<S: std::cmp::PartialEq + AsRef<str>>(_input: &Self, _unauthorized_fields: &[S]) -> Result<Self::Authorized, AuthorizedError>
    {
        unreachable!();
    }

    fn filter_unauthorized_fields(_input: &Self, _scope: &Scope) -> UnAuthorizedFields
    {
        unreachable!();
    }

    fn authorize(
        input: &Self,
        authorizer: &Scope,
    ) -> Result<AuthorizedResult<Self::Authorized>, AuthorizedError>
    {
        let unauthorized_fields: Vec<String> = T::filter_unauthorized_fields(input, authorizer);
        let inner = T::builder_authorized_struct(input, &unauthorized_fields)?;

        Ok(AuthorizedResult {
            inner,
            input_scope: authorizer.clone(),
            status: AuthorizationStatus::Authorized,
            unauthorized_fields
        })
    }
}

pub trait Authorized {}


impl<T> Authorized for AuthorizedResult<T> where T: Authorized {}
impl<T> Authorized for Vec<T> where T: Authorized {}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct MyUser {
        name: String,
        pass: String,
        email: String
    }

    impl Authorized for MyUser {}

    impl Authorizable for MyUser {
        type Authorized = Self;

        fn builder_authorized_struct<S: std::cmp::PartialEq + AsRef<str>>(input: &Self, _unauthorized_fields: &[S]) -> Result<Self::Authorized, AuthorizedError>
        {
            Ok(Self {
                name: input.name.clone(),
                pass: input.pass.clone(),
                email: String::new()
            })
        }

        fn filter_unauthorized_fields(_input: &Self, _scope: &Scope) -> UnAuthorizedFields
        {
            vec!["email".into()]
        }

        fn authorize(
            input: &Self,
            authorizer: &Scope,
        ) -> Result<AuthorizedResult<Self::Authorized>, AuthorizedError>
        {
            let unauthorized_fields = Self::filter_unauthorized_fields(input, authorizer);
            let inner = Self::builder_authorized_struct(input, &unauthorized_fields)?;

            Ok(AuthorizedResult {
                inner,
                input_scope: authorizer.clone(),
                status: AuthorizationStatus::Authorized,
                unauthorized_fields,
            })
        }
    }

    #[cfg(feature = "with_serde")]
    #[test]
    fn it_works() -> Result<(), AuthorizedError>{
        let based_user = MyUser {
            name: "name".into(),
            pass: "pass".into(),
            email: "email".into(),
        };

        let based_user2 = MyUser {
            name: "name2".into(),
            pass: "pass".into(),
            email: "email".into(),
        };

        let res = Authorizor::authorize(&based_user, "read:user")?;

        let users = vec![based_user, based_user2];
        let res = Authorizor::authorize(&users, "read:user")?;

        println!("{:#?}", res);
        Ok(())
    }
}
