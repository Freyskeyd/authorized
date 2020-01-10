use crate::Scope;
use crate::UnAuthorizedFields;

#[derive(PartialEq, Debug)]
pub struct AuthorizedResult<T> {
    pub input_scope: Scope,
    pub inner: T,
    pub status: AuthorizationStatus,
    pub unauthorized_fields: UnAuthorizedFields,
}

#[derive(PartialEq, Debug)]
pub enum AuthorizationStatus {
    Authorized,
    UnAuthorized,
}
