use crate::scope::ParseScopeErr;

#[derive(Debug)]
pub enum AuthorizedError {
    MultipleAuthorizedErrors(Vec<AuthorizedError>),
    ParseScopeError(ParseScopeErr),
}

impl From<ParseScopeErr> for AuthorizedError {
    fn from(error: ParseScopeErr) -> Self {
        Self::ParseScopeError(error)
    }
}
