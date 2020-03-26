use crate::Authorized;
use crate::AuthorizedResult;

#[cfg(feature = "with_serde")]
impl<T: ::serde::ser::Serialize + Authorized> ::serde::ser::Serialize for AuthorizedResult<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ::serde::ser::Serializer,
    {
        self.inner.serialize(serializer)
    }
}
