use std::char;
use std::collections::HashSet;
use std::fmt;
use std::str;

use std::cmp;

/// A scope can be created by a `String`.
///
/// You can use Scope to define rules to validate structures. Validating structure is as simple as
/// comparing two or more scopes.
///
/// A scope can define allowed tokens or denied tokens.
///
/// As an example, imagine you have a `UserResource` which is defined by a `username`, a
/// `password` and an `email`. you may want to apply those rules:
///
/// - `Guest` must only see username
/// - `Regular` user can only see username and email
/// - `Admin` can see everything
///
/// The scope for the email must be: `!guest`
///
/// The scope for the password must be: `admin`
///
/// # Examples
/// ```
/// use authorized::prelude::*;
///
/// struct UserResource {
///     username: String,
///     password: String,
///     email: String
/// }
///
/// let admin_scope = "admin".parse::<Scope>().unwrap();
/// let regular_scope = "regular".parse::<Scope>().unwrap();
/// let guest_scope = "guest".parse::<Scope>().unwrap();
///
/// let username_scope = "".parse::<Scope>().unwrap();
/// let email_scope = "!guest".parse::<Scope>().unwrap();
/// let password_scope = "admin".parse::<Scope>().unwrap();
///
///
/// assert!(username_scope.allow_access(&guest_scope));
/// assert!(!email_scope.allow_access(&guest_scope));
/// assert!(!password_scope.allow_access(&guest_scope));
///
/// assert!(username_scope.allow_access(&regular_scope));
/// assert!(email_scope.allow_access(&regular_scope));
/// assert!(!password_scope.allow_access(&regular_scope));
///
/// assert!(username_scope.allow_access(&admin_scope));
/// assert!(email_scope.allow_access(&admin_scope));
/// assert!(password_scope.allow_access(&admin_scope));
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Scope {
    denied_tokens: HashSet<String>,
    allowed_tokens: HashSet<String>,
}

impl Scope {
    fn invalid_scope_char(ch: char) -> bool {
        match ch {
            '\x21' => false,
            ch if ch >= '\x23' && ch <= '\x5b' => false,
            ch if ch >= '\x5d' && ch <= '\x7e' => false,
            ' ' => false, // Space seperator is a valid char
            _ => true,
        }
    }

    /// Determines if this scope has enough privileges to access some resource requiring the scope
    /// on the right side. This operation is equivalent to comparison via `>=`.
    #[must_use]
    pub fn priviledged_to(&self, rhs: &Self) -> bool {
        rhs <= self
    }

    /// Determines if a resouce protected by this scope should allow access to a token with the
    /// grant on the right side. This operation is equivalent to comparison via `<=`.
    #[must_use]
    pub fn allow_access(&self, rhs: &Self) -> bool {
        self <= rhs
    }
}

/// Expose method to convert the structure into a scope
pub trait IntoScope {
    fn into_scope(&self) -> Result<Scope, ParseScopeErr>;
}

impl<T> IntoScope for T
where
    T: AsRef<str>,
{
    fn into_scope(&self) -> Result<Scope, ParseScopeErr> {
        self.as_ref().parse::<Scope>()
    }
}

impl IntoScope for Scope {
    fn into_scope(&self) -> Result<Scope, ParseScopeErr> {
        Ok(self.clone())
    }
}

#[derive(Debug)]
pub enum ParseScopeErr {
    /// A character was encountered which is not allowed to appear in scope strings.
    ///
    /// Scope-tokens are restricted to the following subset of ascii:
    ///   - The character '!'
    ///   - The character range '\x32' to '\x5b' which includes numbers and upper case letters
    ///   - The character range '\x5d' to '\x7e' which includes lower case letters
    /// Individual scope-tokens are separated by spaces.
    ///
    /// In particular, the characters '\x22' (`"`) and '\x5c' (`\`)  are not allowed.
    InvalidCharacter(char),
}

impl str::FromStr for Scope {
    type Err = ParseScopeErr;

    fn from_str(string: &str) -> Result<Self, ParseScopeErr> {
        if let Some(ch) = string.chars().find(|&ch| Self::invalid_scope_char(ch)) {
            return Err(ParseScopeErr::InvalidCharacter(ch));
        }

        let tokens = string.split(' ').filter(|s| !s.is_empty());

        let denied_tokens: HashSet<String> = tokens
            .clone()
            .filter_map(|s| {
                if s.starts_with('!') {
                    Some(str::to_string(&s[1..]))
                } else {
                    None
                }
            })
            .collect();

        let allowed_tokens: HashSet<String> = tokens
            .clone()
            .filter_map(|s| {
                if s.starts_with('!') {
                    None
                } else {
                    Some(str::to_string(s))
                }
            })
            .collect();

        Ok(Self {
            denied_tokens,
            allowed_tokens,
        })
    }
}

impl fmt::Display for ParseScopeErr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            Self::InvalidCharacter(chr) => {
                write!(fmt, "Encountered invalid character in scope: {}", chr)
            }
        }
    }
}

impl fmt::Debug for Scope {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_tuple("Scope")
            .field(&self.denied_tokens)
            .field(&self.allowed_tokens)
            .finish()
    }
}

impl cmp::PartialOrd for Scope {
    fn partial_cmp(&self, rhs: &Self) -> Option<cmp::Ordering> {
        if !self.denied_tokens.is_empty() || !rhs.denied_tokens.is_empty() {
            let lhs_denied_intersect_count =
                self.denied_tokens.intersection(&rhs.allowed_tokens).count();
            let rhs_denied_intersect_count =
                rhs.denied_tokens.intersection(&self.allowed_tokens).count();

            if lhs_denied_intersect_count > 0 || rhs_denied_intersect_count > 0 {
                return None;
            }
        }

        let intersect_count = self
            .allowed_tokens
            .intersection(&rhs.allowed_tokens)
            .count();

        if intersect_count == self.allowed_tokens.len()
            && intersect_count == rhs.allowed_tokens.len()
        {
            Some(cmp::Ordering::Equal)
        } else if intersect_count == self.allowed_tokens.len() {
            Some(cmp::Ordering::Less)
        } else if intersect_count == rhs.allowed_tokens.len() {
            Some(cmp::Ordering::Greater)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_can_be_parsed() {
        let scope_base = "cap1 cap2".parse::<Scope>().unwrap();
        let scope_less = "cap1".parse::<Scope>().unwrap();
        let scope_uncmp = "cap1 cap3".parse::<Scope>().unwrap();
        let user_scope = "user read:user".parse::<Scope>().unwrap();
        let user_only = "user".parse::<Scope>().unwrap();
        let guest_only = "guest".parse::<Scope>().unwrap();
        let read_user = "read:user".parse::<Scope>().unwrap();
        let not_admin = "!admin".parse::<Scope>().unwrap();

        let admin = "admin".parse::<Scope>().unwrap();
        let admin_read = "admin read:user".parse::<Scope>().unwrap();

        assert_eq!(
            scope_base.partial_cmp(&scope_less),
            Some(cmp::Ordering::Greater)
        );
        assert_eq!(
            scope_less.partial_cmp(&scope_base),
            Some(cmp::Ordering::Less)
        );

        assert_eq!(scope_base.partial_cmp(&scope_uncmp), None);
        assert_eq!(scope_uncmp.partial_cmp(&scope_base), None);

        assert_eq!(
            scope_base.partial_cmp(&scope_base),
            Some(cmp::Ordering::Equal)
        );

        assert!(scope_base.priviledged_to(&scope_less));
        assert!(scope_base.priviledged_to(&scope_base));
        assert!(scope_less.allow_access(&scope_base));
        assert!(scope_base.allow_access(&scope_base));

        assert!(!scope_less.priviledged_to(&scope_base));
        assert!(!scope_base.allow_access(&scope_less));

        assert!(!scope_less.priviledged_to(&scope_uncmp));
        assert!(!scope_base.priviledged_to(&scope_uncmp));
        assert!(!scope_uncmp.allow_access(&scope_less));
        assert!(!scope_uncmp.allow_access(&scope_base));

        assert!(user_only.allow_access(&user_scope));
        assert!(read_user.allow_access(&user_scope));
        assert!(admin.allow_access(&admin));
        assert!(not_admin.allow_access(&user_scope));
        assert!(user_scope.priviledged_to(&not_admin));

        assert!(!not_admin.allow_access(&admin));
        assert!(not_admin.allow_access(&user_only));

        assert!(!not_admin.allow_access(&admin_read));
        assert!(!admin_read.priviledged_to(&not_admin));
    }
}
