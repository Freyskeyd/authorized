#![warn(
    clippy::all,
    // clippy::restriction,
    // clippy::pedantic,
    clippy::nursery,
    // clippy::cargo
)]
#![recursion_limit = "256"]
extern crate proc_macro;
extern crate syn;
#[macro_use]
extern crate quote;
#[macro_use]
extern crate darling;
use darling::ast;
use darling::FromDeriveInput;
use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::DeriveInput;
#[derive(Debug, FromDeriveInput)]
// This line says that we want to process all attributes declared with `my_trait`,
// and that darling should panic if this receiver is given an enum.
#[darling(attributes(authorized))]
struct AuthorizedOpts {
    /// The struct ident.
    ident: syn::Ident,

    /// The type's generics. You'll need these any time your trait is expected
    /// to work with types that declare generics.
    generics: syn::Generics,

    /// Receives the body of the struct or enum. We don't care about
    /// struct fields because we previously told darling we only accept structs.
    data: ast::Data<(), AuthorizedField>,

    /// The Input Receiver demands a volume, so use `Volume::Normal` if the
    /// caller doesn't provide one.
    // #[darling(default)]
    scope: String,
}

#[derive(Debug, FromField)]
#[darling(attributes(authorized))]
struct AuthorizedField {
    /// Get the ident of the field. For fields in tuple or newtype structs or
    /// enum bodies, this can be `None`.
    ident: Option<syn::Ident>,

    /// This magic field name pulls the type from the input.
    ty: syn::Type,

    attrs: Vec<syn::Attribute>,
    /// We declare this as an `Option` so that during tokenization we can write
    /// `field.volume.unwrap_or(derive_input.volume)` to facilitate field-level
    /// overrides of struct-level settings.
    #[darling(default)]
    scope: Option<String>,

    #[darling(default)]
    default: Option<String>,
}

impl ToTokens for AuthorizedOpts {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let struct_name = &self.ident;

        let fields = self
            .data
            .as_ref()
            .take_struct()
            .expect("Should never be enum")
            .fields;

        let authorizable_trait = generate_authorizable_trait(struct_name, &self.scope, &fields);

        tokens.extend(quote! {
            #authorizable_trait
        })
    }
}

fn generate_authorized_trait(
    _struct_name: &syn::Ident,
    fields: &[&AuthorizedField],
) -> proc_macro2::TokenStream {
    let serialize_fields = fields
        .iter()
        .enumerate()
        .map(|(_i, f)| {
            let ident = if let Some(ref ident) = f.ident {
                ident.clone()
            } else {
                panic!("");
            };

            let unauthorized = match &f.default {
                None => quote! { Default::default() },
                Some(def) => match syn::parse_str::<syn::Path>(def) {
                    Ok(path) => quote! { #path },
                    _ => panic!("Cannot parse default path"),
                },
            };

            let name = format!("{}", ident);
            let var_name = syn::Ident::new(&format!("arg_{}", name), ident.span());

            quote! {
                let #var_name = if !unauthorized_fields.iter().any(|v| v.as_ref() == #name) {
                    input.#ident.clone()
                } else {
                    #unauthorized
                };
            }
        })
        .collect::<Vec<_>>();

    let assign_field = fields
        .iter()
        .enumerate()
        .map(|(_i, f)| {
            let ident = if let Some(ref ident) = f.ident {
                ident.clone()
            } else {
                panic!("");
            };

            let name = format!("{}", ident);
            let var_name = syn::Ident::new(&format!("arg_{}", name), ident.span());

            quote! {
                #ident: #var_name
            }
        })
        .collect::<Vec<_>>();

    quote! {
        fn builder_authorized_struct<S: std::cmp::PartialEq + AsRef<str>>(input: &Self, unauthorized_fields: &[S]) -> Result<Self::Authorized, AuthorizedError>
        {
            let unauthorized_fields = unauthorized_fields.as_ref();
            #(#serialize_fields)*

            Ok(Self::Authorized {
                #(#assign_field,)*
            })
        }
    }
}

fn generate_authorizable_trait(
    struct_name: &syn::Ident,
    global_scope: &str,
    fields: &[&AuthorizedField],
) -> proc_macro2::TokenStream {
    let filtering_fields = fields
        .iter()
        .enumerate()
        .map(|(_i, f)| {
            let ident = if let Some(ref ident) = f.ident {
                ident.clone()
            } else {
                panic!("");
            };

            let name = format!("{}", ident);
            if let Some(ref scope) = f.scope {
                quote! {
                    if !#scope.parse::<authorized::scope::Scope>().unwrap().allow_access(scope) {
                        unauthorized_fields.push(String::from(#name));
                    }
                }
            } else {
                quote! {}
            }
        })
        .collect::<Vec<_>>();

    let serialized_struct = generate_authorized_trait(struct_name, fields);
    quote! {
        impl Authorizable for #struct_name {
            type Authorized = Self;

            #serialized_struct

            fn filter_unauthorized_fields(input: &Self, scope: &authorized::scope::Scope) -> UnAuthorizedFields
            {
                let mut unauthorized_fields = vec![];

                #(
                    #filtering_fields
                )*

                unauthorized_fields
            }

            fn authorize(input: &Self, input_scope: &authorized::scope::Scope) -> Result<AuthorizedResult<Self::Authorized>, AuthorizedError> {
                let global_scopes = vec!(#global_scope.parse::<Scope>()?);
                let unauthorized_fields = Self::filter_unauthorized_fields(input, input_scope);

                let status = if global_scopes.iter().map(|scope| scope.allow_access(&input_scope)).any(|access| access) {
                    AuthorizationStatus::Authorized
                } else {
                    AuthorizationStatus::UnAuthorized
                };
                let inner = Self::builder_authorized_struct(input, &unauthorized_fields)?;
                Ok(AuthorizedResult {
                    input_scope: input_scope.clone(),
                    inner,
                    status,
                    unauthorized_fields
                })
            }
        }

    }
}

#[proc_macro_derive(Authorized, attributes(authorized))]
pub fn derive_authorized(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input: DeriveInput = syn::parse(input).unwrap();
    let res = AuthorizedOpts::from_derive_input(&input).unwrap();

    proc_macro::TokenStream::from(quote!(#res))
}
