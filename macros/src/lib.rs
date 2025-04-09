use proc_macro::TokenStream;
use quote::quote;

#[proc_macro_derive(UuidFromParam)]
pub fn derive_uuid_from_param(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).unwrap();

    impl_derive_uuid_macro(&ast)
}

fn impl_derive_uuid_macro(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let gen_derive = quote! {
        #[automatically_derived]
        impl<'r> rocket::request::FromParam<'r> for #name {
            type Error = ();

            #[inline(always)]
            fn from_param(param: &'r str) -> Result<Self, Self::Error> {
                if uuid::Uuid::parse_str(param).is_ok() {
                    Ok(Self(param.to_string()))
                } else {
                    Err(())
                }
            }
        }
    };
    gen_derive.into()
}

#[proc_macro_derive(IdFromParam)]
pub fn derive_id_from_param(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).unwrap();

    impl_derive_safestring_macro(&ast)
}

fn impl_derive_safestring_macro(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let gen_derive = quote! {
        #[automatically_derived]
        impl<'r> rocket::request::FromParam<'r> for #name {
            type Error = ();

            #[inline(always)]
            fn from_param(param: &'r str) -> Result<Self, Self::Error> {
                if param.chars().all(|c| matches!(c, 'a'..='z' | 'A'..='Z' |'0'..='9' | '-')) {
                    Ok(Self(param.to_string()))
                } else {
                    Err(())
                }
            }
        }
    };
    gen_derive.into()
}
