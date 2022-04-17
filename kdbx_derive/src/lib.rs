//extern crate proc_macro;
//#[macro_use]
//extern crate quote;

use proc_macro::TokenStream as TS1;
// use proc_macro2::TokenStream;

use quote::quote;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

#[proc_macro_derive(KdbxParse, attributes(kdbx))]
pub fn derive_deserializer(input: TS1) -> TS1 {
    //TS1::new()
    quote! {
        fn test() {
            println!("Hello, derive");
        }
    }.into()
}
