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

#[derive(Debug)]
struct KdbxField {
    name: String,
    r#type: String,
}

#[proc_macro_derive(KdbxParse, attributes(kdbx))]
pub fn derive_deserializer(input: TS1) -> TS1 {
    let ast: syn::DeriveInput = syn::parse(input).expect("bad parsing");
    let name = &ast.ident;
    let attrs = &ast.attrs;
    let data = &ast.data;

    let _impl_block = match *data {
        syn::Data::Struct(ref data_struct) => {
            // todo!("unfinished");
            // eprintln!("Fields: {:?}", &data_struct.fields);
            let v = data_struct.fields.iter().map(|field| {
                eprintln!("Fields inside");
                // todo!("unfinished");
                let field = field.clone();
                let name = field.ident.unwrap().to_string();
                match field.ty {
                syn::Type::Path(ref p) => {
                    let r#type = p.path.segments.last().unwrap().ident.to_string();//.as_str();
                    // format!("Support Path {} => {}", name, r#type)
                    match r#type {
                        _ => { KdbxField {
                            name,
                            r#type,
                        }},
                    }
                }
                _ => {
                    //unimplemented!("Odd type: {:?}", field.ty);
                    unimplemented!("Odd type");
                },
            }}).collect::<Vec<KdbxField>>();
            eprintln!("Fields done: {:?}.", &v);
            v
        },
        _ => {
            unimplemented!();
        }
    };
    //TS1::new()
    quote! {
        fn test() {
            println!("Hello, derive: {:?}", "boom");
        }
    }.into()
}
