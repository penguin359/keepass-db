//extern crate proc_macro;
//#[macro_use]
//extern crate quote;

use proc_macro::TokenStream as TS1;
use proc_macro2::{token_stream::IntoIter, Ident, TokenStream, TokenTree, Delimiter};

use quote::quote;

use change_case::{pascal_case, snake_case};
use syn::Attribute;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

#[derive(Debug)]
struct KdbxField {
    name: Ident,
    r#type: Ident,
    element_name: String,
}

struct KdbxAttributes {
    element_name: Option<String>
}

fn get_value(tokens: &mut IntoIter) -> Option<String> {
    if let (Some(TokenTree::Punct(symbol)), Some(TokenTree::Literal(value))) = (tokens.next(), tokens.next()) {
        if symbol.as_char() == '=' {
            Some(value.to_string().replace('"', ""))
        } else {
            None
        }
    } else {
        None
    }
}

impl KdbxAttributes {
    fn parse(attrs: &[Attribute]) -> Self {
        let mut element_name = None;
        for attr in attrs.iter().filter(|a| a.path.is_ident("kdbx")) {
            let mut attr_token = attr.tokens.clone().into_iter();
            if let Some(TokenTree::Group(value)) = attr_token.next() {
                if value.delimiter() == Delimiter::Parenthesis {
                    let mut attr_token = value.stream().into_iter();
                    while let Some(item) = attr_token.next() {
                        if let TokenTree::Ident(name) = item {
                            match name.to_string().as_str() {
                                "element" => {
                                    element_name = get_value(&mut attr_token);
                                },
                                _ => {},
                            }
                        }
                    }
                }
            }
        }
        KdbxAttributes {
            element_name,
        }
    }
}

#[proc_macro_derive(KdbxParse, attributes(kdbx))]
pub fn derive_deserializer(input: TS1) -> TS1 {
    let ast: syn::DeriveInput = syn::parse(input).expect("bad parsing");
    let outer_type = &ast.ident;
    let attrs = &ast.attrs;
    let data = &ast.data;

    let _ = KdbxAttributes::parse(attrs);

    let impl_block = match *data {
        syn::Data::Struct(ref data_struct) => {
            // todo!("unfinished");
            // eprintln!("Fields: {:?}", &data_struct.fields);
            let v = data_struct.fields.iter().map(|field| {
                eprintln!("Fields inside");
                // todo!("unfinished");
                let field = field.clone();
                let name = field.ident.unwrap();
                let attrs = KdbxAttributes::parse(&field.attrs);
                let big_name = attrs.element_name.clone().unwrap_or_else(|| pascal_case(&name.to_string()));
                match field.ty {
                syn::Type::Path(ref p) => {
                    let r#type = p.path.segments.last().unwrap().ident.clone();
                    // format!("Support Path {} => {}", name, r#type)
                    match r#type {
                        _ => { KdbxField {
                            name,
                            r#type,
                            element_name: big_name,
                        }},
                    }
                }
                _ => {
                    unimplemented!("Odd type: {:?}", field.ty);
                    // unimplemented!("Odd type");
                },
            }}).collect::<Vec<KdbxField>>();
            eprintln!("Fields done: {:?}.", &v);
            v
        },
        _ => {
            unimplemented!();
        }
    };
    let variables: TokenStream = impl_block.iter().map(|r| {
        let name = &r.name;
        let my_type = &r.r#type;
        quote! { let mut #name: #my_type = #my_type::default(); }
    }).collect();
    let elements: TokenStream = impl_block.iter().map(|r| {
        let name = &r.name;
        let my_type = &r.r#type;
        let my_func = Ident::new(&format!("decode_{}", my_type), outer_type.span());
        // let big_name = pascal_case(&name.to_string());
        let big_name = &r.element_name;
        eprintln!("Matching names: {big_name}");
        let big_name_debug = format!("{big_name}: {{:?}}");
        quote! {
            XmlEvent::StartElement { name, attributes, .. } if name.local_name == #big_name => {
                #name = #my_func(reader, name, attributes)?;
                println!(#big_name_debug, #name);
            }
        }
    }).collect();
    let big_outer_type = pascal_case(&outer_type.to_string());
    let func_name = Ident::new(&format!("decode_{}", snake_case(&outer_type.to_string())), outer_type.span());
    let debug_string = format!("Decode {}...", outer_type.to_string());
    let names = impl_block.iter().map(|r| &r.name);
    quote! {
        fn #func_name<R: Read>(reader: &mut EventReader<R>, name: OwnedName, _attributes: Vec<OwnedAttribute>) -> Result<#outer_type, String> {
            let mut elements = vec![name];
            //elements.push(name);

            #variables
            while elements.len() > 0 {
                let event = reader.next().map_err(|_|"")?;
                println!("Macro debug: {:?}", event);
                println!(#debug_string);
                match event {
                    XmlEvent::StartDocument { .. } => {
                        return Err("Malformed XML document".to_string());
                    },
                    XmlEvent::EndDocument { .. } => {
                        return Err("Malformed XML document".to_string());
                    },
                    #elements
                    XmlEvent::StartElement { name, .. } => {
                        elements.push(name);
                    },
                    XmlEvent::EndElement { name, .. } => {
                        let start_tag = elements.pop().expect("Can't consume a bare end element");
                        if start_tag != name {
                            return Err(format!("Start tag <{}> mismatches end tag </{}>", start_tag, name));
                        }
                    },
                    _ => {
                        // Consume any PI, text, comment, or cdata node
                        //return Ok(());
                    },
                };
            }
            Ok(#outer_type {
                #(#names),*
            })
        }

        fn test() {
            println!("Hello, derive: {:?}", "boom");
        }
    }.into()
}
