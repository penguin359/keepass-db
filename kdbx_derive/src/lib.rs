//extern crate proc_macro;
//#[macro_use]
//extern crate quote;

use proc_macro::TokenStream as TS1;
use proc_macro2::{token_stream::IntoIter, Ident, Span, TokenStream, TokenTree, Delimiter};

use quote::quote;

use change_case::{pascal_case, snake_case};
use syn::{Attribute, Type};

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
    full_type: Type,
    array: bool,
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
            let v = data_struct.fields.iter().map(|field| {
                let field = field.clone();
                let name = field.ident.unwrap();
                let attrs = KdbxAttributes::parse(&field.attrs);
                let big_name = attrs.element_name.clone().unwrap_or_else(|| pascal_case(&name.to_string()));
                match field.ty {
                syn::Type::Path(ref p) => {
                    let r#type = p.path.segments.last().unwrap().ident.clone();
                    match r#type.to_string().as_str() {
                        "Vec" => {
                            if let syn::PathArguments::AngleBracketed(ref args) = p.path.segments.last().unwrap().arguments {
                                if let Some(syn::GenericArgument::Type(Type::Path(ref path))) = args.args.first() {
                                    KdbxField {
                                        name,
                                        r#type: path.path.segments.last().unwrap().ident.clone(),
                                        element_name: big_name,
                                        full_type: field.ty.clone(),
                                        array: true,
                                    }
                                } else {
                                    unimplemented!()
                                }
                            } else {
                                unimplemented!()
                            }
                        },
                        _ => { KdbxField {
                            name,
                            r#type,
                            element_name: big_name,
                            full_type: field.ty.clone(),
                            array: false,
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
        let mangled_name = Ident::new(&format!("field_{}", name), Span::call_site());
        let my_type = &r.r#type;
        let full_type = &r.full_type;
        quote! { let mut #mangled_name = <#full_type as ::std::default::Default>::default(); }
    }).collect();
    let elements: TokenStream = impl_block.iter().map(|r| {
        let name = &r.name;
        let mangled_name = Ident::new(&format!("field_{}", name), Span::call_site());
        let my_type = &r.r#type;
        // let big_name = pascal_case(&name.to_string());
        let big_name = &r.element_name;
        eprintln!("Matching names: {big_name}");
        let big_name_debug = format!("{big_name}: {{:?}}");
        if r.array {
            quote! {
                XmlEvent::StartElement { name, attributes, .. } if name.local_name == #big_name => {
                    #mangled_name.push(#my_type::parse(reader, name, attributes)?);
                    println!(#big_name_debug, #mangled_name);
                }
            }
        } else {
            quote! {
                XmlEvent::StartElement { name, attributes, .. } if name.local_name == #big_name => {
                    #mangled_name = #my_type::parse(reader, name, attributes)?;
                    println!(#big_name_debug, #mangled_name);
                }
            }
        }
    }).collect();
    let big_outer_type = pascal_case(&outer_type.to_string());
    let func_name = Ident::new(&format!("decode_{}", snake_case(&outer_type.to_string())), outer_type.span());
    let debug_string = format!("Decode {}...", outer_type.to_string());
    let names = impl_block.iter().map(|r| {
        let name = &r.name;
        let mangled_name = Ident::new(&format!("field_{}", name), Span::call_site());
        quote! { #name: #mangled_name }
    });
    let results = quote! {
        impl KdbxParse for #outer_type {
            fn parse<R: Read>(reader: &mut EventReader<R>, name: OwnedName, _attributes: Vec<OwnedAttribute>) -> Result<#outer_type, String> {
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
        }
    };
    eprintln!("Macros: {}", results);
    results.into()
}

#[proc_macro_derive(KdbxSerialize, attributes(kdbx))]
pub fn derive_serializer(input: TS1) -> TS1 {
    let ast: syn::DeriveInput = syn::parse(input).expect("bad parsing");
    let outer_type = &ast.ident;
    let attrs = &ast.attrs;
    let data = &ast.data;

    let _ = KdbxAttributes::parse(attrs);

    let impl_block = match *data {
        syn::Data::Struct(ref data_struct) => {
            let v = data_struct.fields.iter().map(|field| {
                let field = field.clone();
                let name = field.ident.unwrap();
                let attrs = KdbxAttributes::parse(&field.attrs);
                let big_name = attrs.element_name.clone().unwrap_or_else(|| pascal_case(&name.to_string()));
                match field.ty {
                syn::Type::Path(ref p) => {
                    let r#type = p.path.segments.last().unwrap().ident.clone();
                    match r#type {
                        _ => { KdbxField {
                            name,
                            r#type,
                            element_name: big_name,
                            full_type: field.ty.clone(),
                            array: false,
                        }},
                    }
                }
                _ => {
                    unimplemented!("Odd type: {:?}", field.ty);
                },
            }}).collect::<Vec<KdbxField>>();
            v
        },
        _ => {
            unimplemented!();
        }
    };
    let elements: TokenStream = impl_block.iter().map(|r| {
        let name = &r.name;
        let my_type = &r.r#type;
        let my_func = Ident::new(&format!("encode_{}", my_type), outer_type.span());
        // let big_name = pascal_case(&name.to_string());
        let big_name = &r.element_name;
        eprintln!("Matching names: {big_name}");
        let big_name_debug = format!("{big_name}: {{:?}}");
        quote! {
            writer.write(xml::writer::XmlEvent::start_element(#big_name)).map_err(|_|"")?;
            #my_func(writer, value.#name)?;
            writer.write(xml::writer::XmlEvent::end_element()).map_err(|_|"")?;
        }
    }).collect();
    let big_outer_type = pascal_case(&outer_type.to_string());
    let func_name = Ident::new(&format!("encode_{}", snake_case(&outer_type.to_string())), outer_type.span());
    let debug_string = format!("Encode {}...", outer_type.to_string());
    let names = impl_block.iter().map(|r| &r.name);
    quote! {
        fn #func_name<W: Write>(writer: &mut EventWriter<W>, value: #outer_type) -> Result<(), String> {
            println!(#debug_string);
            #elements
            Ok(())
        }
    }.into()
}
