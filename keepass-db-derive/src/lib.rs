//#![feature(iterator_try_collect)]

use proc_macro::TokenStream as TS1;
use proc_macro2::{token_stream::IntoIter, Ident, Span, TokenStream, TokenTree};

use quote::{quote, format_ident};

use change_case::pascal_case;
use syn::{Attribute, Error, Type};

#[derive(Debug)]
struct KdbxField {
    name: Ident,
    r#type: Ident,
    element_name: String,
    inner_type: Type,
    full_type: Type,
    array: bool,
    option: bool,
    flatten: bool,
}

struct KdbxAttributes {
    element_name: Option<String>,
    flatten: bool,
}

fn get_value(tokens: &mut IntoIter) -> Option<String> {
    if let (Some(TokenTree::Punct(symbol)), Some(TokenTree::Literal(value))) =
        (tokens.next(), tokens.next())
    {
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
    fn parse(attrs: &[Attribute]) -> Result<Self, Error> {
        let mut element_name = None;
        let mut flatten = false;
        for attr in attrs.iter().filter(|a| a.path().is_ident("keepass_db")).filter_map(|a| match a.meta {
            syn::Meta::List(ref v) => Some(&v.tokens),
            _ => None
        }) {
            //eprintln!("Inner attr tokens: {:#?}", attr);
            let mut attr_token = attr.clone().into_iter();
            while let Some(item) = attr_token.next() {
                if let TokenTree::Ident(name) = item {
                    match name.to_string().as_str() {
                        "element" => {
                            element_name = get_value(&mut attr_token);
                        }
                        "flatten" => {
                            flatten = true;
                        }
                        _ => {
                            return Err(Error::new(name.span(), "Unrecognized attribute"));
                        }
                    }
                }
            }
        }
        Ok(Self {
            element_name,
            flatten,
        })
    }
}

enum TypeCategory<'a> {
    Basic(Ident),
    Option(&'a Type),
    Vec(&'a Type),
    //Array(&'a Type, usize),
    Array(&'a Type),
}

fn get_type(t: &Type) -> TypeCategory {
    match t {
        syn::Type::Path(ref p) => {
            let r#type = p.path.segments.last().unwrap().ident.clone();
            match r#type.to_string().as_str() {
                "Vec" => {
                    if let syn::PathArguments::AngleBracketed(ref args) =
                        p.path.segments.last().unwrap().arguments
                    {
                        if let Some(syn::GenericArgument::Type(inner_type)) = args.args.first() {
                            match inner_type {
                                syn::Type::Path(ref p) if p.path.segments.last().map(|t| t.ident.to_string()) == Some("u8".to_string()) =>
                                    TypeCategory::Basic(p.path.segments.last().unwrap().ident.clone()),
                                _ => TypeCategory::Vec(inner_type),
                            }
                        } else {
                            unimplemented!("Only support type arguments for Vec: {:#?}", args.args.first())
                        }
                    } else {
                        unimplemented!("Only support angle-brackets args for Vec: {:#?}", p.path.segments.last().unwrap().arguments)
                    }
                }
                "Option" => {
                    if let syn::PathArguments::AngleBracketed(ref args) =
                        p.path.segments.last().unwrap().arguments
                    {
                        if let Some(syn::GenericArgument::Type(inner_type)) = args.args.first() {
                            TypeCategory::Option(inner_type)
                        } else {
                            unimplemented!("Only support type arguments for Option: {:#?}", args.args.first())
                        }
                    } else {
                        unimplemented!("Only support angle-brackets args for Option: {:#?}", p.path.segments.last().unwrap().arguments)
                    }
                }
                _ => TypeCategory::Basic(r#type),
            }
        }
        //syn::Type::Array(TypeArray {elem, len, ..}) => {
        //    if let Expr::Lit(ExprLit { lit: Lit::Int(literal), .. }) = len {
        //        TypeCategory::Array(elem, literal.base10_parse().unwrap())
        //    } else {
        //        unimplemented!("Array size must be an integer literal: {:#?}", len)
        //    }
        //}
        //syn::Type::Array(x) => TypeCategory::Array(syn::Type::Array(x))
        syn::Type::Array(_) => TypeCategory::Array(t),
        _ => unimplemented!("Unsupported type: {:?}", t)
    }
}

fn decode_struct(ast: &syn::DeriveInput) -> Result<Vec<KdbxField>, Error> {
    Ok(match ast.data {
        syn::Data::Struct(ref data_struct) => {
            let v = data_struct
                .fields
                .iter()
                .map(|field| {
                    let field = field.clone();
                    let name = field.ident.unwrap();
                    let attrs = KdbxAttributes::parse(&field.attrs)?;
                    let big_name = attrs
                        .element_name
                        .clone()
                        .unwrap_or_else(|| pascal_case(&name.to_string()));
                    let flatten = attrs.flatten;
                    Ok::<_, Error>(match get_type(&field.ty) {
                        TypeCategory::Vec(inner_type) => {
                            let subtype = match get_type(inner_type) {
                                TypeCategory::Basic(t) => t,
                                _ => unimplemented!("Only basic types supported for Vec<_>"),
                            };
                            KdbxField {
                                name,
                                r#type: subtype,
                                element_name: big_name,
                                inner_type: inner_type.clone(),
                                full_type: field.ty.clone(),
                                array: true,
                                option: false,
                                flatten,
                            }
                        }
                        TypeCategory::Option(inner_type) => match get_type(inner_type) {
                            TypeCategory::Basic(t) => KdbxField {
                                name,
                                r#type: t,
                                element_name: big_name,
                                inner_type: inner_type.clone(),
                                full_type: field.ty.clone(),
                                array: false,
                                option: true,
                                flatten,
                            },
                            TypeCategory::Vec(inner_type) => {
                                // TODO recursively call get_type() here
                                if let syn::Type::Path(ref tp) = inner_type {
                                    KdbxField {
                                        name,
                                        r#type: tp.path.segments.last().unwrap().ident.clone(),
                                        element_name: big_name,
                                        inner_type: inner_type.clone(),
                                        full_type: field.ty.clone(),
                                        array: true,
                                        option: true,
                                        flatten,
                                    }
                                } else {
                                    unimplemented!("Only basic inner types supported for Option<Vec<_>>")
                                }
                            }
                            TypeCategory::Array(inner_type) => KdbxField {
                                name,
                                r#type: Ident::new("u8", Span::call_site()),
                                element_name: big_name,
                                inner_type: inner_type.clone(),
                                full_type: field.ty.clone(),
                                array: false,
                                option: true,
                                flatten,
                            },
                            _ => unimplemented!("Only basic and Vec types supported for Option<_>")
                        },
                        TypeCategory::Basic(t) => KdbxField {
                            name,
                            r#type: t,
                            element_name: big_name,
                            inner_type: field.ty.clone(),
                            full_type: field.ty.clone(),
                            array: false,
                            option: false,
                            flatten,
                        },
                        TypeCategory::Array(_inner_type) => KdbxField {
                            name,
                            r#type: Ident::new("u8", Span::call_site()),
                            element_name: big_name,
                            inner_type: field.ty.clone(),
                            full_type: field.ty.clone(),
                            array: false,
                            option: false,
                            flatten,
                        },
                    })
                })
                //.try_collect::<Vec<KdbxField>>()?;
                .map(|v| v.unwrap()).collect::<Vec<KdbxField>>();
            // eprintln!("Fields done: {:?}.", &v);
            v
        }
        _ => unimplemented!("Only structs currently supported for derive")
    })
}

#[proc_macro_derive(KdbxParse, attributes(keepass_db))]
pub fn derive_deserializer(input: TS1) -> TS1 {
    derive_deserializer2(input.into()).into()
}

fn derive_deserializer2(input: TokenStream) -> TokenStream {
    let ast: syn::DeriveInput = syn::parse2(input).expect("bad parsing");
    let outer_type = &ast.ident;

    let impl_block = match decode_struct(&ast) {
        Ok(v) => v,
        Err(e) => { return e.into_compile_error(); },
    };
    // eprintln!("Struct fields: {:#?}", &impl_block);
    let variables: TokenStream = impl_block
        .iter()
        .map(|r| {
            // eprintln!("Field: {r:?}");
            let name = &r.name;
            let mangled_name = format_ident!("field_{}", name);
            let full_type = &r.full_type;
            quote! { let mut #mangled_name = <#full_type as ::std::default::Default>::default(); }
        })
        .collect();
    let elements: TokenStream = impl_block.iter().map(|r| {
        let name = &r.name;
        let mangled_name = format_ident!("field_{}", name);
        let my_type = &r.r#type;
        let _full_type = &r.full_type;
        let inner_type = &r.inner_type;
        // let big_name = pascal_case(&name.to_string());
        let big_name = &r.element_name;
        // eprintln!("Matching names: {big_name}");
        // let big_name_debug = format!("{big_name}: {{:?}}");
        let match_name = my_type.to_string();
        if r.array {
            if r.option {
                quote! {
                    XmlEvent::StartElement { name, attributes, .. } if name.local_name == #big_name => {
                        let mut vec = #mangled_name.get_or_insert_with(|| Vec::new());
                        loop {
                            let event = reader.next().map_err(|_|"")?;
                            match event {
                                XmlEvent::StartElement { name, attributes, .. } if name.local_name == #match_name => {
                                    vec.push(match <#inner_type as KdbxParse<KdbxContext>>::parse(reader, name, attributes, context)? {
                                        Some(v) => v,
                                        None => <#inner_type as ::std::default::Default>::default(),
                                    });
                                },
                                XmlEvent::StartElement { .. } => {
                                    reader.skip().map_err(|e| format!("Malformed XML document: {e}"))?;
                                },
                                XmlEvent::EndElement { .. } => {
                                    break;
                                },
                                _ => {
                                },
                            }
                        }
                        //println!(#big_name_debug, #mangled_name);
                    }
                }
            } else {
            if r.flatten {
                // let full_type = &r.full_type;
                quote! {
                    XmlEvent::StartElement { name, attributes, .. } if name.local_name == #big_name => {
                        #mangled_name.push(match <#inner_type as KdbxParse<KdbxContext>>::parse(reader, name, attributes, context)? {
                            Some(v) => v,
                            None => <#inner_type as ::std::default::Default>::default(),
                        });
                        //println!(#big_name_debug, #mangled_name);
                    }
                }
            } else {
                // let full_type = &r.full_type;
                quote! {
                    XmlEvent::StartElement { name, attributes, .. } if name.local_name == #big_name => {
                        let mut elements = vec![name];

                        while elements.len() > 0 {
                            let event = reader.next().map_err(|_|"")?;
                            match event {
                                XmlEvent::StartElement { name, attributes, .. } if name.local_name == #match_name => {
                                    #mangled_name.push(match <#inner_type as KdbxParse<KdbxContext>>::parse(reader, name, attributes, context)? {
                                        Some(v) => v,
                                        None => <#inner_type as ::std::default::Default>::default(),
                                    });
                                },
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
                            }
                        }
                        //println!(#big_name_debug, #mangled_name);
                    }
                }
            }
            }
        } else {
            if r.option {
                if r.array {
                    quote! {
                    }
                } else {
                    quote! {
                        XmlEvent::StartElement { name, attributes, .. } if name.local_name == #big_name => {
                            #mangled_name = <#inner_type as KdbxParse<KdbxContext>>::parse(reader, name, attributes, context)?;
                            //println!(#big_name_debug, #mangled_name);
                        }
                    }
                }
            } else {
                // let full_type = &r.full_type;
                quote! {
                    XmlEvent::StartElement { name, attributes, .. } if name.local_name == #big_name => {
                        #mangled_name = match <#inner_type as KdbxParse<KdbxContext>>::parse(reader, name, attributes, context)? {
                            Some(v) => v,
                            None => <#inner_type as ::std::default::Default>::default(),
                        };
                        //println!(#big_name_debug, #mangled_name);
                    }
                }
            }
        }
    }).collect();
    let _big_outer_type = pascal_case(&outer_type.to_string());
    // let _func_name = Ident::new(&format!("decode_{}", snake_case(&outer_type.to_string())), outer_type.span());
    // let debug_string = format!("Decode {}...", outer_type.to_string());
    let names = impl_block.iter().map(|r| {
        let name = &r.name;
        let mangled_name = format_ident!("field_{}", name);
        quote! { #name: #mangled_name }
    });
    let results = quote! {
        impl KdbxParse<KdbxContext> for #outer_type {
            fn parse<R: Read>(reader: &mut EventReader<R>, name: OwnedName, _attributes: Vec<OwnedAttribute>, context: &mut KdbxContext) -> Result<Option<#outer_type>, String> {
                let mut elements = vec![name];
                //elements.push(name);

                #variables
                while elements.len() > 0 {
                    let event = reader.next().map_err(|_|"")?;
                    //println!("Macro debug: {:?}", event);
                    //println!(#debug_string);
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
                Ok(Some(#outer_type {
                    #(#names),*
                }))
            }
        }
    };
    // eprintln!("Parse macros: {}", results);
    results
}

#[proc_macro_derive(KdbxSerialize, attributes(keepass_db))]
pub fn derive_serializer(input: TS1) -> TS1 {
    derive_serializer2(input.into()).into()
}

fn derive_serializer2(input: TokenStream) -> TokenStream {
    let ast: syn::DeriveInput = syn::parse2(input).expect("bad parsing");
    let outer_type = &ast.ident;

    let impl_block = match decode_struct(&ast) {
        Ok(v) => v,
        Err(e) => { return e.into_compile_error(); },
    };
    let elements: TokenStream = impl_block.iter().map(|r| {
        let name = &r.name;
        let my_type = &r.r#type;
        let inner_type = &r.inner_type;
        // let full_type = &r.full_type;
        //let my_func = Ident::new(&format!("encode_{}", my_type), outer_type.span());
        // let big_name = pascal_case(&name.to_string());
        let big_name = &r.element_name;
        let match_name = my_type.to_string();
        // eprintln!("Matching names: {big_name}");
        let _big_name_debug = format!("{big_name}: {{:?}}");
        if r.array {
            if r.flatten {
                quote! {
                    // writer.write(xml::writer::XmlEvent::start_element(#big_name)).map_err(|_|"")?;
                    for item in value.#name {
                        writer.write(xml::writer::XmlEvent::start_element(#big_name)).map_err(|_|"")?;
                        <#inner_type as KdbxSerialize<KdbxContext>>::serialize2(writer, item, context)?;
                        writer.write(xml::writer::XmlEvent::end_element()).map_err(|_|"")?;
                    }
                    // writer.write(xml::writer::XmlEvent::end_element()).map_err(|_|"")?;
                }
            } else {
                if r.option {
                    quote! {
                        if let Some(inner) = value.#name {
                            writer.write(xml::writer::XmlEvent::start_element(#big_name)).map_err(|_|"")?;
                            for item in inner {
                                writer.write(xml::writer::XmlEvent::start_element(#match_name)).map_err(|_|"")?;
                                <#inner_type as KdbxSerialize<KdbxContext>>::serialize2(writer, item, context)?;
                                writer.write(xml::writer::XmlEvent::end_element()).map_err(|_|"")?;
                            }
                            writer.write(xml::writer::XmlEvent::end_element()).map_err(|_|"")?;
                        }
                    }
                } else {
                    quote! {
                        writer.write(xml::writer::XmlEvent::start_element(#big_name)).map_err(|_|"")?;
                        for item in value.#name {
                            writer.write(xml::writer::XmlEvent::start_element(#match_name)).map_err(|_|"")?;
                            <#inner_type as KdbxSerialize<KdbxContext>>::serialize2(writer, item, context)?;
                            writer.write(xml::writer::XmlEvent::end_element()).map_err(|_|"")?;
                        }
                        writer.write(xml::writer::XmlEvent::end_element()).map_err(|_|"")?;
                    }
                }
            }
        } else {
            if r.option {
                quote! {
                    if let Some(inner) = value.#name {
                        writer.write(xml::writer::XmlEvent::start_element(#big_name)).map_err(|_|"")?;
                        <#inner_type as KdbxSerialize<KdbxContext>>::serialize2(writer, inner, context)?;
                        writer.write(xml::writer::XmlEvent::end_element()).map_err(|_|"")?;
                    }
                }
            } else {
                quote! {
                    writer.write(xml::writer::XmlEvent::start_element(#big_name)).map_err(|_|"")?;
                    <#inner_type as KdbxSerialize<KdbxContext>>::serialize2(writer, value.#name, context)?;
                    writer.write(xml::writer::XmlEvent::end_element()).map_err(|_|"")?;
                }
            }
        }
    }).collect();
    let _big_outer_type = pascal_case(&outer_type.to_string());
    // let _func_name = Ident::new(&format!("encode_{}", snake_case(&outer_type.to_string())), outer_type.span());
    // let debug_string = format!("Encode {}...", outer_type.to_string());
    // let names = impl_block.iter().map(|r| &r.name);
    let results = quote! {
        impl KdbxSerialize<KdbxContext> for #outer_type {
            fn serialize2<W: Write>(writer: &mut EventWriter<W>, value: #outer_type, context: &mut KdbxContext) -> Result<(), String> {
                //println!(#debug_string);
                #elements
                Ok(())
            }
        }
    };
    // eprintln!("Serialize macros: {}", results);
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        derive_deserializer2(quote! { struct One { field: i32, string: String } });
    }

    #[test]
    fn serialize() {
        derive_serializer2(quote! { struct One { field: i32, string: String } });
    }

    #[test]
    fn quote_expand() {
        let var = "hello";
        assert_eq!(quote! { test #var insert }.to_string(), r#"test "hello" insert"#);
    }

    #[test]
    fn quote_expand_vec() {
        let var = vec!["hello", "world"];
        assert_eq!(quote! { test #(#var)* insert }.to_string(), r#"test "hello" "world" insert"#);
    }

    #[test]
    fn quote_expand_multi_vec() {
        let var = vec!["hello", "world"];
        let var2 = vec!["one", "two", "three"];
        assert_eq!(quote! { test #(#var = #var2)* insert }.to_string(),
        r#"test "hello" = "one" "world" = "two" insert"#);
    }

    #[test]
    fn quote_expand_multi_vec_with_separator() {
        let var = vec!["hello", "world"];
        let var2 = vec!["one", "two", "three"];
        assert_eq!(quote! { test #(#var = #var2),* insert }.to_string(),
        r#"test "hello" = "one" , "world" = "two" insert"#);
    }

    #[test]
    fn decode_attributes_missing() {
        let input = quote! { struct test; };
        let ast: syn::DeriveInput = syn::parse2(input).expect("bad parsing");
        let value = KdbxAttributes::parse(&ast.attrs).expect("Error in attributes");
        assert!(!value.flatten);
        assert!(value.element_name.is_none());
    }

    #[test]
    fn decode_attributes_empty() {
        let input = quote! { #[keepass_db()] struct test; };
        let ast: syn::DeriveInput = syn::parse2(input).expect("bad parsing");
        let value = KdbxAttributes::parse(&ast.attrs).expect("Error in attributes");
        assert!(!value.flatten);
        assert!(value.element_name.is_none());
    }

    #[test]
    fn decode_attributes_full() {
        let input = quote! {
            #[derive(Debug)]
            #[keepass_db(flatten, element = "foobar")]
            struct test;
        };
        let ast: syn::DeriveInput = syn::parse2(input).expect("bad parsing");
        let value = KdbxAttributes::parse(&ast.attrs).expect("Error in attributes");
        assert!(value.flatten);
        assert!(value.element_name.is_some());
        assert_eq!(value.element_name.unwrap(), "foobar");
    }

    #[test]
    fn decode_attributes_misspelled() {
        let input = quote! {
            #[derive(Debug)]
            #[keepass_db(flatten, elment = "foobar")]
            struct test;
        };
        let ast: syn::DeriveInput = syn::parse2(input).expect("bad parsing");
        let value = KdbxAttributes::parse(&ast.attrs);
        assert!(value.is_err());
    }

    #[test]
    fn decode_struct_valid() {
        let input = quote! {
            struct test {
                one: bool,
            }
        };
        let ast: syn::DeriveInput = syn::parse2(input).expect("bad parsing");
        let value = decode_struct(&ast).expect("Failed to decode struct");
        assert_eq!(value.len(), 1);
        assert_eq!(value[0].name.to_string(), "one");
        assert_eq!(value[0].r#type.to_string(), "bool");
        assert_eq!(value[0].element_name, "One");
        // TODO test inner_type and full_type
        assert!(!value[0].array);
        assert!(!value[0].option);
        assert!(!value[0].flatten);
    }

    #[test]
    fn decode_struct_complex() {
        let input = quote! {
            struct test {
                #[keepass_db(flatten)]
                one: u32,
                two: Option<String>,
                three: Vec<bool>,
                four: Option<Vec<i16>>,
            }
        };
        let ast: syn::DeriveInput = syn::parse2(input).expect("bad parsing");
        let value = decode_struct(&ast).expect("Failed to decode struct");
        assert_eq!(value.len(), 4);
        assert_eq!(value[0].name.to_string(), "one");
        assert_eq!(value[0].r#type.to_string(), "u32");
        assert_eq!(value[0].element_name, "One");
        assert!(!value[0].array);
        assert!(!value[0].option);
        assert!(value[0].flatten);
        assert_eq!(value[1].name.to_string(), "two");
        assert_eq!(value[1].r#type.to_string(), "String");
        assert_eq!(value[1].element_name, "Two");
        assert!(!value[1].array);
        assert!(value[1].option);
        assert!(!value[1].flatten);
        assert_eq!(value[2].name.to_string(), "three");
        assert_eq!(value[2].r#type.to_string(), "bool");
        assert_eq!(value[2].element_name, "Three");
        assert!(value[2].array);
        assert!(!value[2].option);
        assert!(!value[2].flatten);
        assert_eq!(value[3].name.to_string(), "four");
        assert_eq!(value[3].r#type.to_string(), "i16");
        assert_eq!(value[3].element_name, "Four");
        assert!(value[3].array);
        assert!(value[3].option);
        assert!(!value[3].flatten);
    }
}
