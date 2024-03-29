use hex::FromHex;

use chrono::offset::Utc;
use rand::Rng;

use super::*;

#[test]
fn test_decode_empty_document() {
    let content = "";
    let mut reader = ParserConfig::new().create_reader(Cursor::new(content));
    let event = reader.next();
    assert!(event.is_err());
}

#[test]
fn test_decode_minimal_document() {
    let content = "<root/>";
    let mut reader = ParserConfig::new().create_reader(Cursor::new(content));
    match reader.next().unwrap() {
        XmlEvent::StartDocument { .. } => {}
        _ => {
            panic!("Missing document start");
        }
    }
    match reader.next().unwrap() {
        XmlEvent::StartElement { name, .. } => {
            assert_eq!(name.local_name, "root");
        }
        _ => {
            panic!("Missing root element start");
        }
    }
    match reader.next().unwrap() {
        XmlEvent::EndElement { name, .. } => {
            assert_eq!(name.local_name, "root");
        }
        _ => {
            panic!("Missing root element end");
        }
    }
    match reader.next().unwrap() {
        XmlEvent::EndDocument => {}
        _ => {
            panic!("Missing document end");
        }
    }
}

#[test]
fn test_consume_minimal_document() {
    let content = "<root/>";
    let mut reader = ParserConfig::new().create_reader(Cursor::new(content));
    match reader.next().unwrap() {
        XmlEvent::StartDocument { .. } => {}
        _ => {
            panic!("Missing document start");
        }
    }
    let element = match reader.next().unwrap() {
        XmlEvent::StartElement { name, .. } => name,
        _ => {
            panic!("Missing document element");
        }
    };
    consume_element(&mut reader, element, vec![]).expect("Failed to consume");
    match reader.next().unwrap() {
        XmlEvent::EndDocument => {}
        _ => {
            panic!("Missing document end");
        }
    }
}

#[test]
fn test_consume_nested_document() {
    let content = "<root>  <consumed>   <child1>  <!-- Comment --> <grandchild/>Test</child1> <child2>More</child2></consumed> </root>";
    let mut reader = ParserConfig::new().create_reader(Cursor::new(content));
    match reader.next().unwrap() {
        XmlEvent::StartDocument { .. } => {}
        _ => {
            panic!("Missing document start");
        }
    };
    match reader.next().unwrap() {
        XmlEvent::StartElement { name, .. } => {
            assert_eq!(name.local_name, "root");
        }
        _ => {
            panic!("Missing root element start");
        }
    };
    match reader.next().unwrap() {
        XmlEvent::Whitespace(_) => {}
        _ => {
            panic!("Missing whitespace");
        }
    };
    match reader.next().unwrap() {
        XmlEvent::StartElement { name, .. } => {
            assert_eq!(name.local_name, "consumed");
        }
        _ => {
            panic!("Missing consumed element start");
        }
    };
    consume_element(&mut reader, OwnedName::local("consumed"), vec![]).expect("Failed to consume");
    match reader.next().unwrap() {
        XmlEvent::Whitespace(_) => {}
        _ => {
            panic!("Missing whitespace");
        }
    };
    match reader.next().unwrap() {
        XmlEvent::EndElement { name, .. } => {
            assert_eq!(name.local_name, "root");
        }
        _ => {
            panic!("Missing root element end");
        }
    };
    match reader.next().unwrap() {
        XmlEvent::EndDocument => {}
        _ => {
            panic!("Missing document end");
        }
    };
}

#[test]
fn test_find_next_element_document() {
    let content = "<root>  <consumed>   <child1>  <!-- Comment --> <grandchild/>Test</child1> <child2>More</child2></consumed> </root>";
    let mut reader = ParserConfig::new().create_reader(Cursor::new(content));
    match reader.next().unwrap() {
        XmlEvent::StartDocument { .. } => {}
        _ => {
            panic!("Missing document start");
        }
    };
    match find_next_element(&mut reader).expect("Valid element") {
        ElementEvent::StartElement { name, .. } => {
            assert_eq!(name.local_name, "root", "Need root element");
        }
        _ => {
            panic!("Missing root element start");
        }
    };
    match find_next_element(&mut reader).expect("Valid element") {
        ElementEvent::StartElement { name, .. } => {
            assert_eq!(name.local_name, "consumed");
        }
        _ => {
            panic!("Missing consumed element start");
        }
    };
    match find_next_element(&mut reader).expect("Valid element") {
        ElementEvent::StartElement { name, .. } => {
            assert_eq!(name.local_name, "child1");
        }
        _ => {
            panic!("Missing child1 element start");
        }
    };
    match find_next_element(&mut reader).expect("Valid element") {
        ElementEvent::StartElement { name, .. } => {
            assert_eq!(name.local_name, "grandchild");
        }
        _ => {
            panic!("Missing grandchild element start");
        }
    };
    match find_next_element(&mut reader).expect("Valid element") {
        ElementEvent::EndElement { name, .. } => {
            assert_eq!(name.local_name, "grandchild");
        }
        _ => {
            panic!("Missing grandchild element end");
        }
    };
    match find_next_element(&mut reader).expect("Valid element") {
        ElementEvent::EndElement { name, .. } => {
            assert_eq!(name.local_name, "child1");
        }
        _ => {
            panic!("Missing child1 element end");
        }
    };
    match find_next_element(&mut reader).expect("Valid element") {
        ElementEvent::StartElement { name, .. } => {
            assert_eq!(name.local_name, "child2");
        }
        _ => {
            panic!("Missing child2 element start");
        }
    };
    match find_next_element(&mut reader).expect("Valid element") {
        ElementEvent::EndElement { name, .. } => {
            assert_eq!(name.local_name, "child2");
        }
        _ => {
            panic!("Missing child2 element end");
        }
    };
    match find_next_element(&mut reader).expect("Valid element") {
        ElementEvent::EndElement { name, .. } => {
            assert_eq!(name.local_name, "consumed");
        }
        _ => {
            panic!("Missing root element end");
        }
    };
    match find_next_element(&mut reader).expect("Valid element") {
        ElementEvent::EndElement { name, .. } => {
            assert_eq!(name.local_name, "root");
        }
        _ => {
            panic!("Missing root element end");
        }
    };
    match reader.next().unwrap() {
        XmlEvent::EndDocument => {}
        _ => {
            panic!("Missing document end");
        }
    };
}

//fn start_document<'a>(contents: &'a (impl AsRef<[u8]> + ?Sized), root: &str) -> EventReader<Cursor<&'a [u8]>> {
fn start_document<'a, C: AsRef<[u8]> + ?Sized>(
    contents: &'a C,
    root: &str,
) -> EventReader<Cursor<&'a [u8]>> {
    //fn start_document_raw<'a>(contents: &'a [u8], root: &str) -> EventReader<Cursor<&'a [u8]>> {
    let mut reader = ParserConfig::new()
        .ignore_comments(false)
        //.ignore_root_level_whitespace(false)
        .create_reader(Cursor::new(contents.as_ref()));
    match reader.next().unwrap() {
        XmlEvent::StartDocument { .. } => {}
        _ => {
            panic!("Missing document start");
        }
    };
    match reader.next().unwrap() {
        XmlEvent::StartElement { name, .. } => {
            assert_eq!(name.local_name, root);
        }
        _ => {
            panic!("Missing root element start");
        }
    }
    return reader;
}

fn end_document(mut reader: EventReader<Cursor<&[u8]>>) {
    match reader.next().unwrap() {
        XmlEvent::EndDocument => {}
        _ => {
            panic!("Missing document end");
        }
    };
}

//fn start_document<'a>(contents: &'static str, root: &str) -> EventReader<Cursor<&'a [u8]>> {
//    start_document_raw(contents.as_bytes(), root)
//}

fn parse_document<P: KdbxParse<KdbxContext>>(contents: &'static str) -> P {
    let root = std::any::type_name::<P>().rsplit(":").nth(0).unwrap();
    let mut reader = start_document(contents, root);
    let doc = P::parse(
        &mut reader,
        OwnedName::local(root),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    end_document(reader);
    return doc;
}

fn serialize_document<S: KdbxSerialize<KdbxContext> + Clone>(doc: &S) -> String {
    let value = write_kdbx_document(doc);
    std::str::from_utf8(&value).expect("Valid UTF-8").to_string()
}

#[derive(Clone, Default, KdbxParse, KdbxSerialize)]
struct StringTest {
    field: String,
}

#[test]
fn test_parsing_empty_string() {
    let mut reader = start_document("<root> <Field /> </root>", "root");
    let actual = StringTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, "");
    end_document(reader);

    let mut reader = start_document("<root> <Field></Field> </root>", "root");
    let actual = StringTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, "");
    end_document(reader);

    let mut reader = start_document(
        "<root> <Field><!-- This is invisible --></Field> </root>",
        "root",
    );
    let actual = StringTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, "");
    end_document(reader);
}

#[test]
fn test_parsing_valid_string() {
    let mut reader = start_document("<root> <Field>This is me.</Field> </root>", "root");
    let actual = StringTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, "This is me.");
    end_document(reader);
}

#[test]
fn test_parsing_whitespace_string() {
    let mut reader = start_document("<root> <Field> \t  </Field> </root>", "root");
    let actual = StringTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, " \t  ");
    end_document(reader);
}

#[test]
fn test_parsing_mixed_string() {
    let mut reader = start_document(
        "<root> <Field>\tA spaced <!--hidden-->string.  </Field> </root>",
        "root",
    );
    let actual = StringTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, "\tA spaced string.  ");
    end_document(reader);
}

#[test]
fn test_parsing_string_ignores_child_elements() {
    let mut reader = start_document("<root> <Field>This <b>is</b> me.</Field> </root>", "root");
    let actual = StringTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, "This  me.");
    end_document(reader);
}

#[test]
fn test_serializing_empty_string() {
    let doc = write_kdbx_document(&StringTest {
        field: "".to_string(),
    });
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    //assert_eq!(actual, "<StringTest><Field/></StringTest>");  // TODO This should be normalized
    assert_eq!(actual, "<StringTest><Field></Field></StringTest>");
}

#[test]
fn test_serializing_valid_string() {
    let doc = write_kdbx_document(&StringTest {
        field: "This is valid.".to_string(),
    });
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(
        actual,
        "<StringTest><Field>This is valid.</Field></StringTest>"
    );
}

#[test]
fn test_serializing_whitespace_string() {
    let doc = write_kdbx_document(&StringTest {
        field: "  \t ".to_string(),
    });
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(actual, "<StringTest><Field>  \t </Field></StringTest>");
}

#[test]
fn test_serializing_mixed_string() {
    let doc = write_kdbx_document(&StringTest {
        field: " This <b>is</b> valid.\t".to_string(),
    });
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    //assert_eq!(actual, "<StringTest><Field/></StringTest>");  // TODO This should be normalized
    assert_eq!(
        actual,
        "<StringTest><Field> This &lt;b>is&lt;/b> valid.\t</Field></StringTest>"
    );
}

#[derive(Clone, Default, KdbxParse, KdbxSerialize)]
struct OptionStringTest {
    field: Option<String>,
}

#[test]
fn test_parsing_optional_empty_string() {
    let mut reader = start_document("<root> <Field /> </root>", "root");
    let actual = OptionStringTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field.as_deref(), None);
    end_document(reader);

    let mut reader = start_document("<root> <Field></Field> </root>", "root");
    let actual = OptionStringTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field.as_deref(), None);
    end_document(reader);

    let mut reader = start_document(
        "<root> <Field><!-- This is invisible --></Field> </root>",
        "root",
    );
    let actual = OptionStringTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    //assert_eq!(actual.field.as_deref(), Some(""));  // Even a lone comment makes it non-empty
    assert_eq!(actual.field.as_deref(), None);
    end_document(reader);
}

#[test]
fn test_parsing_optional_valid_string() {
    let mut reader = start_document("<root> <Field>This is me.</Field> </root>", "root");
    let actual = OptionStringTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field.as_deref(), Some("This is me."));
    end_document(reader);
}

#[test]
fn test_parsing_optional_whitespace_string() {
    let mut reader = start_document("<root> <Field> \t  </Field> </root>", "root");
    let actual = OptionStringTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field.as_deref(), Some(" \t  "));
    end_document(reader);
}

#[test]
fn test_parsing_optional_mixed_string() {
    let mut reader = start_document(
        "<root> <Field>\tA spaced <!--hidden-->string.  </Field> </root>",
        "root",
    );
    let actual = OptionStringTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field.as_deref(), Some("\tA spaced string.  "));
    end_document(reader);
}

#[test]
fn test_serializing_optional_empty_string() {
    let doc = write_kdbx_document(&OptionStringTest { field: None });
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(actual, "<OptionStringTest/>");

    let doc = write_kdbx_document(&OptionStringTest {
        field: Some("".to_string()),
    });
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    //assert_eq!(actual, "<OptionStringTest><Field/></OptionStringTest>");  // TODO This should be normalized
    assert_eq!(
        actual,
        "<OptionStringTest><Field></Field></OptionStringTest>"
    );
}

#[test]
fn test_serializing_optional_valid_string() {
    let doc = write_kdbx_document(&OptionStringTest {
        field: Some("This is valid.".to_string()),
    });
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(
        actual,
        "<OptionStringTest><Field>This is valid.</Field></OptionStringTest>"
    );
}

#[test]
fn test_serializing_optional_whitespace_string() {
    let doc = write_kdbx_document(&OptionStringTest {
        field: Some("  \t ".to_string()),
    });
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(
        actual,
        "<OptionStringTest><Field>  \t </Field></OptionStringTest>"
    );
}

#[test]
fn test_serializing_optional_mixed_string() {
    let doc = write_kdbx_document(&OptionStringTest {
        field: Some(" This <b>is</b> valid.\t".to_string()),
    });
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    //assert_eq!(actual, "<OptionStringTest><Field/></OptionStringTest>");  // TODO This should be normalized
    assert_eq!(
        actual,
        "<OptionStringTest><Field> This &lt;b>is&lt;/b> valid.\t</Field></OptionStringTest>"
    );
}

#[derive(Clone, Default, KdbxParse, KdbxSerialize)]
struct BoolTest {
    field: bool,
}

#[test]
fn test_parsing_empty_bool() {
    let mut reader = start_document("<root> <Field /> </root>", "root");
    let actual = BoolTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, false);
    end_document(reader);

    let mut reader = start_document("<root> <Field></Field> </root>", "root");
    let actual = BoolTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, false);
    end_document(reader);

    let mut reader = start_document(
        "<root> <Field><!-- This is invisible --></Field> </root>",
        "root",
    );
    let actual = BoolTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, false);
    end_document(reader);
}

#[test]
fn test_parsing_valid_false_bool() {
    let mut reader = start_document("<root> <Field>false</Field> </root>", "root");
    let actual = BoolTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, false);
    end_document(reader);

    let mut reader = start_document("<root> <Field>FALSE</Field> </root>", "root");
    let actual = BoolTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, false);
    end_document(reader);

    let mut reader = start_document("<root> <Field>False</Field> </root>", "root");
    let actual = BoolTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, false);
    end_document(reader);
}

#[test]
fn test_parsing_invalid_false_bool() {
    // TODO Test for warnings about invalid values
    let mut reader = start_document("<root> <Field>This is me.</Field> </root>", "root");
    let actual = BoolTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, false);
    end_document(reader);
}

#[test]
fn test_parsing_valid_true_bool() {
    let mut reader = start_document("<root> <Field>true</Field> </root>", "root");
    let actual = BoolTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, true);
    end_document(reader);

    let mut reader = start_document("<root> <Field>TRUE</Field> </root>", "root");
    let actual = BoolTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, true);
    end_document(reader);

    let mut reader = start_document("<root> <Field>True</Field> </root>", "root");
    let actual = BoolTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, true);
    end_document(reader);
}

#[test]
fn test_serializing_false_bool() {
    let doc = write_kdbx_document(&BoolTest { field: false });
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(actual, "<BoolTest><Field>False</Field></BoolTest>");
}

#[test]
fn test_serializing_true_bool() {
    let doc = write_kdbx_document(&BoolTest { field: true });
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(actual, "<BoolTest><Field>True</Field></BoolTest>");
}

#[derive(Clone, Default, KdbxParse, KdbxSerialize)]
struct OptionBoolTest {
    field: Option<bool>,
}

#[test]
fn test_parsing_optional_empty_bool() {
    let mut reader = start_document("<root> <Field /> </root>", "root");
    let actual = OptionBoolTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, None);
    end_document(reader);

    let mut reader = start_document("<root> <Field></Field> </root>", "root");
    let actual = OptionBoolTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, None);
    end_document(reader);

    let mut reader = start_document(
        "<root> <Field><!-- This is invisible --></Field> </root>",
        "root",
    );
    let actual = OptionBoolTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, None);
    end_document(reader);
}

#[test]
fn test_parsing_optional_valid_false_bool() {
    let mut reader = start_document("<root> <Field>false</Field> </root>", "root");
    let actual = OptionBoolTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, Some(false));
    end_document(reader);

    let mut reader = start_document("<root> <Field>FALSE</Field> </root>", "root");
    let actual = OptionBoolTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, Some(false));
    end_document(reader);

    let mut reader = start_document("<root> <Field>False</Field> </root>", "root");
    let actual = OptionBoolTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, Some(false));
    end_document(reader);
}

#[test]
fn test_parsing_optional_invalid_false_bool() {
    // TODO Test for warnings about invalid values
    let mut reader = start_document("<root> <Field>This is me.</Field> </root>", "root");
    let actual = OptionBoolTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, Some(false));
    end_document(reader);
}

#[test]
fn test_parsing_optional_valid_true_bool() {
    let mut reader = start_document("<root> <Field>true</Field> </root>", "root");
    let actual = OptionBoolTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, Some(true));
    end_document(reader);

    let mut reader = start_document("<root> <Field>TRUE</Field> </root>", "root");
    let actual = OptionBoolTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, Some(true));
    end_document(reader);

    let mut reader = start_document("<root> <Field>True</Field> </root>", "root");
    let actual = OptionBoolTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, Some(true));
    end_document(reader);
}

#[test]
fn test_serializing_optional_empty_bool() {
    let doc = write_kdbx_document(&OptionBoolTest { field: None });
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(actual, "<OptionBoolTest/>");
}

#[test]
fn test_serializing_optional_false_bool() {
    let doc = write_kdbx_document(&OptionBoolTest { field: Some(false) });
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(
        actual,
        "<OptionBoolTest><Field>False</Field></OptionBoolTest>"
    );
}

#[test]
fn test_serializing_optional_true_bool() {
    let doc = write_kdbx_document(&OptionBoolTest { field: Some(true) });
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(
        actual,
        "<OptionBoolTest><Field>True</Field></OptionBoolTest>"
    );
}

#[derive(Clone, Default, KdbxParse, KdbxSerialize)]
struct UuidTest {
    field: Uuid,
}

#[test]
fn test_parsing_empty_uuid() {
    let mut reader = start_document("<root> <Field /> </root>", "root");
    let actual = UuidTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, Uuid::nil());
    end_document(reader);

    let mut reader = start_document("<root> <Field></Field> </root>", "root");
    let actual = UuidTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, Uuid::nil());
    end_document(reader);

    let mut reader = start_document(
        "<root> <Field><!-- This is invisible --></Field> </root>",
        "root",
    );
    let actual = UuidTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, Uuid::nil());
    end_document(reader);
}

#[test]
fn test_parsing_nil_uuid() {
    let mut reader = start_document(
        "<root> <Field>AAAAAAAAAAAAAAAAAAAAAA==</Field> </root>",
        "root",
    );
    let actual = UuidTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, Uuid::nil());
    end_document(reader);
}

#[test]
fn test_parsing_valid_uuid() {
    let mut reader = start_document(
        "<root> <Field>MZ3RgvukSfWAAWlPEBQOzA==</Field> </root>",
        "root",
    );
    let actual = UuidTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, uuid!("319dd182-fba4-49f5-8001-694f10140ecc"));
    end_document(reader);
}

#[test]
fn test_serializing_nil_uuid() {
    let doc = write_kdbx_document(&UuidTest { field: Uuid::nil() });
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(
        actual,
        "<UuidTest><Field>AAAAAAAAAAAAAAAAAAAAAA==</Field></UuidTest>"
    );
}

#[test]
fn test_serializing_valid_uuid() {
    let doc = write_kdbx_document(&UuidTest {
        field: uuid!("319dd182-fba4-49f5-8001-694f10140ecc"),
    });
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(
        actual,
        "<UuidTest><Field>MZ3RgvukSfWAAWlPEBQOzA==</Field></UuidTest>"
    );
}

#[derive(Clone, Default, KdbxParse, KdbxSerialize)]
struct OptionUuidTest {
    field: Option<Uuid>,
}

#[test]
fn test_parsing_optional_empty_uuid() {
    let mut reader = start_document("<root> <Field /> </root>", "root");
    let actual = OptionUuidTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, None);
    end_document(reader);

    let mut reader = start_document("<root> <Field></Field> </root>", "root");
    let actual = OptionUuidTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, None);
    end_document(reader);

    let mut reader = start_document(
        "<root> <Field><!-- This is invisible --></Field> </root>",
        "root",
    );
    let actual = OptionUuidTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, None);
    end_document(reader);
}

#[test]
fn test_parsing_optional_nil_uuid() {
    let mut reader = start_document(
        "<root> <Field>AAAAAAAAAAAAAAAAAAAAAA==</Field> </root>",
        "root",
    );
    let actual = OptionUuidTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, Some(Uuid::nil()));
    end_document(reader);
}

#[test]
fn test_parsing_optional_valid_uuid() {
    let mut reader = start_document(
        "<root> <Field>MZ3RgvukSfWAAWlPEBQOzA==</Field> </root>",
        "root",
    );
    let actual = OptionUuidTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(
        actual.field,
        Some(uuid!("319dd182-fba4-49f5-8001-694f10140ecc"))
    );
    end_document(reader);
}

#[test]
fn test_serializing_optional_empty_uuid() {
    let doc = write_kdbx_document(&OptionUuidTest { field: None });
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(actual, "<OptionUuidTest/>");
}

#[test]
fn test_serializing_optional_nil_uuid() {
    let doc = write_kdbx_document(&OptionUuidTest {
        field: Some(Uuid::nil()),
    });
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(
        actual,
        "<OptionUuidTest><Field>AAAAAAAAAAAAAAAAAAAAAA==</Field></OptionUuidTest>"
    );
}

#[test]
fn test_serializing_optional_valid_uuid() {
    let doc = write_kdbx_document(&OptionUuidTest {
        field: Some(uuid!("319dd182-fba4-49f5-8001-694f10140ecc")),
    });
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(
        actual,
        "<OptionUuidTest><Field>MZ3RgvukSfWAAWlPEBQOzA==</Field></OptionUuidTest>"
    );
}

#[derive(Clone, Default, KdbxParse, KdbxSerialize)]
struct DateTimeTest {
    field: DateTime<Utc>,
}

#[test]
#[ignore = "What should default datetime be?"]
fn test_parsing_empty_datetime_kdbx3() {
    let mut reader = start_document("<root> <Field /> </root>", "root");
    let mut context = KdbxContext::default();
    context.major_version = 3;
    let actual = DateTimeTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut context,
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(
        actual.field,
        Utc.with_ymd_and_hms(1, 1, 1, 0, 0, 0).unwrap()
    );
    end_document(reader);

    let mut reader = start_document("<root> <Field></Field> </root>", "root");
    let mut context = KdbxContext::default();
    context.major_version = 3;
    let actual = DateTimeTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut context,
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(
        actual.field,
        Utc.with_ymd_and_hms(1, 1, 1, 0, 0, 0).unwrap()
    );
    end_document(reader);

    let mut reader = start_document(
        "<root> <Field><!-- This is invisible --></Field> </root>",
        "root",
    );
    let mut context = KdbxContext::default();
    context.major_version = 3;
    let actual = DateTimeTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut context,
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(
        actual.field,
        Utc.with_ymd_and_hms(1, 1, 1, 0, 0, 0).unwrap()
    );
    end_document(reader);
}

#[test]
fn test_parsing_nil_datetime_kdbx3() {
    let mut reader = start_document("<root> <Field>0001-01-01T00:00:00Z</Field> </root>", "root");
    let mut context = KdbxContext::default();
    context.major_version = 3;
    let actual = DateTimeTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut context,
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(
        actual.field,
        Utc.with_ymd_and_hms(1, 1, 1, 0, 0, 0).unwrap()
    );
    end_document(reader);
}

#[test]
fn test_parsing_valid_datetime_kdbx1() {
    // This is an older format from Alpha/Beta KeePass releases
    let mut reader = start_document("<root> <Field>2021-07-30T21:31:02</Field> </root>", "root");
    let mut context = KdbxContext::default();
    context.major_version = 1;
    let actual = DateTimeTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut context,
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(
        actual.field,
        Local.with_ymd_and_hms(2021, 7, 30, 21, 31, 2).single().expect("valid local date")
    );
    end_document(reader);
}

#[test]
fn test_parsing_valid_datetime_kdbx3() {
    let mut reader = start_document("<root> <Field>2021-07-30T21:31:02Z</Field> </root>", "root");
    let mut context = KdbxContext::default();
    context.major_version = 3;
    let actual = DateTimeTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut context,
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(
        actual.field,
        DateTime::parse_from_rfc3339("2021-07-30T14:31:02-07:00").unwrap()
    );
    end_document(reader);
}

#[test]
fn test_serializing_nil_datetime_kdbx3() {
    let mut context = KdbxContext::default();
    context.major_version = 3;
    let doc = write_kdbx_document_with_context(&DateTimeTest {
        field: Utc.with_ymd_and_hms(1, 1, 1, 0, 0, 0).unwrap(),
    }, &mut context);
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(
        actual,
        "<DateTimeTest><Field>0001-01-01T00:00:00Z</Field></DateTimeTest>"
    );
}

#[test]
fn test_serializing_valid_datetime_kdbx3() {
    let mut context = KdbxContext::default();
    context.major_version = 3;
    let doc = write_kdbx_document_with_context(&DateTimeTest {
        field: DateTime::parse_from_rfc3339("2021-07-30T14:31:02-07:00")
            .unwrap()
            .into(),
    }, &mut context);
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(
        actual,
        "<DateTimeTest><Field>2021-07-30T21:31:02Z</Field></DateTimeTest>"
    );
}

#[test]
#[ignore = "What should default datetime be?"]
fn test_parsing_empty_datetime_kdbx41() {
    let mut reader = start_document("<root> <Field /> </root>", "root");
    let actual = DateTimeTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(
        actual.field,
        Utc.with_ymd_and_hms(1, 1, 1, 0, 0, 0).unwrap()
    );
    end_document(reader);

    let mut reader = start_document("<root> <Field></Field> </root>", "root");
    let actual = DateTimeTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(
        actual.field,
        Utc.with_ymd_and_hms(1, 1, 1, 0, 0, 0).unwrap()
    );
    end_document(reader);

    let mut reader = start_document(
        "<root> <Field><!-- This is invisible --></Field> </root>",
        "root",
    );
    let actual = DateTimeTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(
        actual.field,
        Utc.with_ymd_and_hms(1, 1, 1, 0, 0, 0).unwrap()
    );
    end_document(reader);
}

#[test]
fn test_parsing_nil_datetime_kdbx41() {
    let mut reader = start_document("<root> <Field>AAAAAAAAAAA=</Field> </root>", "root");
    let actual = DateTimeTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(
        actual.field,
        Utc.with_ymd_and_hms(1, 1, 1, 0, 0, 0).unwrap()
    );
    end_document(reader);
}

#[test]
fn test_parsing_valid_datetime_kdbx41() {
    let mut reader = start_document("<root> <Field>lmaW2A4AAAA=</Field> </root>", "root");
    let actual = DateTimeTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(
        actual.field,
        DateTime::parse_from_rfc3339("2021-07-30T14:31:02-07:00").unwrap()
    );
    end_document(reader);
}

#[test]
fn test_serializing_nil_datetime_kdbx41() {
    let doc = write_kdbx_document(&DateTimeTest {
        field: Utc.with_ymd_and_hms(1, 1, 1, 0, 0, 0).unwrap(),
    });
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(
        actual,
        "<DateTimeTest><Field>AAAAAAAAAAA=</Field></DateTimeTest>"
    );
}

#[test]
fn test_serializing_valid_datetime_kdbx41() {
    let doc = write_kdbx_document(&DateTimeTest {
        field: DateTime::parse_from_rfc3339("2021-07-30T14:31:02-07:00")
            .unwrap()
            .into(),
    });
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(
        actual,
        "<DateTimeTest><Field>lmaW2A4AAAA=</Field></DateTimeTest>"
    );
}

#[derive(Clone, Default, KdbxParse, KdbxSerialize)]
struct OptionDateTimeTest {
    field: Option<DateTime<Utc>>,
}

#[test]
fn test_parsing_optional_empty_datetime_kdbx3() {
    let mut reader = start_document("<root> <Field /> </root>", "root");
    let mut context = KdbxContext::default();
    context.major_version = 3;
    let actual = OptionDateTimeTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut context,
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, None);
    end_document(reader);

    let mut reader = start_document("<root> <Field></Field> </root>", "root");
    let mut context = KdbxContext::default();
    context.major_version = 3;
    let actual = OptionDateTimeTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut context,
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, None);
    end_document(reader);

    let mut reader = start_document(
        "<root> <Field><!-- This is invisible --></Field> </root>",
        "root",
    );
    let mut context = KdbxContext::default();
    context.major_version = 3;
    let actual = OptionDateTimeTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut context,
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, None);
    end_document(reader);
}

#[test]
fn test_parsing_optional_nil_datetime_kdbx3() {
    let mut reader = start_document("<root> <Field>0001-01-01T00:00:00Z</Field> </root>", "root");
    let mut context = KdbxContext::default();
    context.major_version = 3;
    let actual = OptionDateTimeTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut context,
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(
        actual.field,
        Some(Utc.with_ymd_and_hms(1, 1, 1, 0, 0, 0).unwrap())
    );
    end_document(reader);
}

#[test]
fn test_parsing_optional_valid_datetime_kdbx3() {
    let mut reader = start_document("<root> <Field>2021-07-30T21:31:02Z</Field> </root>", "root");
    let mut context = KdbxContext::default();
    context.major_version = 3;
    let actual = OptionDateTimeTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut context,
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(
        actual.field,
        Some(
            DateTime::parse_from_rfc3339("2021-07-30T14:31:02-07:00")
                .unwrap()
                .into()
        )
    );
    end_document(reader);
}

#[test]
fn test_serializing_optional_empty_datetime_kdbx3() {
    let mut context = KdbxContext::default();
    context.major_version = 3;
    let doc = write_kdbx_document_with_context(&OptionDateTimeTest { field: None }, &mut context);
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(actual, "<OptionDateTimeTest/>");
}

#[test]
fn test_serializing_optional_nil_datetime_kdbx3() {
    let mut context = KdbxContext::default();
    context.major_version = 3;
    let doc = write_kdbx_document_with_context(&OptionDateTimeTest {
        field: Some(Utc.with_ymd_and_hms(1, 1, 1, 0, 0, 0).unwrap()),
    }, &mut context);
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(
        actual,
        "<OptionDateTimeTest><Field>0001-01-01T00:00:00Z</Field></OptionDateTimeTest>"
    );
}

#[test]
fn test_serializing_optional_valid_datetime_kdbx3() {
    let mut context = KdbxContext::default();
    context.major_version = 3;
    let doc = write_kdbx_document_with_context(&OptionDateTimeTest {
        field: Some(
            DateTime::parse_from_rfc3339("2021-07-30T14:31:02-07:00")
                .unwrap()
                .into(),
        ),
    }, &mut context);
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(
        actual,
        "<OptionDateTimeTest><Field>2021-07-30T21:31:02Z</Field></OptionDateTimeTest>"
    );
}

#[test]
fn test_parsing_optional_empty_datetime_kdbx41() {
    let mut reader = start_document("<root> <Field /> </root>", "root");
    let actual = OptionDateTimeTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, None);
    end_document(reader);

    let mut reader = start_document("<root> <Field></Field> </root>", "root");
    let actual = OptionDateTimeTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, None);
    end_document(reader);

    let mut reader = start_document(
        "<root> <Field><!-- This is invisible --></Field> </root>",
        "root",
    );
    let actual = OptionDateTimeTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(actual.field, None);
    end_document(reader);
}

#[test]
fn test_parsing_optional_nil_datetime_kdbx41() {
    let mut reader = start_document("<root> <Field>AAAAAAAAAAA=</Field> </root>", "root");
    let actual = OptionDateTimeTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(
        actual.field,
        Some(Utc.with_ymd_and_hms(1, 1, 1, 0, 0, 0).unwrap())
    );
    end_document(reader);
}

#[test]
fn test_parsing_optional_valid_datetime_kdbx41() {
    let mut reader = start_document("<root> <Field>lmaW2A4AAAA=</Field> </root>", "root");
    let actual = OptionDateTimeTest::parse(
        &mut reader,
        OwnedName::local("root"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Parsing error")
    .expect("Missing object");
    assert_eq!(
        actual.field,
        Some(
            DateTime::parse_from_rfc3339("2021-07-30T14:31:02-07:00")
                .unwrap()
                .into()
        )
    );
    end_document(reader);
}

#[test]
fn test_serializing_optional_empty_datetime_kdbx41() {
    let doc = write_kdbx_document(&OptionDateTimeTest { field: None });
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(actual, "<OptionDateTimeTest/>");
}

#[test]
fn test_serializing_optional_nil_datetime_kdbx41() {
    let doc = write_kdbx_document(&OptionDateTimeTest {
        field: Some(Utc.with_ymd_and_hms(1, 1, 1, 0, 0, 0).unwrap()),
    });
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(
        actual,
        "<OptionDateTimeTest><Field>AAAAAAAAAAA=</Field></OptionDateTimeTest>"
    );
}

#[test]
fn test_serializing_optional_valid_datetime_kdbx41() {
    let doc = write_kdbx_document(&OptionDateTimeTest {
        field: Some(
            DateTime::parse_from_rfc3339("2021-07-30T14:31:02-07:00")
                .unwrap()
                .into(),
        ),
    });
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(
        actual,
        "<OptionDateTimeTest><Field>lmaW2A4AAAA=</Field></OptionDateTimeTest>"
    );
}

// TODO Test negative timestamps

#[test]
fn test_decode_optional_empty_string() {
    let mut reader = start_document("<root/>", "root");
    assert_eq!(
        decode_optional_string(&mut reader, OwnedName::local("root"), vec![]).expect("Failed parsing"),
        None
    );
    end_document(reader);
}

#[test]
fn test_decode_optional_basic_string() {
    let mut reader = start_document("<root>  This is a test of it 1   </root>", "root");
    assert_eq!(
        decode_optional_string(&mut reader, OwnedName::local("root"), vec![]).expect("Failed parsing"),
        Some(String::from("  This is a test of it 1   "))
    );
    end_document(reader);
}

#[test]
fn test_decode_optional_whitespace_string() {
    let mut reader = start_document("<root>     </root>", "root");
    assert_eq!(
        decode_optional_string(&mut reader, OwnedName::local("root"), vec![]).expect("Failed parsing"),
        Some(String::from("     "))
    );
    end_document(reader);
}

#[test]
fn test_decode_optional_cdata_string() {
    let mut reader = start_document("<root><![CDATA[This is a test of it 3]]></root>", "root");
    assert_eq!(
        decode_optional_string(&mut reader, OwnedName::local("root"), vec![]).expect("Failed parsing"),
        Some(String::from("This is a test of it 3"))
    );
    end_document(reader);
}

#[test]
fn test_decode_optional_full_string() {
    let mut reader = start_document(
        "<root>  This is <![CDATA[ Test ]]> of it 4   </root>",
        "root",
    );
    assert_eq!(
        decode_optional_string(&mut reader, OwnedName::local("root"), vec![]).expect("Failed parsing"),
        Some(String::from("  This is  Test  of it 4   "))
    );
    end_document(reader);
}

#[test]
fn test_decode_optional_empty_base64() {
    let mut reader = start_document("<root/>", "root");
    assert_eq!(
        decode_optional_base64(&mut reader, OwnedName::local("root"), vec![]).expect("Failed parsing"),
        None
    );
    end_document(reader);
}

#[test]
fn test_decode_optional_valid_base64() {
    let mut reader = start_document("<root>/u3erb7vyv4=</root>", "root");
    assert_eq!(
        decode_optional_base64(&mut reader, OwnedName::local("root"), vec![]).expect("Failed parsing"),
        Some(
            [0xfeu8, 0xed, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe]
                .as_ref()
                .to_owned()
        )
    );
    end_document(reader);
}

// TODO Test malformed base64

#[test]
fn test_encode_optional_empty_base64() {
    let buffer = vec![];
    let mut writer = xml::writer::EmitterConfig::new()
        .write_document_declaration(false)
        .normalize_empty_elements(true)
        .cdata_to_characters(true)
        .pad_self_closing(false)
        .create_writer(buffer);
    writer
        .write(xml::writer::XmlEvent::start_element("root"))
        .expect("Failed to write start tag!");
    encode_optional_base64::<_, &[u8]>(&mut writer, None).expect("Writing value");
    writer
        .write(xml::writer::XmlEvent::end_element())
        .expect("Failed to write end tag!");
    let doc = writer.into_inner();
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(actual, "<root/>");

    let buffer = vec![];
    let mut writer = xml::writer::EmitterConfig::new()
        .write_document_declaration(false)
        .normalize_empty_elements(true)
        .cdata_to_characters(true)
        .pad_self_closing(false)
        .create_writer(buffer);
    writer
        .write(xml::writer::XmlEvent::start_element("root"))
        .expect("Failed to write start tag!");
    encode_optional_base64(&mut writer, Some(vec![])).expect("Writing value");
    writer
        .write(xml::writer::XmlEvent::end_element())
        .expect("Failed to write end tag!");
    let doc = writer.into_inner();
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    //assert_eq!(actual, "<root/>");  // TODO This should be normalized
    assert_eq!(actual, "<root></root>");
}

#[test]
fn test_encode_optional_valid_base64() {
    let buffer = vec![];
    let mut writer = xml::writer::EmitterConfig::new()
        .write_document_declaration(false)
        .normalize_empty_elements(true)
        .cdata_to_characters(true)
        .pad_self_closing(false)
        .create_writer(buffer);
    writer
        .write(xml::writer::XmlEvent::start_element("root"))
        .expect("Failed to write start tag!");
    encode_optional_base64(
        &mut writer,
        Some([0xfeu8, 0xed, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe]),
    )
    .expect("Writing value");
    writer
        .write(xml::writer::XmlEvent::end_element())
        .expect("Failed to write end tag!");
    let doc = writer.into_inner();
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(actual, "<root>/u3erb7vyv4=</root>");
}

#[test]
fn test_decode_empty_base64() {
    let mut reader = start_document("<root/>", "root");
    assert_eq!(
        decode_base64(&mut reader, OwnedName::local("root"), vec![]).expect("Failed parsing"),
        vec![]
    );
    end_document(reader);
}

#[test]
fn test_decode_valid_base64() {
    let mut reader = start_document("<root>/u3erb7vyv4=</root>", "root");
    assert_eq!(
        decode_base64(&mut reader, OwnedName::local("root"), vec![]).expect("Failed parsing"),
        [0xfeu8, 0xed, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe]
            .as_ref()
            .to_owned()
    );
    end_document(reader);
}

#[test]
fn test_encode_empty_base64() {
    let buffer = vec![];
    let mut writer = xml::writer::EmitterConfig::new()
        .write_document_declaration(false)
        .normalize_empty_elements(true)
        .cdata_to_characters(true)
        .pad_self_closing(false)
        .create_writer(buffer);
    writer
        .write(xml::writer::XmlEvent::start_element("root"))
        .expect("Failed to write start tag!");
    encode_base64(&mut writer, vec![]).expect("Writing value");
    writer
        .write(xml::writer::XmlEvent::end_element())
        .expect("Failed to write end tag!");
    let doc = writer.into_inner();
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    //assert_eq!(actual, "<root/>");  // TODO This should be normalized
    assert_eq!(actual, "<root></root>");
}

#[test]
fn test_encode_valid_base64() {
    let buffer = vec![];
    let mut writer = xml::writer::EmitterConfig::new()
        .write_document_declaration(false)
        .normalize_empty_elements(true)
        .cdata_to_characters(true)
        .pad_self_closing(false)
        .create_writer(buffer);
    writer
        .write(xml::writer::XmlEvent::start_element("root"))
        .expect("Failed to write start tag!");
    encode_base64(
        &mut writer,
        [0xfeu8, 0xed, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe],
    )
    .expect("Writing value");
    writer
        .write(xml::writer::XmlEvent::end_element())
        .expect("Failed to write end tag!");
    let doc = writer.into_inner();
    let actual = std::str::from_utf8(&doc).expect("Valid UTF-8");
    assert_eq!(actual, "<root>/u3erb7vyv4=</root>");
}

#[test]
fn test_decode_memory_protection_empty() {
    let mut reader = start_document("<MemoryProtection/>", "MemoryProtection");
    //assert_eq!(MemoryProtection::parse(&mut reader).expect("Failed parsing"), Some(String::from("  This is  Test  of it 4   ")));
    let mp = MemoryProtection::parse(
        &mut reader,
        OwnedName::local("MemoryProtection"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Failed parsing")
    .unwrap();
    end_document(reader);
    assert_eq!(mp.protect_notes, false);
    assert_eq!(mp.protect_password, false);
    assert_eq!(mp.protect_title, false);
    assert_eq!(mp.protect_url, false);
    assert_eq!(mp.protect_user_name, false);
}

#[test]
fn test_decode_memory_protection_some() {
    let mut reader = start_document(
        r#"		<MemoryProtection>
    <ProtectTitle>False</ProtectTitle>
    <ProtectUserName>False</ProtectUserName>
    <ProtectPassword>True</ProtectPassword>
    <ProtectURL>False</ProtectURL>
    <ProtectNotes>False</ProtectNotes>
</MemoryProtection>
"#,
        "MemoryProtection",
    );
    let mp = MemoryProtection::parse(
        &mut reader,
        OwnedName::local("MemoryProtection"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Failed parsing")
    .unwrap();
    end_document(reader);
    assert_eq!(mp.protect_notes, false);
    assert_eq!(mp.protect_password, true);
    assert_eq!(mp.protect_title, false);
    assert_eq!(mp.protect_url, false);
    assert_eq!(mp.protect_user_name, false);
}

#[test]
fn test_decode_memory_protection_all() {
    let mut reader = start_document(
        r#"		<MemoryProtection>
    <ProtectTitle>True</ProtectTitle>
    <ProtectUserName>True</ProtectUserName>
    <ProtectPassword>True</ProtectPassword>
    <ProtectURL>True</ProtectURL>
    <ProtectNotes>True</ProtectNotes>
</MemoryProtection>
"#,
        "MemoryProtection",
    );
    let mp = MemoryProtection::parse(
        &mut reader,
        OwnedName::local("MemoryProtection"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Failed parsing")
    .unwrap();
    end_document(reader);
    assert_eq!(mp.protect_notes, true);
    assert_eq!(mp.protect_password, true);
    assert_eq!(mp.protect_title, true);
    assert_eq!(mp.protect_url, true);
    assert_eq!(mp.protect_user_name, true);
}

fn write_kdbx_document<K: KdbxSerialize<KdbxContext> + Clone>(expected: &K) -> Vec<u8> {
    write_kdbx_document_with_context(expected, &mut KdbxContext::default())
}

fn write_kdbx_document_with_context<K: KdbxSerialize<C> + Clone, C>(expected: &K, context: &mut C) -> Vec<u8> {
    let buffer = vec![];
    let mut writer = xml::writer::EmitterConfig::new()
        .write_document_declaration(false)
        .normalize_empty_elements(true)
        .cdata_to_characters(true)
        .pad_self_closing(false)
        .create_writer(buffer);
    writer
        .write(xml::writer::XmlEvent::start_element(
            std::any::type_name::<K>().rsplit(":").nth(0).unwrap(),
        ))
        .expect("Success!");
    K::serialize2(&mut writer, expected.clone(), context).expect("Failed serializing");
    writer
        .write(xml::writer::XmlEvent::end_element())
        .expect("Success!");
    writer.into_inner()
}

#[test]
fn test_encode_memory_protection_all() {
    let buffer = write_kdbx_document(&MemoryProtection {
        protect_notes: true,
        protect_password: true,
        protect_title: true,
        protect_url: true,
        protect_user_name: true,
    });
    let mut reader = ParserConfig::new().create_reader(Cursor::new(buffer));
    match reader.next().unwrap() {
        XmlEvent::StartDocument { .. } => {}
        _ => {
            panic!("Missing document start");
        }
    };
    let root = "MemoryProtection";
    match reader.next().unwrap() {
        XmlEvent::StartElement { name, .. } => {
            assert_eq!(name.local_name, root);
        }
        _ => {
            panic!("Missing root element start");
        }
    }
    let mp = MemoryProtection::parse(
        &mut reader,
        OwnedName::local("MemoryProtection"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Failed parsing")
    .unwrap();
    //end_document(reader);
    assert_eq!(mp.protect_notes, true);
    assert_eq!(mp.protect_password, true);
    assert_eq!(mp.protect_title, true);
    assert_eq!(mp.protect_url, true);
    assert_eq!(mp.protect_user_name, true);
}

#[test]
fn test_decode_item_empty() {
    let mut reader = start_document("<Item/>", "Item");
    let item = decode_item(&mut reader, OwnedName::local("Item"), vec![]).expect("Failed parsing");
    end_document(reader);
    assert_eq!(item.0, "");
    assert_eq!(item.1, "");
}

#[test]
fn test_decode_item_pair() {
    let mut reader = start_document(
        "  <Item>  <Value>mexican</Value>  <Key>food</Key>   </Item>  ",
        "Item",
    );
    let result = decode_item(&mut reader, OwnedName::local("Item"), vec![]);
    if result.is_err() {
        assert!(false, "Decoding returned error: {:?}", result.unwrap_err());
    }
    let item = result.unwrap();
    end_document(reader);
    assert_eq!(item.0, "food");
    assert_eq!(item.1, "mexican");
}

#[test]
fn test_decode_custom_data_empty() {
    let mut reader = start_document("<CustomData/>", "CustomData");
    let custom_data =
        decode_custom_data(&mut reader, OwnedName::local("CustomData"), vec![]).expect("Failed parsing");
    end_document(reader);
    assert_eq!(custom_data.len(), 0);
}

#[test]
fn test_decode_custom_data_simple() {
    let mut reader = start_document(
        "<CustomData><Item><Key>one</Key><Value>1</Value></Item></CustomData>",
        "CustomData",
    );
    let custom_data =
        decode_custom_data(&mut reader, OwnedName::local("CustomData"), vec![]).expect("Failed parsing");
    end_document(reader);
    assert_eq!(custom_data.len(), 1);
    assert!(custom_data.contains_key("one"), "Has appropriate key");
    assert_eq!(custom_data["one"], "1");
}

#[derive(Clone, Default, KdbxParse, KdbxSerialize)]
struct ColorTest {
    field: Color,
}

#[test]
fn test_decode_color_empty() {
    let actual: ColorTest = parse_document("<ColorTest><Field/></ColorTest>");
    assert_eq!(actual.field.red, 0);
    assert_eq!(actual.field.green, 0);
    assert_eq!(actual.field.blue, 0);
}

#[test]
fn test_decode_color_filled() {
    let actual: ColorTest = parse_document("<ColorTest><Field>#80FF0F</Field></ColorTest>");
    assert_eq!(actual.field.red, 128);
    assert_eq!(actual.field.green, 255);
    assert_eq!(actual.field.blue, 15);
}

#[test]
fn test_encode_color_empty() {
    let actual = serialize_document(&ColorTest {
        field: Color::default(),
    });
    assert_eq!(actual, "<ColorTest><Field>#000000</Field></ColorTest>");
}

#[test]
fn test_encode_color_filled() {
    let actual = serialize_document(&ColorTest {
        field: Color { red: 128, green: 255, blue: 15 },
    });
    assert_eq!(actual, "<ColorTest><Field>#80FF0F</Field></ColorTest>");
}

#[derive(Clone, Default, KdbxParse, KdbxSerialize)]
struct OptionColorTest {
    field: Option<Color>,
}

#[test]
fn test_decode_optional_color_empty() {
    let actual: OptionColorTest = parse_document("<OptionColorTest/>");
    assert_eq!(actual.field, None);
}

#[test]
fn test_decode_optional_color_filled() {
    let actual: OptionColorTest = parse_document("<OptionColorTest><Field>#80FF0F</Field></OptionColorTest>");
    assert!(actual.field.is_some());
    let field = actual.field.unwrap();
    assert_eq!(field.red, 128);
    assert_eq!(field.green, 255);
    assert_eq!(field.blue, 15);
}

#[test]
fn test_encode_optional_color_empty() {
    let actual = serialize_document(&OptionColorTest {
        field: None,
    });
    assert_eq!(actual, "<OptionColorTest/>");
}

#[test]
fn test_encode_optional_color_filled() {
    let actual = serialize_document(&OptionColorTest {
        field: Some(Color { red: 128, green: 255, blue: 15 }),
    });
    assert_eq!(actual, "<OptionColorTest><Field>#80FF0F</Field></OptionColorTest>");
}

#[derive(Clone, Default, KdbxParse, KdbxSerialize)]
struct TagsTest {
    field: Tags,
}

#[test]
fn test_decode_tags_empty() {
    let actual: TagsTest = parse_document("<TagsTest><Field/></TagsTest>");
    assert!(actual.field.tags.is_empty());
    assert_eq!(actual.field.tags.len(), 0);
}

#[test]
fn test_decode_tags_filled() {
    let actual: TagsTest = parse_document("<TagsTest><Field>alpha;omega;gamma</Field></TagsTest>");
    assert_eq!(actual.field.tags.len(), 3);
    assert!(actual.field.tags.contains("alpha"));
    assert!(actual.field.tags.contains("gamma"));
    assert!(actual.field.tags.contains("omega"));
}

#[test]
fn test_encode_tags_empty() {
    let actual = serialize_document(&TagsTest {
        field: Tags::default(),
    });
    assert_eq!(actual, "<TagsTest><Field></Field></TagsTest>");
}

#[test]
fn test_encode_tags_filled() {
    let mut set = BTreeSet::new();
    set.insert("omega".to_string());
    set.insert("alpha".to_string());
    set.insert("gamma".to_string());
    let actual = serialize_document(&TagsTest {
        field: Tags { tags: set },
    });
    assert_eq!(actual, "<TagsTest><Field>alpha;gamma;omega</Field></TagsTest>");
}

#[derive(Clone, Default, KdbxParse, KdbxSerialize)]
struct OptionTagsTest {
    field: Option<Tags>,
}

#[test]
fn test_decode_optional_tags_empty() {
    let actual: OptionTagsTest = parse_document("<OptionTagsTest/>");
    assert_eq!(actual.field, None);
}

#[test]
fn test_decode_optional_tags_filled() {
    let actual: OptionTagsTest = parse_document("<OptionTagsTest><Field>alpha;omega;gamma</Field></OptionTagsTest>");
    assert!(actual.field.is_some());
    let field = actual.field.unwrap();
    assert_eq!(field.tags.len(), 3);
    assert!(field.tags.contains("alpha"));
    assert!(field.tags.contains("gamma"));
    assert!(field.tags.contains("omega"));
}

#[test]
fn test_encode_optional_tags_empty() {
    let actual = serialize_document(&OptionTagsTest {
        field: None,
    });
    assert_eq!(actual, "<OptionTagsTest/>");
}

#[test]
fn test_encode_optional_tags_filled() {
    let mut set = BTreeSet::new();
    set.insert("omega".to_string());
    set.insert("alpha".to_string());
    set.insert("gamma".to_string());
    let actual = serialize_document(&OptionTagsTest {
        field: Some(Tags { tags: set }),
    });
    assert_eq!(actual, "<OptionTagsTest><Field>alpha;gamma;omega</Field></OptionTagsTest>");
}

#[test]
fn test_decode_meta_empty() {
    let mut reader = start_document("<Meta/>", "Meta");
    let meta = Meta::parse(
        &mut reader,
        OwnedName::local("Meta"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Failed parsing")
    .unwrap();
    end_document(reader);
    assert_eq!(meta.database_name, "");
    assert_eq!(meta.default_user_name, "");
    assert_eq!(meta.memory_protection.protect_notes, false);
    assert_eq!(meta.memory_protection.protect_password, false);
    assert_eq!(meta.memory_protection.protect_title, false);
    assert_eq!(meta.memory_protection.protect_url, false);
    assert_eq!(meta.memory_protection.protect_user_name, false);
}

#[test]
#[ignore = "CustomData assertions are broken and commented out"]
fn test_decode_meta_filled() {
    let mut reader = start_document(
        r#"
    <Meta>
    <Generator>KeePassXC</Generator>
    <DatabaseName>Dummy</DatabaseName>
    <DatabaseNameChanged>3BmO1Q4AAAA=</DatabaseNameChanged>
    <DatabaseDescription>Empty KDBX 4.x Database</DatabaseDescription>
    <DatabaseDescriptionChanged>3BmO1Q4AAAA=</DatabaseDescriptionChanged>
    <DefaultUserName>someone</DefaultUserName>
    <DefaultUserNameChanged>I6fN1Q4AAAA=</DefaultUserNameChanged>
    <MaintenanceHistoryDays>365</MaintenanceHistoryDays>
    <Color/>
    <MasterKeyChanged>4xqO1Q4AAAA=</MasterKeyChanged>
    <MasterKeyChangeRec>-1</MasterKeyChangeRec>
    <MasterKeyChangeForce>-1</MasterKeyChangeForce>
    <MemoryProtection>
        <ProtectTitle>False</ProtectTitle>
        <ProtectUserName>False</ProtectUserName>
        <ProtectPassword>True</ProtectPassword>
        <ProtectURL>False</ProtectURL>
        <ProtectNotes>False</ProtectNotes>
    </MemoryProtection>
    <CustomIcons/>
    <RecycleBinEnabled>True</RecycleBinEnabled>
    <RecycleBinUUID>AAAAAAAAAAAAAAAAAAAAAA==</RecycleBinUUID>
    <RecycleBinChanged>zRmO1Q4AAAA=</RecycleBinChanged>
    <EntryTemplatesGroup>AAAAAAAAAAAAAAAAAAAAAA==</EntryTemplatesGroup>
    <EntryTemplatesGroupChanged>zRmO1Q4AAAA=</EntryTemplatesGroupChanged>
    <LastSelectedGroup>AAAAAAAAAAAAAAAAAAAAAA==</LastSelectedGroup>
    <LastTopVisibleGroup>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleGroup>
    <HistoryMaxItems>10</HistoryMaxItems>
    <HistoryMaxSize>6291456</HistoryMaxSize>
    <SettingsChanged>I6fN1Q4AAAA=</SettingsChanged>
    <CustomData>
        <Item>
            <Key>FDO_SECRETS_EXPOSED_GROUP</Key>
            <Value>{00000000-0000-0000-0000-000000000000}</Value>
        </Item>
        <Item>
            <Key>KPXC_DECRYPTION_TIME_PREFERENCE</Key>
            <Value>100</Value>
        </Item>
        <Item>
            <Key>_LAST_MODIFIED</Key>
            <Value>Thu Feb 6 06:08:06 2020 GMT</Value>
        </Item>
    </CustomData>
</Meta>
"#,
        "Meta",
    );
    let meta = Meta::parse(
        &mut reader,
        OwnedName::local("Meta"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Failed parsing")
    .unwrap();
    end_document(reader);
    assert_eq!(meta.database_name, "Dummy");
    assert_eq!(meta.default_user_name, "someone");
    assert_eq!(meta.memory_protection.protect_notes, false);
    assert_eq!(meta.memory_protection.protect_password, true);
    assert_eq!(meta.memory_protection.protect_title, false);
    assert_eq!(meta.memory_protection.protect_url, false);
    assert_eq!(meta.memory_protection.protect_user_name, false);
    assert_eq!(
        meta.custom_data.len(),
        3,
        "Correct number of custom data fields"
    );
//    assert!(
//        meta.custom_data
//            .contains_key("KPXC_DECRYPTION_TIME_PREFERENCE"),
//        "Missing a custom data field"
//    );
//    assert_eq!(
//        meta.custom_data["KPXC_DECRYPTION_TIME_PREFERENCE"], "100",
//        "Custom data field has wrong value"
//    );
}

#[test]
fn test_decode_times_filled() {
    let mut reader = start_document(
        r#"
        <Times>
            <CreationTime>lmaW2A4AAAA=</CreationTime>
            <LastModificationTime>/HOW2A4AAAA=</LastModificationTime>
            <LastAccessTime>anqW2A4AAAA=</LastAccessTime>
            <ExpiryTime>PGmW2A4AAAA=</ExpiryTime>
            <Expires>True</Expires>
            <UsageCount>56</UsageCount>
            <LocationChanged>cOQO2Q4AAAA=</LocationChanged>
        </Times>
    "#,
        "Times",
    );
    let times = Times::parse(
        &mut reader,
        OwnedName::local("Times"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Failed parsing")
    .unwrap();
    end_document(reader);
    assert_eq!(
        times.last_modification_time,
        DateTime::parse_from_rfc3339("2021-07-30T15:28:12-07:00").unwrap()
    );
    assert_eq!(
        times.creation_time,
        DateTime::parse_from_rfc3339("2021-07-30T14:31:02-07:00").unwrap()
    );
    assert_eq!(
        times.last_access_time,
        DateTime::parse_from_rfc3339("2021-07-30T15:55:38-07:00").unwrap()
    );
    assert_eq!(
        times.expiry_time,
        DateTime::parse_from_rfc3339("2021-07-30T14:42:20-07:00").unwrap()
    );
    assert_eq!(times.expires, true);
    assert_eq!(times.usage_count, 56);
    assert_eq!(
        times.location_changed,
        DateTime::parse_from_rfc3339("2021-10-30T00:00:00-07:00").unwrap()
    );
}

#[test]
fn test_encode_times_filled() {
    let expected = Times {
        last_modification_time: DateTime::parse_from_rfc3339("2021-07-30T15:28:12-07:00")
            .unwrap()
            .with_timezone(&Utc),
        creation_time: DateTime::parse_from_rfc3339("2021-07-30T14:31:02-07:00")
            .unwrap()
            .with_timezone(&Utc),
        last_access_time: DateTime::parse_from_rfc3339("2021-07-30T15:55:38-07:00")
            .unwrap()
            .with_timezone(&Utc),
        expiry_time: DateTime::parse_from_rfc3339("2021-07-30T14:42:20-07:00")
            .unwrap()
            .with_timezone(&Utc),
        expires: true,
        usage_count: 56,
        location_changed: DateTime::parse_from_rfc3339("2021-10-30T00:00:00-07:00")
            .unwrap()
            .with_timezone(&Utc),
    };
    let contents = write_kdbx_document(&expected);
    let mut reader = start_document(&contents, "Times");
    let actual = Times::parse(
        &mut reader,
        OwnedName::local("Times"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Failed parsing")
    .unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn test_decode_entry_empty() {
    let mut reader = start_document("<Entry/>", "Entry");
    let entry = Entry::parse(
        &mut reader,
        OwnedName::local("Entry"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Failed parsing")
    .unwrap();
    end_document(reader);
    assert_eq!(entry.uuid, Uuid::nil());
    assert_eq!(entry.icon_id, 0);
    assert_eq!(entry.history, None);
}

#[test]
fn test_decode_entry_filled() {
    let mut reader = start_document(
        r#"
    <Entry>
            <UUID>g9fGIDnSR8WvjPBJ/L4juA==</UUID>
            <IconID>12</IconID>
            <History>
                    <Entry>
                        <UUID>g9fGIDnSR8WvjPBJ/L4juA==</UUID>
                        <IconID>7</IconID>
                    </Entry>
                    <Entry>
                        <UUID>g9fGIDnSR8WvjPBJ/L4juA==</UUID>
                        <IconID>25</IconID>
                    </Entry>
            </History>
    </Entry>
    "#,
        "Entry",
    );
    let entry = Entry::parse(
        &mut reader,
        OwnedName::local("Entry"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Failed parsing")
    .unwrap();
    end_document(reader);
    let expected_uuid = uuid!("83d7c620-39d2-47c5-af8c-f049fcbe23b8");
    assert_eq!(entry.uuid, expected_uuid);
    assert_eq!(entry.icon_id, 12);
    let history = entry.history.unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].uuid, expected_uuid);
    assert_eq!(history[0].icon_id, 7);
    assert_eq!(history[1].uuid, expected_uuid);
    assert_eq!(history[1].icon_id, 25);
}

#[test]
fn test_encode_entry_filled() {
    let mut reader = start_document(
        r#"
    <Entry>
            <UUID>g9fGIDnSR8WvjPBJ/L4juA==</UUID>
            <IconID>12</IconID>
            <History>
                    <Entry>
                        <UUID>g9fGIDnSR8WvjPBJ/L4juA==</UUID>
                        <IconID>7</IconID>
                    </Entry>
                    <Entry>
                        <UUID>g9fGIDnSR8WvjPBJ/L4juA==</UUID>
                        <IconID>25</IconID>
                    </Entry>
            </History>
    </Entry>
    "#,
        "Entry",
    );
    let actual = Entry::parse(
        &mut reader,
        OwnedName::local("Entry"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Failed parsing")
    .unwrap();
    end_document(reader);

    let buffer = write_kdbx_document(&actual);
    //    Entry {
    //        protect_notes: true,
    //        protect_password: true,
    //        protect_title: true,
    //        protect_url: true,
    //        protect_user_name: true,
    //    }).expect("Failed parsing");
    let mut reader = ParserConfig::new().create_reader(Cursor::new(buffer));
    match reader.next().unwrap() {
        XmlEvent::StartDocument { .. } => {}
        _ => {
            panic!("Missing document start");
        }
    };
    let root = "Entry";
    match reader.next().unwrap() {
        XmlEvent::StartElement { name, .. } => {
            assert_eq!(name.local_name, root);
        }
        _ => {
            panic!("Missing root element start");
        }
    }
    let entry = Entry::parse(
        &mut reader,
        OwnedName::local("Entry"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Failed parsing")
    .unwrap();

    let expected_uuid = uuid!("83d7c620-39d2-47c5-af8c-f049fcbe23b8");
    assert_eq!(entry.uuid, expected_uuid);
    assert_eq!(entry.icon_id, 12);
    let history = entry.history.unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].uuid, expected_uuid);
    assert_eq!(history[0].icon_id, 7);
    assert_eq!(history[1].uuid, expected_uuid);
    assert_eq!(history[1].icon_id, 25);
}

#[test]
fn test_decode_document_empty() {
    let mut reader = start_document("<KeePassFile/>", "KeePassFile");
    let document = KeePassFile::parse(
        &mut reader,
        OwnedName::local("KeePassFile"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Failed parsing")
    .unwrap();
    end_document(reader);
    assert_eq!(document.meta.database_name, "");
    assert_eq!(document.meta.default_user_name, "");
    assert_eq!(document.meta.memory_protection.protect_notes, false);
    assert_eq!(document.meta.memory_protection.protect_password, false);
    assert_eq!(document.meta.memory_protection.protect_title, false);
    assert_eq!(document.meta.memory_protection.protect_url, false);
    assert_eq!(document.meta.memory_protection.protect_user_name, false);
}

#[test]
fn test_encode_document_empty() {
    let expected = KeePassFile::default();
    let buffer = vec![];
    let mut writer = xml::writer::EventWriter::new(buffer);
    writer
        .write(xml::writer::XmlEvent::start_element("KeePassFile"))
        .expect("Success!");
    KeePassFile::serialize2(&mut writer, expected, &mut KdbxContext::default()).expect("Failed serializing");
    writer
        .write(xml::writer::XmlEvent::end_element())
        .expect("Success!");
    let buffer = writer.into_inner();
    let mut reader = ParserConfig::new().create_reader(Cursor::new(buffer));
    match reader.next().unwrap() {
        XmlEvent::StartDocument { .. } => {}
        _ => {
            panic!("Missing document start");
        }
    };
    let root = "KeePassFile";
    match reader.next().unwrap() {
        XmlEvent::StartElement { name, .. } => {
            assert_eq!(name.local_name, root);
        }
        _ => {
            panic!("Missing root element start");
        }
    }
    let actual = KeePassFile::parse(
        &mut reader,
        OwnedName::local("KeePassFile"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Failed parsing")
    .unwrap();
    assert_eq!(actual.meta.database_name, "");
    assert_eq!(actual.meta.default_user_name, "");
    assert_eq!(actual.meta.memory_protection.protect_notes, false);
    assert_eq!(actual.meta.memory_protection.protect_password, false);
    assert_eq!(actual.meta.memory_protection.protect_title, false);
    assert_eq!(actual.meta.memory_protection.protect_url, false);
    assert_eq!(actual.meta.memory_protection.protect_user_name, false);
}

#[test]
#[ignore = "CustomData assertions are broken and commented out"]
fn test_decode_document_filled() {
    // let mut file = File::open("dummy.xml").expect("Missing test data dummy.xml");
    // let mut contents = Vec::new();
    // let mut Cursor::new(contents);
    // file.read_to_end(&mut contents);
    let contents = include_str!("../testdata/dummy.xml");
    let mut reader = start_document(contents, "KeePassFile");
    let document = KeePassFile::parse(
        &mut reader,
        OwnedName::local("KeePassFile"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Failed parsing")
    .unwrap();
    end_document(reader);
    assert_eq!(document.meta.database_name, "Dummy");
    assert_eq!(document.meta.default_user_name, "someone");
    assert_eq!(document.meta.memory_protection.protect_notes, false);
    assert_eq!(document.meta.memory_protection.protect_password, true);
    assert_eq!(document.meta.memory_protection.protect_title, false);
    assert_eq!(document.meta.memory_protection.protect_url, false);
    assert_eq!(document.meta.memory_protection.protect_user_name, false);
    assert_eq!(
        document.meta.custom_data.len(),
        3,
        "Correct number of custom data fields"
    );
//    assert!(
//        document
//            .meta
//            .custom_data
//            .contains_key("KPXC_DECRYPTION_TIME_PREFERENCE"),
//        "Missing a custom data field"
//    );
//    assert_eq!(
//        document.meta.custom_data["KPXC_DECRYPTION_TIME_PREFERENCE"], "100",
//        "Custom data field has wrong value"
//    );
}

#[test]
fn test_encode_document_filled() {
    let mut expected = KeePassFile::default();
    expected.meta.database_name = "Dummy".to_string();
    expected.meta.default_user_name = "Someone".to_string();
    expected.meta.memory_protection.protect_notes = true;
    expected.meta.memory_protection.protect_password = true;
    expected.meta.memory_protection.protect_title = true;
    expected.meta.memory_protection.protect_url = true;
    expected.meta.memory_protection.protect_user_name = true;
    let buffer = vec![];
    let mut writer = xml::writer::EventWriter::new(buffer);
    writer
        .write(xml::writer::XmlEvent::start_element("KeePassFile"))
        .expect("Success!");
    KeePassFile::serialize2(&mut writer, expected, &mut KdbxContext::default()).expect("Failed serializing");
    writer
        .write(xml::writer::XmlEvent::end_element())
        .expect("Success!");
    let buffer = writer.into_inner();
    let mut reader = ParserConfig::new().create_reader(Cursor::new(buffer));
    match reader.next().unwrap() {
        XmlEvent::StartDocument { .. } => {}
        _ => {
            panic!("Missing document start");
        }
    };
    let root = "KeePassFile";
    match reader.next().unwrap() {
        XmlEvent::StartElement { name, .. } => {
            assert_eq!(name.local_name, root);
        }
        _ => {
            panic!("Missing root element start");
        }
    }
    let actual = KeePassFile::parse(
        &mut reader,
        OwnedName::local("KeePassFile"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Failed parsing")
    .unwrap();
    assert_eq!(actual.meta.database_name, "Dummy");
    assert_eq!(actual.meta.default_user_name, "Someone");
    assert_eq!(actual.meta.memory_protection.protect_notes, true);
    assert_eq!(actual.meta.memory_protection.protect_password, true);
    assert_eq!(actual.meta.memory_protection.protect_title, true);
    assert_eq!(actual.meta.memory_protection.protect_url, true);
    assert_eq!(actual.meta.memory_protection.protect_user_name, true);
}

#[test]
fn test_decode_document_kdbx41() {
    // let mut file = File::open("dummy.xml").expect("Missing test data dummy.xml");
    // let mut contents = Vec::new();
    // let mut Cursor::new(contents);
    // file.read_to_end(&mut contents);
    let contents = include_str!("../testdata/dummy-kdbx41.xml");
    let mut reader = start_document(contents, "KeePassFile");
    let document = KeePassFile::parse(
        &mut reader,
        OwnedName::local("KeePassFile"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Failed parsing")
    .unwrap();
    end_document(reader);
    assert_eq!(document.meta.generator, "KeePass");
    assert_eq!(document.meta.database_name, "MyDatabase");
    assert_eq!(
        document.meta.database_name_changed,
        Some(
            DateTime::parse_from_rfc3339("2021-07-30T21:33:09+00:00")
                .unwrap()
                .with_timezone(&Utc)
        )
    );
    assert_eq!(
        document.meta.database_description,
        "A KDBX 4.1 Database from KeePass 2.48.1."
    );
    assert_eq!(
        document.meta.database_description_changed,
        Some(
            DateTime::parse_from_rfc3339("2021-07-30T21:33:09+00:00")
                .unwrap()
                .with_timezone(&Utc)
        )
    );
    assert_eq!(document.meta.default_user_name, "user");
    assert_eq!(
        document.meta.default_user_name_changed,
        Some(
            DateTime::parse_from_rfc3339("2021-07-30T21:33:09+00:00")
                .unwrap()
                .with_timezone(&Utc)
        )
    );
    assert_eq!(document.meta.maintenance_history_days, 365);
    //assert_eq!(document.meta.color, Color::rgb(0xFF, 0x00, 0x3F));
    assert_eq!(
        document.meta.master_key_changed,
        Some(
            DateTime::parse_from_rfc3339("2021-07-31T00:02:45+00:00")
                .unwrap()
                .with_timezone(&Utc)
        )
    );
    assert_eq!(document.meta.master_key_change_rec, 182);
    assert_eq!(document.meta.master_key_change_force, 365);
    assert_eq!(document.meta.memory_protection.protect_notes, false);
    assert_eq!(document.meta.memory_protection.protect_password, true);
    assert_eq!(document.meta.memory_protection.protect_title, false);
    assert_eq!(document.meta.memory_protection.protect_url, false);
    assert_eq!(document.meta.memory_protection.protect_user_name, false);
    assert_eq!(
        document.meta.settings_changed,
        Some(
            DateTime::parse_from_rfc3339("2021-07-31T00:03:06+00:00")
                .unwrap()
                .with_timezone(&Utc)
        )
    );
    assert_eq!(
        document.meta.custom_data.len(),
        0,
        "Correct number of custom data fields"
    );
    // <CustomIcons>
    //     <Icon>
    //         <UUID>abfkJtfYxkaUtH41POXBww==</UUID>
    //         <Data>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</Data>
    //     </Icon>
    // </CustomIcons>
    // <RecycleBinEnabled>True</RecycleBinEnabled>
    // <RecycleBinUUID>jhrLg94DAkieJE8L64Mhsw==</RecycleBinUUID>
    // <RecycleBinChanged>lmaW2A4AAAA=</RecycleBinChanged>
    // <EntryTemplatesGroup>orPZQak4Aku0L67SCKGjOA==</EntryTemplatesGroup>
    // <EntryTemplatesGroupChanged>YXWW2A4AAAA=</EntryTemplatesGroupChanged>
    // <HistoryMaxItems>10</HistoryMaxItems>
    // <HistoryMaxSize>6291456</HistoryMaxSize>
    // <LastSelectedGroup>L/aVHMsHiESAi+PBE3bfuQ==</LastSelectedGroup>
    // <LastTopVisibleGroup>YROF9wRy0EylaPcWGFS+zQ==</LastTopVisibleGroup>
}

/*
use super::Cursor;
use super::{EventReader, XmlEvent};

#[test]
fn test_basic_document() {
    let mut cursor = Cursor::new(b"");
    let mut reader = EventReader::new(cursor);
    match reader.next().unwrap() {
        XmlEvent::StartDocument { .. } => (),
        _ => { panic!("Bad state"); },
    };
    match reader.next().unwrap() {
        XmlEvent::StartDocument { .. } => (),
        _ => { panic!("Bad state"); },
    };
}
*/

#[test]
fn test_decode_document_filled_contents() {
    let contents = include_str!("../testdata/dummy.xml");
    let mut reader = start_document(contents, "KeePassFile");
    let document = KeePassFile::parse(
        &mut reader,
        OwnedName::local("KeePassFile"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Failed parsing")
    .unwrap();
    end_document(reader);
    //assert_eq!(document.meta.database_name, "Dummy");
    //assert_eq!(document.meta.default_user_name, "someone");
    //assert_eq!(document.meta.memory_protection.protect_notes, false);
    //assert_eq!(document.meta.memory_protection.protect_password, true);
    //assert_eq!(document.meta.memory_protection.protect_title, false);
    //assert_eq!(document.meta.memory_protection.protect_url, false);
    //assert_eq!(document.meta.memory_protection.protect_user_name, false);
    //assert_eq!(document.meta.custom_data.len(), 3, "Correct number of custom data fields");
    //assert!(document.meta.custom_data.contains_key("KPXC_DECRYPTION_TIME_PREFERENCE"), "Missing a custom data field");
    //assert_eq!(document.meta.custom_data["KPXC_DECRYPTION_TIME_PREFERENCE"], "100", "Custom data field has wrong value");
    assert_eq!(document.root.group.entry.len(), 0);
    assert_eq!(document.root.group.group.len(), 1);
    assert_eq!(document.root.group.group[0].entry.len(), 1);
    assert_eq!(
        document.root.group.group[0].entry[0]
            .history
            .as_ref()
            .unwrap()
            .len(),
        2,
        "{:#?}",
        document.root.group.group[0].entry[0].history
    );
    assert_eq!(document.root.group.group[0].group.len(), 2);
    assert_eq!(document.root.group.group[0].group[0].entry.len(), 1);
    assert_eq!(
        document.root.group.group[0].group[0].entry[0]
            .history
            .as_ref()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(document.root.group.group[0].group[0].group.len(), 1);
    assert_eq!(document.root.group.group[0].group[0].group[0].entry.len(), 1);
    assert_eq!(
        document.root.group.group[0].group[0].group[0].entry[0]
            .history
            .as_ref()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(document.root.group.group[0].group[0].group[0].group.len(), 0);
    assert_eq!(document.root.group.group[0].group[1].entry.len(), 0);
    assert_eq!(document.root.group.group[0].group[1].group.len(), 0);
}

#[test]
fn test_decode_document_filled_group() {
    let contents = include_str!("../testdata/dummy.xml");
    let mut reader = start_document(contents, "KeePassFile");
    let document = KeePassFile::parse(
        &mut reader,
        OwnedName::local("KeePassFile"),
        vec![],
        &mut KdbxContext::default(),
    )
    .expect("Failed parsing")
    .unwrap();
    end_document(reader);
    assert_eq!(document.root.group.entry.len(), 0);
    let group = &document.root.group;
    let expected_uuid = Uuid::parse_str("5a1c21b4-b663-4efb-ba79-9dea57a393eb").unwrap();
    assert_eq!(group.uuid, expected_uuid);
    assert_eq!(group.name, "Root");
    assert_eq!(group.notes, "");
    assert_eq!(group.icon_id, 48);
    assert_eq!(
        group.times.last_modification_time,
        DateTime::parse_from_rfc3339("2019-12-20T01:24:29+00:00").unwrap()
    );
    assert_eq!(
        group.times.creation_time,
        DateTime::parse_from_rfc3339("2019-12-20T01:24:29+00:00").unwrap()
    );
    assert_eq!(
        group.times.last_access_time,
        DateTime::parse_from_rfc3339("2019-12-20T01:24:29+00:00").unwrap()
    );
    assert_eq!(
        group.times.expiry_time,
        DateTime::parse_from_rfc3339("2019-12-20T01:24:29+00:00").unwrap()
    );
    assert_eq!(group.times.expires, false);
    assert_eq!(group.times.usage_count, 0);
    assert_eq!(
        group.times.location_changed,
        DateTime::parse_from_rfc3339("2019-12-20T01:24:29+00:00").unwrap()
    );
    assert_eq!(group.is_expanded, true);
    //<DefaultAutoTypeSequence/>
    //<EnableAutoType>null</EnableAutoType>
    //<EnableSearching>null</EnableSearching>
    let expected_uuid = Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap();
    assert_eq!(group.last_top_visible_entry, expected_uuid);
}

#[test]
fn test_block_writer() {
    let test_string = [
        "This is a t",
        "est of the block writer an",
        "d reader code to verify that it created the",
        " appropria",
        "te set of hmac keys and validates.",
        "",
    ];
    let mut rng = rand::thread_rng();
    let key = rng.gen::<[u8; 32]>();
    let mut buf = Vec::new();
    {
        let cursor = Cursor::new(&mut buf);
        eprintln!("HMAC Test Key: {:0x?}", &key);
        let mut writer = BlockWriter::new(&key, cursor);
        for string in test_string {
            writer.write_all(string.as_bytes()).unwrap();
            writer.flush().unwrap();
        }
    }
    //let expected = test_string.chain(["a".to_string()].iter()).join("");
    let expected = test_string.join("");
    eprintln!("Block output: {}", String::from_utf8_lossy(&buf));
    assert_eq!(buf.len(), expected.len() + test_string.len() * (32 + 4));
    let cursor = Cursor::new(&mut buf);
    let mut reader = BlockReader::new(&key, cursor);
    let mut actual = Vec::new();
    assert_eq!(reader.read_to_end(&mut actual).unwrap(), actual.len());
    assert_eq!(expected, String::from_utf8_lossy(&actual));
}

#[test]
#[ignore = "Recent regression 2023-08-10"]
fn test_crypto_writer() {
    let test_string = [
        "This is a t",
        "est of the block writer an",
        "d reader code to verify that it created the",
        " appropria",
        "te set of hmac keys and validates.",
        "",
    ];
    let cipher = Cipher::aes_256_cbc();
    let mut rng = rand::thread_rng();
    let key = rng.gen::<[u8; 32]>();
    let iv = rng.gen::<[u8; 16]>();
    let mut buf = Vec::new();
    {
        let cursor: Cursor<&mut Vec<u8>> = Cursor::new(&mut buf);
        eprintln!("AES Test Key: {:0x?}", &key);
        let mut writer =
            Crypto::new(cipher, &key, Some(&iv), cursor).expect("Failed to create crypto");
        for string in test_string {
            writer.write_all(string.as_bytes()).unwrap();
            writer.flush().unwrap();
        }
    }
    //let expected = test_string.chain(["a".to_string()].iter()).join("");
    let expected = test_string.join("");
    eprintln!("Block output: {}", String::from_utf8_lossy(&buf));
    assert_eq!(buf.len(), (expected.len() + 15) / 16 * 16);
    let actual = decrypt(cipher, &key, Some(&iv), &buf).expect("Failed to decrypt");
    // let cursor = Cursor::new(&mut buf);
    // let mut reader = BlockReader::new(&key, cursor);
    // let mut actual = Vec::new();
    // assert_eq!(reader.read_to_end(&mut actual).unwrap(), actual.len());
    assert_eq!(expected, String::from_utf8_lossy(&actual));
}

#[test]
#[cfg(feature = "write")]
fn test_save_tlvs_ver3() {
    let mut buf = Cursor::new(Vec::new());
    let mut map = BTreeMap::new();
    map.insert(3, vec![vec![9u8, 8u8, 7u8]]);
    map.insert(1, vec![vec![0u8, 1u8, 2u8, 3u8]]);
    map.insert(2, vec![vec![3u8, 4u8], vec![5u8, 6u8]]);
    let expected = vec![
        1u8, 4, 0, 0, 1, 2, 3, // TLV 1 = [0,1,2,3]
        2, 2, 0, 3, 4, // TLV 2 = [3, 4]
        2, 2, 0, 5, 6, // TLV 2 = [5, 6]
        3, 3, 0, 9, 8, 7, // TLV 3 =  [9, 8, 7]
        0, 0, 0, // TLV END
    ];
    let actual = save_tlvs(&mut buf, &map, 3).expect("Failed to write tlvs");
    assert_eq!(expected, actual);
    assert_eq!(expected, buf.into_inner());
}

#[test]
fn test_load_tlvs_ver3() {
    let mut buf = Cursor::new(vec![
        2, 2, 0, 3, 4, // TLV 2 = [3, 4]
        3, 3, 0, 9, 8, 7, // TLV 3 =  [9, 8, 7]
        1u8, 4, 0, 0, 1, 2, 3, // TLV 1 = [0,1,2,3]
        2, 2, 0, 5, 6, // TLV 2 = [5, 6]
        0, 0, 0, // TLV END
    ]);
    let (actual, bytes) = load_tlvs(&mut buf, 3).expect("Failed to read tlvs");
    assert_eq!(bytes, buf.into_inner());
    assert_eq!(actual.len(), 3);
    assert_eq!(actual[&1].len(), 1);
    assert_eq!(actual[&2].len(), 2);
    assert_eq!(actual[&3].len(), 1);
    assert_eq!(actual[&1], vec![vec![0u8, 1u8, 2u8, 3u8]]);
    assert_eq!(actual[&2], vec![vec![3u8, 4u8], vec![5u8, 6u8]]);
    assert_eq!(actual[&3], vec![vec![9u8, 8u8, 7u8]]);
}

#[test]
#[cfg(feature = "write")]
fn test_save_tlvs_ver4() {
    let mut buf = Cursor::new(Vec::new());
    let mut map = BTreeMap::new();
    map.insert(3, vec![vec![9u8, 8u8, 7u8]]);
    map.insert(1, vec![vec![0u8, 1u8, 2u8, 3u8]]);
    map.insert(2, vec![vec![3u8, 4u8], vec![5u8, 6u8]]);
    let expected = vec![
        1u8, 4, 0, 0, 0, 0, 1, 2, 3, // TLV 1 = [0,1,2,3]
        2, 2, 0, 0, 0, 3, 4, // TLV 2 = [3, 4]
        2, 2, 0, 0, 0, 5, 6, // TLV 2 = [5, 6]
        3, 3, 0, 0, 0, 9, 8, 7, // TLV 3 =  [9, 8, 7]
        0, 0, 0, 0, 0, // TLV END
    ];
    let actual = save_tlvs(&mut buf, &map, 4).expect("Failed to write tlvs");
    assert_eq!(expected, actual);
    assert_eq!(expected, buf.into_inner());
}

#[test]
fn test_load_tlvs_ver4() {
    let mut buf = Cursor::new(vec![
        2, 2, 0, 0, 0, 3, 4, // TLV 2 = [3, 4]
        3, 3, 0, 0, 0, 9, 8, 7, // TLV 3 =  [9, 8, 7]
        1u8, 4, 0, 0, 0, 0, 1, 2, 3, // TLV 1 = [0,1,2,3]
        2, 2, 0, 0, 0, 5, 6, // TLV 2 = [5, 6]
        0, 0, 0, 0, 0, // TLV END
    ]);
    let (actual, bytes) = load_tlvs(&mut buf, 4).expect("Failed to read tlvs");
    assert_eq!(bytes, buf.into_inner());
    assert_eq!(actual.len(), 3);
    assert_eq!(actual[&1].len(), 1);
    assert_eq!(actual[&2].len(), 2);
    assert_eq!(actual[&3].len(), 1);
    assert_eq!(actual[&1], vec![vec![0u8, 1u8, 2u8, 3u8]]);
    assert_eq!(actual[&2], vec![vec![3u8, 4u8], vec![5u8, 6u8]]);
    assert_eq!(actual[&3], vec![vec![9u8, 8u8, 7u8]]);
}

#[test]
fn test_load_variant_map_empty() {
    let buf = vec![
        0u8, 1,   // Version 1.0
        0x0, // End
    ];
    let map = load_map(&buf).expect("Error decoding map");
    assert_eq!(map.len(), 0);
}

#[test]
fn test_load_variant_map_bool() {
    let buf = vec![
        0u8, 1, // Version 1.0
        0x08, 4, 0, 0, 0, 0x42, 0x4f, 0x4f, 0x4c, 1, 0, 0, 0, 1, // BOOL = true
        0x08, 2, 0, 0, 0, 0x6e, 0x6f, 1, 0, 0, 0, 0,   // no = true
        0x0, // End
    ];
    let map = load_map(&buf).expect("Error decoding map");
    assert_eq!(map.len(), 2);
    assert!(map.contains_key("BOOL"));
    assert!(map.contains_key("no"));
    assert_eq!(map["BOOL"], MapValue::Bool(true));
    assert_eq!(map["no"], MapValue::Bool(false));
}

#[test]
fn test_load_variant_map_bytes() {
    let buf = vec![
        0u8, 1, // Version 1.0
        0x42, 5, 0, 0, 0, 0x62, 0x79, 0x74, 0x65, 0x73, 4, 0, 0, 0, 1, 2, 3,
        4,   // bytes = [1, 2, 3, 4]
        0x0, // End
    ];
    let map = load_map(&buf).expect("Error decoding map");
    assert_eq!(map.len(), 1);
    assert!(map.contains_key("bytes"));
    assert_eq!(map["bytes"], MapValue::ByteArray(vec![1, 2, 3, 4]));
}

#[test]
fn test_load_variant_map() {
    let buf = vec![
        0u8, 1, // Version 1.0
        0x04, 3, 0, 0, 0, 0x55, 0x33, 0x32, 4, 0, 0, 0, 0, 0, 0, 0x80, // U32 = 0x80000000
        0x05, 3, 0, 0, 0, 0x55, 0x36, 0x34, 8, 0, 0, 0, 123, 0, 0, 0, 0, 0, 0, 0, // U64 = 123
        0x08, 4, 0, 0, 0, 0x42, 0x4f, 0x4f, 0x4c, 1, 0, 0, 0, 1, // BOOL = true
        0x08, 2, 0, 0, 0, 0x6e, 0x6f, 1, 0, 0, 0, 0, // no = true
        0x0c, 3, 0, 0, 0, 0x49, 0x33, 0x32, 4, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, // I32 = -1
        0x0d, 3, 0, 0, 0, 0x49, 0x36, 0x34, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0x80, // I64 = uint64::min
        0x18, 2, 0, 0, 0, 0x68, 0x69, 3, 0, 0, 0, 0x62, 0x79, 0x65, // hi = bye
        0x42, 5, 0, 0, 0, 0x62, 0x79, 0x74, 0x65, 0x73, 4, 0, 0, 0, 1, 2, 3,
        4,   // bytes = [1, 2, 3, 4]
        0x0, // End
    ];
    let map = load_map(&buf).expect("Error decoding map");
    assert_eq!(map.len(), 8);
    assert!(map.contains_key("U32"));
    assert!(map.contains_key("U64"));
    assert!(map.contains_key("BOOL"));
    assert!(map.contains_key("no"));
    assert!(map.contains_key("I32"));
    assert!(map.contains_key("I64"));
    assert!(map.contains_key("hi"));
    assert!(map.contains_key("bytes"));
    assert_eq!(map["U32"], MapValue::UInt32(0x80000000));
    assert_eq!(map["U64"], MapValue::UInt64(123));
    assert_eq!(map["BOOL"], MapValue::Bool(true));
    assert_eq!(map["no"], MapValue::Bool(false));
    assert_eq!(map["I32"], MapValue::Int32(-1));
    assert_eq!(map["I64"], MapValue::Int64(i64::MIN));
    assert_eq!(map["hi"], MapValue::String("bye".to_string()));
    assert_eq!(map["bytes"], MapValue::ByteArray(vec![1, 2, 3, 4]));
}

#[test]
#[cfg(feature = "write")]
fn test_save_variant_map() {
    let mut expected = HashMap::new();
    expected.insert("U32".to_string(), MapValue::UInt32(0x80000000));
    expected.insert("U64".to_string(), MapValue::UInt64(123));
    expected.insert("BOOL".to_string(), MapValue::Bool(true));
    expected.insert("no".to_string(), MapValue::Bool(false));
    expected.insert("I32".to_string(), MapValue::Int32(-1));
    expected.insert("I64".to_string(), MapValue::Int64(i64::MIN));
    expected.insert("hi".to_string(), MapValue::String("bye".to_string()));
    expected.insert("bytes".to_string(), MapValue::ByteArray(vec![1, 2, 3, 4]));
    let bytes = save_map(&expected);
    let actual = load_map(&bytes).expect("Read failure");
    assert_eq!(actual, expected);
}
