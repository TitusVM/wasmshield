use wasmparser::Payload;

/// For now, this decomposition can only identify signed components, other components are ignored.
pub fn decompose(file_contents: &[u8]) -> Vec<Vec<u8>> {
    split_composition(file_contents)
}

fn split_composition(composition: &[u8]) -> Vec<Vec<u8>> {
    const SECTION_DELIMITER: [u8; 4] = [0x00, 0x61, 0x73, 0x6d];
    const SIGNATURE_DELIMITER: [u8; 20] = [
        0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00,
        0x00, 0x75, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61,
        0x74, 0x75, 0x72, 0x65,
    ];
    let mut components: Vec<Vec<u8>> = Vec::new();
    let mut bookmark = 0;
    let mut counter = 0;

    for i in 0..(composition.len() - SIGNATURE_DELIMITER.len()) {
        if composition[i..(i + SECTION_DELIMITER.len())] == SECTION_DELIMITER {
            if composition[i..(i + SIGNATURE_DELIMITER.len())] == SIGNATURE_DELIMITER {
                if counter == 0 {
                    // The first signature is the one from the composed component so we store the whole component
                    // This may seem redundant but it actually ensures that the parts we remove later on (in clean_extracted())
                    // do not contain any modified sections of code. 
                    components.push(composition.to_vec());
                } else if bookmark != 0{
                    components.push(composition[bookmark..i].to_vec());
                }
                // Update bookmark to the start of the new signed component
                bookmark = i;
                counter += 1;
            }
        }
    }

    // Push the last component if it exists
    if bookmark < composition.len() {
        components.push(composition[bookmark..].to_vec());
    }

    components
}


/// Remove last couple of bytes from an extracted component, this is to be able to verify it's signature. These bytes are not part of the component.
pub fn clean_extracted(extracted: &Vec<u8>) -> Vec<u8> {
    let mut end_last_section = 0;
    for payload in wasmparser::Parser::new(0).parse_all(&extracted) {
        match payload {
            Ok(Payload::CustomSection(reader)) => {
                // The last sections range end will define when the component actually ends. We can then only return up to then, we don't need the rest.
                end_last_section = reader.range().end;
            }
            _ => {}
        }
    };
    extracted[0..end_last_section].to_vec()
}


/// Attempts to return a name for a component
pub fn get_name(file_contents: &[u8]) -> String {
    let mut name = "UNKNOWN_NAME".to_string();

    const ID_MODULE: [u8; 1] = [0x00];
    const LEN_POS: usize = 1; // Len of name is at the second position
    
    for payload in wasmparser::Parser::new(0).parse_all(file_contents) {
        match payload.map_err(|_| anyhow::Error::msg("Couldn't parse binary")) {
            Ok(Payload::CustomSection(reader)) => {
                if reader.name() == "name" {
                    if reader.data().starts_with(&ID_MODULE) {
                        name = String::from_utf8_lossy(&reader.data()[(LEN_POS+1)..(reader.data()[LEN_POS] as usize + LEN_POS + 1)]).into_owned();
                        // The first name found describes the component, we don't need to look at the subcomponents
                        break;
                    }
                }
            }
            // Ignore all other sections
            _ => {}
        }
    }
    name
}