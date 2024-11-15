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