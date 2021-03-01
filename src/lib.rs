use profligate::auto::{analysis::ENGLISH_FREQ_TABLE, auto_decrypt_caesar, validation::*};
use profligate::caesar::CaesarError;
use wasm_bindgen::prelude::*;

/// Because the English word list takes so long to initialize, I made this an unsafe, mutable static. It's wrapped in an Option because Rust requires statics to have an initial value known at compile time.
/// It actually gets created by `init()`.
static mut ENGLISH_VALIDATOR: Option<WordListValidator> = None;

#[wasm_bindgen]
/// This function sets up the English word-list validator. You should call it immediately after loading the WASM module, because this takes a non-instant amount of time.
pub fn init() {
    unsafe {
        let word_list = WordList::new(ENGLISH_WORDS);
        let validator = WordListValidator::new(word_list);
        ENGLISH_VALIDATOR = Some(validator);
    }
}

fn get_english_validator() -> &'static mut WordListValidator<'static> {
    unsafe {
        match &ENGLISH_VALIDATOR {
            None => {
                init();
                ENGLISH_VALIDATOR.as_mut().unwrap()
            }
            Some(_) => ENGLISH_VALIDATOR.as_mut().unwrap(),
        }
    }
}

fn error_msg(err: &CaesarError) -> String {
    match err {
        CaesarError::NonAscii => "Error: The input text contained non-ASCII characters, which are unsupported.",
        CaesarError::PlaintextInvalid => "Error: The most likely decrypted plaintext did not make sense to the validator you chose. Adjust your known plaintext (crib) or word list validation threshold."
    }.into()
}

/// Encrypt text manually. The key should fit into a Rust `i16`.
#[wasm_bindgen]
pub fn encrypt(text: String, key: i16) -> String {
    let mut text = text;
    let res = profligate::caesar::encrypt(&mut text, key);
    match res {
        Ok(_) => text,
        Err(e) => error_msg(&e),
    }
}
/// Decrypt text manually. The key should fit into a Rust `i16`.
#[wasm_bindgen]
pub fn decrypt(text: String, key: i16) -> String {
    let mut text = text;
    let res = profligate::caesar::decrypt(&mut text, key);
    match res {
        Ok(_) => text,
        Err(e) => error_msg(&e),
    }
}
/// Decrypt text automatically, given a "crib" (a piece of text we expect to find in the plaintext).
#[wasm_bindgen]
pub fn decrypt_auto_crib(text: String, crib: String) -> String {
    let mut text = text;
    let validator = CribValidator::new(crib);
    let res = auto_decrypt_caesar(&mut text, &ENGLISH_FREQ_TABLE, &validator);
    match res {
        Ok(i) => format!("Success after {} iterations:\n{}", i, text),
        Err(e) => error_msg(&e),
    }
}
/// Decrypt text automatically by trying different possible keys until the text looks like English. By setting `threshold`, you can control the proportion of intelligible words.
#[wasm_bindgen]
pub fn decrypt_auto_english(text: String, threshold: f32) -> String {
    let mut text = text;
    let validator = get_english_validator();
    validator.set_threshold(threshold);
    let res = auto_decrypt_caesar(&mut text, &ENGLISH_FREQ_TABLE, validator);
    match res {
        Ok(i) => format!("Success after {} iterations:\n{}", i, text),
        Err(e) => error_msg(&e),
    }
}
