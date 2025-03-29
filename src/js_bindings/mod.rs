use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn greet() {
    alert("Hello, test-wasm!");
}
