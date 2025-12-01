use std::{env, fs, path::PathBuf};

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let webapp_dir = PathBuf::from(&manifest_dir);
    let out_dir = webapp_dir.join("../dist");

    // Create dist directory
    std::fs::create_dir_all(&out_dir).expect("Failed to create dist directory");

    // Compile SCSS to CSS
    let scss_path = webapp_dir.join("styles.scss");
    if scss_path.exists() {
        let scss =
            fs::read_to_string(&scss_path).expect("Failed to read SCSS file");

        let css = grass::from_string(
            scss,
            &grass::Options::default().style(grass::OutputStyle::Compressed),
        )
        .expect("Failed to compile SCSS");

        fs::write(out_dir.join("styles.css"), css)
            .expect("Failed to write CSS file");

        println!("cargo:warning=SCSS compiled successfully");
    }

    // Copy index.html
    std::fs::copy(webapp_dir.join("index.html"), out_dir.join("index.html"))
        .expect("Failed to copy index.html");

    /*
    println!("cargo:warning=Client built successfully to ../dist");
    */
}
