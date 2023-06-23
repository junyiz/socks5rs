use std::fmt::Display;

pub fn log<T: Display>(color: &str, text: &str, err: T) {
    // https://gist.github.com/fnky/458719343aabd01cfb17a3a4f7296797
    println!("\x1b[0;{color}m{text}\x1b[0m: {err}");
}
