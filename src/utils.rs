pub fn pluralize(item_name: &str, quantity: i64) -> String {
    let mut result = String::from(item_name);
    if quantity != 1 {
        result += "s";
    }
    result
}
