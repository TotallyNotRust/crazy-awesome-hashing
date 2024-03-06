#[cfg(test)]
mod tests {
    use crate::{delete_user, login, make_user};
 
    #[test]
    fn make_user_and_login() {
        assert!(make_user("Bruger1".to_owned(), "PasSwORd1".to_owned()));
        assert!(login("Bruger1".to_owned(), "PasSwORd1".to_owned()));
    }

    #[test]
    fn make_user_and_delete() {
        assert!(make_user("Bruger1".to_owned(), "PasSwORd1".to_owned()));
        assert!(delete_user("Bruger1".to_owned()));
    }
}