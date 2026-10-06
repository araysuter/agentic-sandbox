pub mod server {
    #[derive(Clone)]
    pub struct AppState {
        pub disposable: Option<std::sync::Arc<crate::disposable::DisposableController>>,
    }
}
pub mod operator_auth {
    #[derive(Clone, Copy)]
    pub enum OperatorRole {
        Admin,
        Operator,
    }
}
#[path = "../../../../management/src/http/disposable.rs"]
pub mod disposable;
