pub mod server {
    #[derive(Clone)]
    pub struct AppState {
        pub local_audits: Option<std::sync::Arc<crate::local_audits::LocalAuditService>>,
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

#[path = "../../../../management/src/http/local_audits.rs"]
pub mod local_audits;
