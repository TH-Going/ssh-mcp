use crate::models::Approval;

pub trait CoreEventSink: Send + Sync + 'static {
    fn on_state_changed(&self) {}
    fn on_approval_created(&self, _approval: &Approval) {}
    fn on_failure_alert(
        &self,
        _title: &str,
        _body: &str,
        _server_id: Option<&str>,
        _job_id: Option<&str>,
    ) {
    }
    fn on_terminal_output(&self, _session_id: &str, _data: &str) {}
    fn on_terminal_closed(&self, _session_id: &str, _reason: Option<&str>) {}
}

#[derive(Default)]
pub struct NoopEventSink;

impl CoreEventSink for NoopEventSink {}
