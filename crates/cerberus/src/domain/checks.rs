use super::Head;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Ok,
    /// Degrades the guard: collected by [`problems_of`] into the sentinel.
    Fail,
    /// Worth knowing, never degrades. Only `doctor` produces these.
    Warn,
    /// Not probed: the head is off, or a prerequisite already failed.
    Skip,
}

/// One probe's outcome. For a `Fail`, `summary` is the exact problem text
/// that goes into the sentinel; for the rest it's a short description.
#[derive(Clone, Debug)]
pub struct Check {
    pub head: Option<Head>,
    pub id: &'static str,
    pub status: Status,
    pub summary: String,
    pub detail: Option<String>,
    pub fix: Option<String>,
}

impl Check {
    pub(crate) fn new(
        head: Option<Head>,
        id: &'static str,
        status: Status,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            head,
            id,
            status,
            summary: summary.into(),
            detail: None,
            fix: None,
        }
    }

    pub fn ok(head: Option<Head>, id: &'static str, summary: impl Into<String>) -> Self {
        Self::new(head, id, Status::Ok, summary)
    }

    pub fn warn(head: Option<Head>, id: &'static str, summary: impl Into<String>) -> Self {
        Self::new(head, id, Status::Warn, summary)
    }

    pub(crate) fn skip(head: Head, id: &'static str, why: impl Into<String>) -> Self {
        Self::new(Some(head), id, Status::Skip, why)
    }

    /// `problem` is the message without the head label, which is added here.
    pub(crate) fn fail(head: Head, id: &'static str, problem: impl Into<String>) -> Self {
        let summary = format!("{}: {}", head.label(), problem.into());
        Self::new(Some(head), id, Status::Fail, summary)
    }

    /// `summary` without the leading head label, for display next to the id.
    pub fn short_summary(&self) -> &str {
        self.head
            .map(Head::label)
            .and_then(|l| self.summary.strip_prefix(&l))
            .map(|rest| rest.trim_start_matches(':').trim_start())
            .unwrap_or(&self.summary)
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
}
