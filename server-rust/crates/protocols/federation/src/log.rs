use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// Structured-log sink (Go's `*slog.Logger`). Messages never carry payload
/// or address material beyond what the Go lines carry.
#[derive(Clone)]
pub struct Logger(Arc<dyn Fn(LogLevel, String) + Send + Sync>);

impl Logger {
    pub fn new(f: impl Fn(LogLevel, String) + Send + Sync + 'static) -> Self {
        Logger(Arc::new(f))
    }
    /// stderr, dropping debug lines.
    pub fn stderr() -> Self {
        Logger::new(|l, m| {
            if l != LogLevel::Debug {
                eprintln!("{l:?} {m}");
            }
        })
    }
    pub fn discard() -> Self {
        Logger::new(|_, _| {})
    }
    pub fn log(&self, level: LogLevel, msg: impl Into<String>) {
        (self.0)(level, msg.into())
    }
    pub fn debug(&self, msg: impl Into<String>) {
        self.log(LogLevel::Debug, msg)
    }
    pub fn info(&self, msg: impl Into<String>) {
        self.log(LogLevel::Info, msg)
    }
    pub fn warn(&self, msg: impl Into<String>) {
        self.log(LogLevel::Warn, msg)
    }
    pub fn error(&self, msg: impl Into<String>) {
        self.log(LogLevel::Error, msg)
    }
}
