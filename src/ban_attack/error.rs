use std::{fmt, io};

#[derive(Debug)]
pub enum Error {
    Config(String),
    Rule { rule: String, message: String },
    Io(io::Error),
    Backend(BackendError),
    EngineBusy,
    CommandTimeout,
    EngineStopped,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(msg) => write!(f, "invalid configuration: {msg}"),
            Self::Rule { rule, message } => write!(f, "failed to compile rule `{rule}`: {message}"),
            Self::Io(err) => write!(f, "{err}"),
            Self::Backend(err) => write!(f, "{err}"),
            Self::EngineBusy => write!(f, "ban engine command queue is full"),
            Self::CommandTimeout => write!(f, "ban engine command timed out"),
            Self::EngineStopped => write!(f, "ban engine has stopped"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Backend(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<BackendError> for Error {
    fn from(err: BackendError) -> Self {
        Self::Backend(err)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendError(pub String);

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for BackendError {}

impl From<String> for BackendError {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for BackendError {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}
