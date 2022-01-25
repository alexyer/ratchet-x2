#[derive(Debug, PartialEq)]
pub enum DoubleRatchetError {
    NotInitialized,
    TooManySkippedKeys,
    AeadError,
}

pub type DoubleRatchetResult<T> = Result<T, DoubleRatchetError>;
