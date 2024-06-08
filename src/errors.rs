use thiserror::Error;

/// Error type for the validator registration.
#[derive(Debug, Error)]
pub enum ValidatorError {
    /// Error propagated by IO operations
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    /// Error when the signature verification fails.
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// Serde JSON Error
    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),
}

/// Error type for subgraph
#[derive(Debug, Error)]
pub enum SubgraphError {
    /// Error propagated by IO operations
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    /// Error after trying requests with both production and development endpoints
    #[error("All the subgraph requests failed")]
    AllRequestsFailed,
}



/// Application error type.
#[derive(Debug, Error)]
pub enum AppError {
    /// Error when the validator data file verification fails.
    #[error(transparent)]
    ValidatorError(#[from] ValidatorError),
}