use chrono::Utc;
use rust_decimal::Decimal;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sqlx::postgres::{PgTypeInfo, PgValueRef};
use sqlx::{Decode, Encode, FromRow, Postgres, Type};

use crate::error::TransactionError;
use std::fmt;
use std::str::FromStr;

// Transaction data structure
#[derive(Serialize, Deserialize, FromRow)]
pub struct Transaction {
    id: i32,
    user_id: i32,
    amount: Decimal,
    description: Option<String>,
    created_at: chrono::DateTime<Utc>,
    transaction_type: TransactionType,
}

// TransactionType enum
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TransactionType {
    Deposit,
    Withdrawal,
}

impl fmt::Display for TransactionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransactionType::Deposit => write!(f, "DEPOSIT"),
            TransactionType::Withdrawal => write!(f, "WITHDRAWAL"),
        }
    }
}

impl FromStr for TransactionType {
    type Err = TransactionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "DEPOSIT" => Ok(TransactionType::Deposit),
            "WITHDRAWAL" => Ok(TransactionType::Withdrawal),
            _ => Err(TransactionError::InvalidInput(
                "Transaction type must be DEPOSIT or WITHDRAWAL".into(),
            )),
        }
    }
}

impl Serialize for TransactionType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for TransactionType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TransactionTypeVisitor;

        impl<'de> Visitor<'de> for TransactionTypeVisitor {
            type Value = TransactionType;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("DEPOSIT or WITHDRAWAL")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                TransactionType::from_str(value).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(TransactionTypeVisitor)
    }
}

impl Type<Postgres> for TransactionType {
    fn type_info() -> PgTypeInfo {
        PgTypeInfo::with_name("transaction_type")
    }
}

impl<'r> Decode<'r, Postgres> for TransactionType {
    fn decode(value: PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <&str as Decode<Postgres>>::decode(value)?;
        TransactionType::from_str(s).map_err(|e| e.to_string().into())
    }
}

impl<'q> Encode<'q, Postgres> for TransactionType {
    fn encode_by_ref(&self, buf: &mut sqlx::postgres::PgArgumentBuffer) -> sqlx::encode::IsNull {
        let s = self.to_string();
        <&str as Encode<Postgres>>::encode(&s, buf)
    }
}
