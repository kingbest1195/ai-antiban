//! Hexagonal port decoupling BIN domain evaluation from external HTTP providers.

use super::model::{BinSource, CardFunding};
use std::future::Future;
use std::pin::Pin;

pub type BinLookupFuture<'a> =
    Pin<Box<dyn Future<Output = Result<RawBinInfo, BinLookupError>> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawBinInfo {
    pub scheme: Option<String>,
    pub funding: CardFunding,
    pub is_prepaid: Option<bool>,
    pub is_commercial: Option<bool>,
    pub is_reloadable: Option<bool>,
    pub card_category: Option<String>,
    pub country_code: Option<String>,
    pub issuer_name: Option<String>,
    pub source: BinSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinLookupError {
    Timeout,
    Network(String),
    HttpStatus(u16),
    NotFound,
    InvalidPayload(String),
}

impl BinLookupError {
    pub fn user_reason_ru(&self) -> String {
        match self {
            BinLookupError::Timeout => {
                "Сервис проверки карты по первым цифрам не ответил вовремя.".to_string()
            }
            BinLookupError::Network(_) => {
                "Не удалось подключиться к сервису проверки карты по первым цифрам.".to_string()
            }
            BinLookupError::HttpStatus(429) => {
                "Сервис проверки карт временно ограничил запросы — попробуйте чуть позже."
                    .to_string()
            }
            BinLookupError::HttpStatus(code) => {
                format!("Сервис проверки карт временно недоступен (код ответа {code}).")
            }
            BinLookupError::NotFound => {
                "Первые цифры этой карты не найдены в справочнике банков.".to_string()
            }
            BinLookupError::InvalidPayload(_) => {
                "Сервис проверки карт вернул пустой или некорректный ответ.".to_string()
            }
        }
    }
}

pub trait BinLookupPort: Send + Sync {
    fn lookup<'a>(&'a self, bin_prefix: &'a str) -> BinLookupFuture<'a>;
}
