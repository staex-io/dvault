use candid::{CandidType, Deserialize};

pub type Res<T> = Result<T, Error>;

#[derive(CandidType, Deserialize, Default, PartialEq, Debug)]
pub enum Error {
    #[default]
    Internal,
}

#[ic_cdk::query]
fn invoke_test(message: String) -> Res<String> {
    Ok(format!("dvault test: {}!", message))
}

ic_cdk::export_candid!();
