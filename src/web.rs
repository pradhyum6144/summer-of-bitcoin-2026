use actix_cors::Cors;
use actix_web::{web, App, HttpServer, HttpResponse};
use std::env;

use coin_smith::builder::{build_psbt, psbt_to_base64};
use coin_smith::coin_selection::select_coins_multi;
use coin_smith::fixture::{normalize_fixture, validate_fixture, Fixture};
use coin_smith::report::{build_report_full, error_report};
use coin_smith::signer::sign_psbt_with_test_keys;

async fn health() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({"ok": true}))
}

async fn build_handler(body: web::Json<serde_json::Value>) -> HttpResponse {
    let fixture: Fixture = match serde_json::from_value(body.into_inner()) {
        Ok(f) => f,
        Err(e) => {
            return HttpResponse::BadRequest().json(error_report(
                &coin_smith::fixture::BuildError {
                    code: "INVALID_FIXTURE".to_string(),
                    message: format!("Cannot parse fixture: {}", e),
                },
            ));
        }
    };

    if let Err(e) = validate_fixture(&fixture) {
        return HttpResponse::BadRequest().json(error_report(&e));
    }
    let mut fixture = fixture;
    normalize_fixture(&mut fixture);

    let payment_total: u64 = fixture.payments.iter().map(|p| p.value_sats).sum();
    let payment_script_types: Vec<&str> =
        fixture.payments.iter().map(|p| p.script_type.as_str()).collect();
    let max_inputs = fixture.policy.as_ref().and_then(|p| p.max_inputs);

    let (selection, scores) = match select_coins_multi(
        &fixture.utxos,
        payment_total,
        &payment_script_types,
        &fixture.change.script_type,
        fixture.fee_rate_sat_vb,
        max_inputs,
    ) {
        Ok(s) => s,
        Err(e) => return HttpResponse::BadRequest().json(error_report(&e)),
    };

    let change_param = selection.change_amount.map(|amt| (amt, &fixture.change));
    let build_result = match build_psbt(&fixture, &selection.selected, &fixture.payments, change_param) {
        Ok(r) => r,
        Err(e) => return HttpResponse::InternalServerError().json(error_report(&e)),
    };

    let psbt_b64 = psbt_to_base64(&build_result.psbt);

    // Sign PSBT with test keys
    let input_script_types: Vec<String> = selection.selected.iter().map(|u| u.script_type.clone()).collect();
    let mut psbt_for_signing = build_result.psbt.clone();
    let signing_result = sign_psbt_with_test_keys(&mut psbt_for_signing, &input_script_types).ok();

    let report = build_report_full(&fixture, &selection, &psbt_b64, Some(scores), signing_result);

    HttpResponse::Ok().json(report)
}

async fn index() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../static/index.html"))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse()
        .unwrap_or(3000);

    let url = format!("http://127.0.0.1:{}", port);
    println!("{}", url);

    HttpServer::new(|| {
        let cors = Cors::permissive();
        App::new()
            .wrap(cors)
            .route("/", web::get().to(index))
            .route("/api/health", web::get().to(health))
            .route("/api/build", web::post().to(build_handler))
    })
    .bind(("127.0.0.1", port))?
    .run()
    .await
}
