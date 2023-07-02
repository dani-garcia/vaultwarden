use rocket::Route;

use crate::{
    config::CONFIG,
    db::{
        models::{Organization, User},
        DbConn,
    },
};

use lazy_static::lazy_static;
use prometheus::{register_gauge, register_gauge_vec, Encoder, Gauge, GaugeVec, TextEncoder};
use prometheus_static_metric::make_static_metric;

pub fn routes() -> Vec<Route> {
    if !CONFIG.prometheus_enabled() {
        return routes![];
    }
    routes![metrics]
}

make_static_metric! {
    pub struct UserGauge: Gauge {
        "enabled" => {
            enabled:"true",
            disabled:"false",
        },
    }
}

lazy_static! {
    pub static ref USER_COUNTER_VEC: GaugeVec =
        register_gauge_vec!("vw_users", "Total number of users in the system", &["enabled"]).unwrap();
    pub static ref USER_COUNTER: UserGauge = UserGauge::from(&USER_COUNTER_VEC);
    pub static ref ORGANIZATION_COUNTER: Gauge =
        register_gauge!("vw_organizations", "Total number of organizations in the system").unwrap();
}

#[get("/")]
async fn metrics(mut conn: DbConn) -> String {
    let users = User::get_all(&mut conn).await;
    let org_count = Organization::count(&mut conn).await;

    USER_COUNTER.enabled.set(users.iter().filter(|u| u.enabled).count() as f64);
    USER_COUNTER.disabled.set(users.iter().filter(|u| !u.enabled).count() as f64);
    ORGANIZATION_COUNTER.set(org_count as f64);
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();

    encoder.encode(&metric_families, &mut buffer).unwrap();

    String::from_utf8(buffer.clone()).unwrap()
}
