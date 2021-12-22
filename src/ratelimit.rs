use once_cell::sync::Lazy;
use std::{net::IpAddr, num::NonZeroU32, time::Duration};

use governor::{clock::DefaultClock, state::keyed::DashMapStateStore, Quota, RateLimiter};

use crate::{Error, CONFIG};

type Limiter<T = IpAddr> = RateLimiter<T, DashMapStateStore<T>, DefaultClock>;

static LIMITER_LOGIN: Lazy<Limiter> = Lazy::new(|| {
    let seconds = Duration::from_secs(CONFIG.login_ratelimit_seconds());
    let burst = NonZeroU32::new(CONFIG.login_ratelimit_max_burst()).expect("Non-zero login ratelimit burst");
    RateLimiter::keyed(Quota::with_period(seconds).expect("Non-zero login ratelimit seconds").allow_burst(burst))
});

static LIMITER_ADMIN: Lazy<Limiter> = Lazy::new(|| {
    let seconds = Duration::from_secs(CONFIG.admin_ratelimit_seconds());
    let burst = NonZeroU32::new(CONFIG.admin_ratelimit_max_burst()).expect("Non-zero admin ratelimit burst");
    RateLimiter::keyed(Quota::with_period(seconds).expect("Non-zero admin ratelimit seconds").allow_burst(burst))
});

pub fn check_limit_login(ip: &IpAddr) -> Result<(), Error> {
    match LIMITER_LOGIN.check_key(ip) {
        Ok(_) => Ok(()),
        Err(_e) => {
            err_code!("Too many login requests", 429);
        }
    }
}

pub fn check_limit_admin(ip: &IpAddr) -> Result<(), Error> {
    match LIMITER_ADMIN.check_key(ip) {
        Ok(_) => Ok(()),
        Err(_e) => {
            err_code!("Too many admin requests", 429);
        }
    }
}
