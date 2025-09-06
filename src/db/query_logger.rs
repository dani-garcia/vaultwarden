use dashmap::DashMap;
use diesel::connection::{Instrumentation, InstrumentationEvent};
use std::{
    sync::{Arc, LazyLock},
    thread,
    time::Instant,
};

pub static QUERY_PERF_TRACKER: LazyLock<Arc<DashMap<(thread::ThreadId, String), Instant>>> =
    LazyLock::new(|| Arc::new(DashMap::new()));

pub fn simple_logger() -> Option<Box<dyn Instrumentation>> {
    Some(Box::new(|event: InstrumentationEvent<'_>| match event {
        InstrumentationEvent::StartEstablishConnection {
            url,
            ..
        } => {
            debug!("Establishing connection: {url}")
        }
        InstrumentationEvent::FinishEstablishConnection {
            url,
            error,
            ..
        } => {
            if let Some(e) = error {
                error!("Error during establishing a connection with {url}: {e:?}")
            } else {
                debug!("Connection established: {url}")
            }
        }
        InstrumentationEvent::StartQuery {
            query,
            ..
        } => {
            let query_string = format!("{query:?}");
            let start = Instant::now();
            QUERY_PERF_TRACKER.insert((thread::current().id(), query_string), start);
        }
        InstrumentationEvent::FinishQuery {
            query,
            ..
        } => {
            let query_string = format!("{query:?}");
            if let Some((_, start)) = QUERY_PERF_TRACKER.remove(&(thread::current().id(), query_string.clone())) {
                let duration = start.elapsed();
                if duration.as_secs() >= 5 {
                    warn!("SLOW QUERY [{:.2}s]: {}", duration.as_secs_f32(), query_string);
                } else if duration.as_secs() >= 1 {
                    info!("SLOW QUERY [{:.2}s]: {}", duration.as_secs_f32(), query_string);
                } else {
                    debug!("QUERY [{:?}]: {}", duration, query_string);
                }
            }
        }
        _ => {}
    }))
}
