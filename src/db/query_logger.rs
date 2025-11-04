use diesel::connection::{Instrumentation, InstrumentationEvent};
use std::{cell::RefCell, collections::HashMap, time::Instant};

thread_local! {
    static QUERY_PERF_TRACKER: RefCell<HashMap<String, Instant>> = RefCell::new(HashMap::new());
}

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
            QUERY_PERF_TRACKER.with_borrow_mut(|map| {
                map.insert(query_string, start);
            });
        }
        InstrumentationEvent::FinishQuery {
            query,
            ..
        } => {
            let query_string = format!("{query:?}");
            QUERY_PERF_TRACKER.with_borrow_mut(|map| {
                if let Some(start) = map.remove(&query_string) {
                    let duration = start.elapsed();
                    if duration.as_secs() >= 5 {
                        warn!("SLOW QUERY [{:.2}s]: {}", duration.as_secs_f32(), query_string);
                    } else if duration.as_secs() >= 1 {
                        info!("SLOW QUERY [{:.2}s]: {}", duration.as_secs_f32(), query_string);
                    } else {
                        debug!("QUERY [{:?}]: {}", duration, query_string);
                    }
                }
            });
        }
        _ => {}
    }))
}
