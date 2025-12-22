#![allow(dead_code, unused_imports)]
/// Database metrics collection utilities

use std::time::Instant;

/// Database operation tracker for metrics
pub struct DbOperationTimer {
    start_time: Instant,
    operation: String,
}

impl DbOperationTimer {
    pub fn new(operation: &str) -> Self {
        Self {
            start_time: Instant::now(),
            operation: operation.to_string(),
        }
    }

    pub fn finish(self) {
        let duration = self.start_time.elapsed();
        crate::metrics::observe_db_query_duration(&self.operation, duration.as_secs_f64());
    }
}

/// Macro to instrument database operations
#[macro_export]
macro_rules! db_metric {
    ($operation:expr, $code:block) => {{
        #[cfg(feature = "enable_metrics")]
        let timer = crate::db::metrics::DbOperationTimer::new($operation);

        let result = $code;

        #[cfg(feature = "enable_metrics")]
        timer.finish();

        result
    }};
}

/// Track database connection pool statistics
pub async fn update_pool_metrics(_pool: &crate::db::DbPool) {
    #[cfg(feature = "enable_metrics")]
    {
        // Note: This is a simplified implementation
        // In a real implementation, you'd want to get actual pool statistics
        // from the connection pool (r2d2 provides some stats)

        // For now, we'll just update with basic info
        let db_type = crate::db::DbConnType::from_url(&crate::CONFIG.database_url())
            .map(|t| match t {
                crate::db::DbConnType::sqlite => "sqlite",
                crate::db::DbConnType::mysql => "mysql",
                crate::db::DbConnType::postgresql => "postgresql",
            })
            .unwrap_or("unknown");

        // These would be actual pool statistics in a real implementation
        let active_connections = 1; // placeholder
        let idle_connections = crate::CONFIG.database_max_conns() as i64 - active_connections;

        crate::metrics::update_db_connections(db_type, active_connections, idle_connections);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_db_operation_timer() {
        let timer = DbOperationTimer::new("test_query");
        thread::sleep(Duration::from_millis(1));
        timer.finish();
        // In a real test, we'd verify the metric was recorded
    }
}