use std::io::{Error, ErrorKind};

// Cache the AWS SDK config, as recommended by the AWS SDK documentation. The
// initial load is async, so we spawn a thread to load it and then join it to
// get the result in a blocking fashion.
static AWS_SDK_CONFIG: std::sync::LazyLock<std::io::Result<aws_config::SdkConfig>> = std::sync::LazyLock::new(|| {
    std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        
        std::io::Result::Ok(rt.block_on(aws_config::load_defaults(aws_config::BehaviorVersion::latest())))
    })
        .join()
        .map_err(|e| Error::new(ErrorKind::Other, format!("Failed to load AWS config for DSQL connection: {e:#?}")))?
        .map_err(|e| Error::new(ErrorKind::Other, format!("Failed to load AWS config for DSQL connection: {e}")))
});

pub(crate) fn aws_sdk_config() -> std::io::Result<&'static aws_config::SdkConfig> {
    (*AWS_SDK_CONFIG).as_ref().map_err(|e| match e.get_ref() {
        Some(inner) => Error::new(e.kind(), inner),
        None => Error::from(e.kind()),
    })
}