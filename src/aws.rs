#[cfg(dsql)]
use std::io::Error;

use aws_config::{AppName, BehaviorVersion};
use tokio::sync::OnceCell;

use crate::http_client::aws::AwsReqwestConnector;

fn aws_reqwest_connector() -> AwsReqwestConnector {
    let reqwest_client = reqwest::Client::builder().build().expect("Failed to build reqwest client");

    AwsReqwestConnector {
        client: reqwest_client,
    }
}

pub(crate) async fn aws_sdk_config() -> &'static aws_config::SdkConfig {
    static AWS_CONFIG: OnceCell<aws_config::SdkConfig> = OnceCell::const_new();

    AWS_CONFIG
        .get_or_init(|| async {
            aws_config::defaults(BehaviorVersion::latest())
                .app_name(AppName::new("vaultwarden").expect("Failed to build AWS app name"))
                .http_client(aws_reqwest_connector())
                .load()
                .await
        })
        .await
}

#[cfg(dsql)]
pub(crate) fn aws_sdk_config_blocking() -> std::io::Result<&'static aws_config::SdkConfig> {
    std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        std::io::Result::Ok(rt.block_on(aws_sdk_config()))
    })
    .join()
    .map_err(|e| Error::other(format!("Failed to load AWS SDK config: {e:?}")))?
}
