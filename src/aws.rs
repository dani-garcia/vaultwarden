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
