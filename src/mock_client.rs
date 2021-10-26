#[cfg(test)]
pub(crate) mod test {
    use anyhow::{anyhow, Result};
    use async_trait::async_trait;
    use oci_distribution::{
        client::ImageData, manifest::OciManifest, secrets::RegistryAuth, Reference,
    };

    #[derive(Default)]
    pub struct MockOciClient {
        pub fetch_manifest_digest_response: Option<Result<String>>,
        pub pull_response: Option<Result<ImageData>>,
        pub pull_manifest_response: Option<Result<(OciManifest, String)>>,
    }

    #[async_trait]
    impl crate::registry::ClientCapabilities for MockOciClient {
        async fn fetch_manifest_digest(
            &mut self,
            _image: &Reference,
            _auth: &RegistryAuth,
        ) -> Result<String> {
            let mock_response = self
                .fetch_manifest_digest_response
                .as_ref()
                .ok_or_else(|| anyhow!("No fetch_manifest_digest_response provided!"))?;

            match mock_response {
                Ok(r) => Ok(r.clone()),
                Err(e) => Err(anyhow!("{:?}", e)),
            }
        }

        async fn pull(
            &mut self,
            _image: &Reference,
            _auth: &RegistryAuth,
            _accepted_media_types: Vec<&str>,
        ) -> Result<ImageData> {
            let mock_response = self
                .pull_response
                .as_ref()
                .ok_or_else(|| anyhow!("No pull_response provided!"))?;

            match mock_response {
                Ok(r) => Ok(r.clone()),
                Err(e) => Err(anyhow!("{:?}", e)),
            }
        }

        async fn pull_manifest(
            &mut self,
            _image: &Reference,
            _auth: &RegistryAuth,
        ) -> Result<(OciManifest, String)> {
            let mock_response = self
                .pull_manifest_response
                .as_ref()
                .ok_or_else(|| anyhow!("No pull_manifest_response provided!"))?;

            match mock_response {
                Ok(r) => Ok(r.clone()),
                Err(e) => Err(anyhow!("{:?}", e)),
            }
        }
    }
}
