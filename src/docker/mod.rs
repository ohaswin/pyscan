use std::path::{PathBuf, Path};
use tokio::process::Command;

use crate::parser::scan_dir;
use crate::error::PyscanError;

pub async fn list_files_in_docker_image(image: &str, path: PathBuf) -> crate::error::Result<()> {
    // Create a container from the image without starting it
    let output = Command::new("docker")
        .arg("create")
        .arg(image)
        .output()
        .await
        .map_err(|e| PyscanError::Docker(e.to_string()))?;

    if !output.status.success() {
        return Err(PyscanError::Docker(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    let container_id = String::from_utf8(output.stdout)
        .map_err(|e| PyscanError::Docker(e.to_string()))?
        .trim()
        .to_string();

    // Create a tmp folder to keep our docker-files
    create_tmp_folder(".")
        .map_err(|e| PyscanError::Docker(format!("Could not create a temporary folder for the docker files: {e}")))?;

    // Copy files from the container to a temporary directory on the host
    let output = Command::new("docker")
        .current_dir(".")
        .arg("cp")
        .arg(format!(
            "{}:/{}",
            container_id,
            path.to_str().expect("Path contains non-unicode characters")
        ))
        .arg("./tmp/docker-files")
        .output()
        .await
        .map_err(|e| PyscanError::Docker(e.to_string()))?;

    if !output.status.success() {
        return Err(PyscanError::Docker(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    scan_dir(Path::new("./tmp/docker-files")).await?;
    cleanup().map_err(|e| PyscanError::Docker(e.to_string()))?;

    // docker stop
    let _output = Command::new("docker")
        .arg("stop")
        .arg(&container_id)
        .output()
        .await
        .map_err(|e| PyscanError::Docker(e.to_string()))?;

    // docker remove
    let _output = Command::new("docker")
        .arg("rm")
        .arg(&container_id)
        .output()
        .await
        .map_err(|e| PyscanError::Docker(e.to_string()))?;

    Ok(())
}

fn create_tmp_folder(path: &str) -> std::io::Result<()> {
    let tmp_path = format!("{}/tmp/docker-files", path);
    std::fs::create_dir_all(tmp_path)?;
    Ok(())
}

fn cleanup() -> Result<(), std::io::Error> {
    std::fs::remove_dir_all("./tmp/docker-files")
}
