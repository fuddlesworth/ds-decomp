use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use ds_decomp::config::config::Config;
use serde::Serialize;

use crate::{
    cmd::ARM9_LCF_FILE_NAME,
    config::{
        delinks::{DelinksMap, DelinksMapOptions},
        link_names::{LinkNames, object_to_link},
    },
    util::path::PathExt,
};

#[derive(Args)]
pub struct JsonDelinks {
    /// Path to config.yaml.
    #[arg(long, short = 'c')]
    pub config_path: PathBuf,
}

#[derive(Serialize)]
pub struct ModulesJson {
    pub arm9_lcf_file: PathBuf,
    pub arm9_objects_file: PathBuf,
    pub files: Vec<DelinkFileJson>,
}

#[derive(Serialize)]
pub struct DelinkFileJson {
    pub name: String,
    pub delink_file: PathBuf,
    /// The object that the link takes the file's code and data from.
    pub object_to_link: PathBuf,
    /// The path that the link's object list gives for it: `object_to_link`, or a copy of it that the build makes when
    /// another file has the same file name, which the linker script can't tell apart otherwise (see [`LinkNames`]).
    pub link_object: PathBuf,
}

impl JsonDelinks {
    pub fn run(&self) -> Result<()> {
        let json = self.modules_json()?;
        let json_string = serde_json::to_string_pretty(&json)?;
        println!("{json_string}");

        Ok(())
    }

    pub fn modules_json(&self) -> Result<ModulesJson> {
        let config = Config::from_file(&self.config_path)?;
        let config_dir = self.config_path.parent().unwrap();

        let build_path = config_dir.join(&config.build_path);
        let delinks_path = config_dir.join(&config.delinks_path);

        let delinks_map = DelinksMap::from_config(&config, config_dir, DelinksMapOptions {
            // Migrating would create delink files with identical names, which is wasteful when we
            // call `DelinksMap::delink_files()` later
            migrate_sections: false,
            generate_gap_files: true,
        })?;

        let link_names = LinkNames::new(&delinks_map);
        let files = delinks_map
            .delink_files()
            .map(|file| {
                let (file_path, _) = file.split_file_ext();
                let object_to_link = object_to_link(file, &build_path, &delinks_path);
                let link_object = link_names.link_object(file, &build_path, &delinks_path);
                let delink_file = delinks_path.join(&file_path).clean().with_extension("o");

                Ok(DelinkFileJson {
                    name: file.unique_name(),
                    delink_file,
                    object_to_link,
                    link_object,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let arm9_lcf_file = build_path.join(ARM9_LCF_FILE_NAME).clean();
        let arm9_objects_file = build_path.join("objects.txt").clean();

        Ok(ModulesJson { arm9_lcf_file, arm9_objects_file, files })
    }
}
