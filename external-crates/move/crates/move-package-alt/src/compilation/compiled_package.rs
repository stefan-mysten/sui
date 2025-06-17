// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    flavor::MoveFlavor,
    graph::PackageGraph,
    package::{EnvironmentName, Package, RootPackage, lockfile::DependencyInfo},
};

use move_bytecode_source_map::utils::{serialize_to_json, serialize_to_json_string};

use move_command_line_common::files::{
    DEBUG_INFO_EXTENSION, MOVE_BYTECODE_EXTENSION, MOVE_COMPILED_EXTENSION, MOVE_EXTENSION,
    find_move_filenames,
};
use move_compiler::{
    compiled_unit::CompiledUnit,
    diagnostics::{report_diagnostics_to_buffer, warning_filters::WarningFiltersBuilder},
    shared::{PackageConfig, PackagePaths, files::FileName},
};
use move_core_types::{identifier::Identifier, parsing::address::NumericalAddress};
use move_disassembler::disassembler::Disassembler;
use move_package::compilation::{
    compiled_package::ModuleFormat, package_layout::CompiledPackageLayout,
};
use move_symbol_pool::Symbol;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Path, PathBuf},
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BuildConfig {
    pub save_disassembly: bool,
}

pub struct CompiledPackage {
    /// The path to the compiled package
    pub path: String,

    /// The dependencies of the package
    pub dependencies: BTreeMap<EnvironmentName, DependencyInfo>,
}

pub fn compile<F: MoveFlavor>(root_pkg: RootPackage<F>) {
    let pkgs = BTreeSet::from(["Sui", "SuiSystem", "MoveStdlib"]);
    let default_addresses = BTreeMap::from([
        (
            Symbol::from("std"),
            NumericalAddress::parse_str("0x1").unwrap(),
        ),
        (
            Symbol::from("sui"),
            NumericalAddress::parse_str("0x2").unwrap(),
        ),
        (
            Symbol::from("sui_system"),
            NumericalAddress::parse_str("0x3").unwrap(),
        ),
    ]);

    let mut starting_addr = 9010;
    let mut named_address_map: BTreeMap<Symbol, NumericalAddress> = BTreeMap::new();
    let root_pkg_paths = find_move_filenames(&[root_pkg.package_path().path().as_path()], false)
        .unwrap()
        .into_iter()
        .map(FileName::from)
        .collect::<Vec<_>>();

    // compile just first environment
    if let Some(entry) = &root_pkg.dependencies().first_key_value() {
        let deps = entry.1;
        let mut deps_paths = vec![];
        let nodes = deps.nodes();

        for node in nodes {
            println!("Building dependency: {}", node.package.name());
            let node_path = vec![node.package.path().path().as_path()];
            let paths = find_move_filenames(&node_path, false)
                .unwrap()
                .into_iter()
                .map(FileName::from)
                .collect::<Vec<_>>();
            let is_dependency = if node.package.name() == root_pkg.package_name() {
                false
            } else {
                true
            };

            starting_addr = starting_addr + 1;
            let pkg_name: Symbol = node.package.name().as_str().into();
            let addr = NumericalAddress::parse_str(&format!("0x{starting_addr}")).expect("fine");
            let named_address_map = if pkgs.contains(node.package.name().as_str()) {
                default_addresses.clone()
            } else {
                let mut addresses = BTreeMap::from(default_addresses.clone());
                addresses.extend([(pkg_name, addr)]);
                addresses
            };

            let source_package_paths: PackagePaths<Symbol, Symbol> = PackagePaths {
                name: Some((
                    node.package.name().as_str().into(),
                    PackageConfig {
                        is_dependency: true,
                        warning_filter: WarningFiltersBuilder::new_for_source(),
                        flavor: move_compiler::editions::Flavor::Sui,
                        edition: move_compiler::editions::Edition {
                            edition: root_pkg.edition().into(),
                            release: None,
                        },
                    },
                )),
                named_address_map,
                paths,
            };

            deps_paths.push(source_package_paths);
        }

        let compiler = move_compiler::Compiler::from_package_paths(None, deps_paths, vec![]);

        let result = compiler.unwrap();
        let data = result.build();

        println!("Compiled ok: {}", data.is_ok());

        let root_package_name = root_pkg.package_name().as_str().into();

        let (file_map, all_compiled_units) = data.unwrap();
        let all_compiled_units = all_compiled_units.unwrap().0;
        let mut all_compiled_units_vec = vec![];
        let mut root_compiled_units = vec![];
        let mut deps_compiled_units = vec![];

        for mut annot_unit in all_compiled_units {
            let source_path = PathBuf::from(
                file_map
                    .get(&annot_unit.loc().file_hash())
                    .unwrap()
                    .0
                    .as_str(),
            );
            let package_name = annot_unit.named_module.package_name.unwrap();
            // unwraps below are safe as the source path exists (or must have existed at some point)
            // so it would be syntactically correct
            let file_name = PathBuf::from(source_path.file_name().unwrap());
            if let Ok(p) = dunce::canonicalize(source_path.parent().unwrap()) {
                annot_unit
                    .named_module
                    .source_map
                    .set_from_file_path(p.join(file_name));
            }
            let unit = CompiledUnitWithSource {
                unit: annot_unit.named_module,
                source_path,
            };
            if package_name == root_package_name {
                root_compiled_units.push(unit.clone())
            } else {
                deps_compiled_units.push((package_name, unit.clone()))
            }
            all_compiled_units_vec.push((unit.source_path, unit.unit));
        }

        let compiled_package_info = CompiledPackageInfo {
            package_name: root_package_name,
            address_alias_instantiation: BTreeMap::new(),
            source_digest: None,
            build_flags: BuildConfig {
                save_disassembly: true,
            },
        };

        save_to_disk(
            root_compiled_units,
            compiled_package_info,
            deps_compiled_units,
            root_pkg,
            PathBuf::from(".").join("build"),
        );

        //
        // let (files, units_res) = data.unwrap();
        // match units_res {
        //     Ok((units, warning_diags)) => {
        //         decorate_warnings(warning_diags, Some(&files));
        //         fn_info = Some(Self::fn_info(&units));
        //         Ok((files, units))
        //     }
        //     Err(error_diags) => {
        //         // with errors present don't even try decorating warnings output to avoid
        //         // clutter
        //         assert!(!error_diags.is_empty());
        //         let diags_buf =
        //             report_diagnostics_to_buffer(&files, error_diags, /* color */ true);
        //         if let Err(err) = std::io::stderr().write_all(&diags_buf) {
        //             anyhow::bail!("Cannot output compiler diagnostics: {}", err);
        //         }
        //         anyhow::bail!("Compilation error");
        //     }
        // }

        // println!("Compiled package data: {:?}", data.unwrap().1.unwrap_err());
    }
}

fn find_default_address<'a>(
    pkg_name: &Identifier,
    default_addresses: &'a BTreeMap<Symbol, NumericalAddress>,
) -> Option<&'a NumericalAddress> {
    let std = Identifier::from_utf8("MoveStdlib".into()).unwrap();
    let sui = Identifier::from_utf8("Sui".into()).unwrap();
    let system = Identifier::from_utf8("SuiSystem".into()).unwrap();
    match pkg_name {
        std => default_addresses.get(&("std".into())),
        sui => default_addresses.get(&("sui".into())),
        system => default_addresses.get(&("sui_system".into())),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledPackageInfo {
    /// The name of the compiled package
    pub package_name: Symbol,
    /// The instantiations for all named addresses that were used for compilation
    pub address_alias_instantiation: BTreeMap<String, String>,
    /// The hash of the source directory at the time of compilation. `None` if the source for this
    /// package is not available/this package was not compiled.
    pub source_digest: Option<String>,
    /// The build flags that were used when compiling this package.
    pub build_flags: BuildConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnDiskPackage {
    /// Information about the package and the specific compilation that was done.
    pub compiled_package_info: CompiledPackageInfo,
    /// Dependency names for this package.
    pub dependencies: Vec<Symbol>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnDiskCompiledPackage {
    /// Path to the root of the package and its data on disk. Relative to/rooted at the directory
    /// containing the `Move.toml` file for this package.
    pub root_path: PathBuf,
    pub package: OnDiskPackage,
}

#[derive(Debug, Clone)]
pub struct CompiledUnitWithSource {
    pub unit: CompiledUnit,
    pub source_path: PathBuf,
}

impl OnDiskCompiledPackage {
    /// Save `bytes` under `path_under` relative to the package on disk
    pub(crate) fn save_under(&self, file: impl AsRef<Path>, bytes: &[u8]) -> anyhow::Result<()> {
        let path_to_save = self.root_path.join(file);
        let parent = path_to_save.parent().unwrap();
        std::fs::create_dir_all(parent)?;
        std::fs::write(path_to_save, bytes).map_err(|err| err.into())
    }

    fn save_disassembly_to_disk(
        &self,
        package_name: Symbol,
        unit: &CompiledUnitWithSource,
    ) -> anyhow::Result<()> {
        let root_package = self.package.compiled_package_info.package_name;
        assert!(self.root_path.ends_with(root_package.as_str()));
        let disassembly_dir = CompiledPackageLayout::Disassembly.path();
        let file_path = if root_package == package_name {
            PathBuf::new()
        } else {
            CompiledPackageLayout::Dependencies
                .path()
                .join(package_name.as_str())
        }
        .join(unit.unit.name.as_str());
        let d = Disassembler::from_unit(&unit.unit);
        let (disassembled_string, mut bytecode_map) = d.disassemble_with_source_map()?;
        let disassembly_file_path = disassembly_dir
            .join(&file_path)
            .with_extension(MOVE_BYTECODE_EXTENSION);
        self.save_under(
            disassembly_file_path.clone(),
            disassembled_string.as_bytes(),
        )?;
        // unwrap below is safe as we just successfully saved a file at disassembly_file_path
        if let Ok(p) =
            dunce::canonicalize(self.root_path.join(disassembly_file_path).parent().unwrap())
        {
            bytecode_map
                .set_from_file_path(p.join(&file_path).with_extension(MOVE_BYTECODE_EXTENSION));
        }
        self.save_under(
            disassembly_dir.join(&file_path).with_extension("json"),
            serialize_to_json_string(&bytecode_map)?.as_bytes(),
        )
    }

    fn save_compiled_unit(
        &self,
        package_name: Symbol,
        compiled_unit: &CompiledUnitWithSource,
    ) -> anyhow::Result<()> {
        let root_package = &self.package.compiled_package_info.package_name;
        // assert!(self.root_path.ends_with(root_package.as_str()));
        let category_dir = CompiledPackageLayout::CompiledModules.path();
        let root_pkg_name: Symbol = root_package.as_str().into();
        let file_path = if root_pkg_name == package_name {
            PathBuf::new()
        } else {
            CompiledPackageLayout::Dependencies
                .path()
                .join(package_name.as_str())
        }
        .join(compiled_unit.unit.name.as_str());

        self.save_under(
            category_dir
                .join(&file_path)
                .with_extension(MOVE_COMPILED_EXTENSION),
            compiled_unit.unit.serialize().as_slice(),
        )?;
        self.save_under(
            CompiledPackageLayout::DebugInfo
                .path()
                .join(&file_path)
                .with_extension(DEBUG_INFO_EXTENSION),
            compiled_unit.unit.serialize_source_map().as_slice(),
        )?;
        self.save_under(
            CompiledPackageLayout::DebugInfo
                .path()
                .join(&file_path)
                .with_extension("json"),
            &serialize_to_json(&compiled_unit.unit.source_map)?,
        )?;
        self.save_under(
            CompiledPackageLayout::Sources
                .path()
                .join(&file_path)
                .with_extension(MOVE_EXTENSION),
            std::fs::read_to_string(&compiled_unit.source_path)?.as_bytes(),
        )
    }
}

pub(crate) fn save_to_disk<F: MoveFlavor>(
    root_compiled_units: Vec<CompiledUnitWithSource>,
    compiled_package_info: CompiledPackageInfo,
    deps_compiled_units: Vec<(Symbol, CompiledUnitWithSource)>,
    root_pkg: RootPackage<F>,
    under_path: PathBuf,
) -> anyhow::Result<OnDiskCompiledPackage> {
    // self.check_filepaths_ok()?;
    // assert!(under_path.ends_with(CompiledPackageLayout::Root.path()));
    let root_package: Symbol = root_pkg.package_name().as_str().into();
    let on_disk_package = OnDiskCompiledPackage {
        root_path: under_path.join(root_package.to_string()),
        package: OnDiskPackage {
            compiled_package_info: compiled_package_info.clone(),
            dependencies: deps_compiled_units
                .iter()
                .map(|(package_name, _)| package_name.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        },
    };

    // Clear out the build dir for this package so we don't keep artifacts from previous
    // compilations
    if on_disk_package.root_path.is_dir() {
        std::fs::remove_dir_all(&on_disk_package.root_path)?;
    }

    std::fs::create_dir_all(&on_disk_package.root_path)?;

    for compiled_unit in root_compiled_units {
        on_disk_package.save_compiled_unit(root_package, &compiled_unit)?;
        // TODO: fix this
        // if compiled_package_info.build_flags.save_disassembly {
        //     on_disk_package.save_disassembly_to_disk(root_package, compiled_unit)?;
        // }
    }
    for (dep_name, compiled_unit) in deps_compiled_units {
        let dep_name: Symbol = dep_name.as_str().into();
        on_disk_package.save_compiled_unit(dep_name, &compiled_unit)?;
        if compiled_package_info.build_flags.save_disassembly {
            on_disk_package.save_disassembly_to_disk(dep_name, &compiled_unit)?;
        }
    }

    // if let Some(docs) = &self.compiled_docs {
    //     for (doc_filename, doc_contents) in docs {
    //         on_disk_package.save_under(
    //             CompiledPackageLayout::CompiledDocs
    //                 .path()
    //                 .join(doc_filename)
    //                 .with_extension("md"),
    //             doc_contents.clone().as_bytes(),
    //         )?;
    //     }
    // }

    on_disk_package.save_under(
        CompiledPackageLayout::BuildInfo.path(),
        serde_yaml::to_string(&on_disk_package.package)?.as_bytes(),
    )?;

    Ok(on_disk_package)
}
