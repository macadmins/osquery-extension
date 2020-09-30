# macadmins-extension

## Usage

For testing, you can load the extension with `osqueryi`.

By default, osquery does not want to load extensions not owned by root. You can either change the ownership of macadmins_extension.ext to root, or run osquery with the `--allow_unsafe` flag.

```bash
osqueryi --extension /path/to/macadmins_extension.ext
```

For production deployment, you should refer to the [osquery documentation](https://osquery.readthedocs.io/en/stable/deployment/extensions/).

## Tables

| Table                    | Description                                                                                   | Platforms               | Notes                                                                                                                                                                                                                               |
| ------------------------ | --------------------------------------------------------------------------------------------- | ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `file_lines`             | Read an arbitrary file                                                                        | Linux / macOS / Windows | Use the constraint `path` and `last` to specify the file to read lines from                                                                                                                                                         |
| `filevault_users`        | Information on the users able to unlock the current boot volume when encrypted with Filevault | macOS                   |                                                                                                                                                                                                                                     |
| `google_chrome_profiles` | Profiles configured in Google Chrome.                                                         | Linux / macOS / Windows |                                                                                                                                                                                                                                     |
| `macos_profiles`         | High level information on installed profiles enrollment                                       | macOS                   |
| `mdm`                    | Information on the device's MDM enrollment                                                    | macOS                   | Code based on work by [Kolide](https://github.com/kolide/launcher)                                                                                                                                                                  |
| `munki_info`             | Information from the last [Munki](https://github.com/munki/munki) run                         | macOS                   | Code based on work by [Kolide](https://github.com/kolide/launcher)                                                                                                                                                                  |
| `munki_installs`         | Items [Munki](https://github.com/munki/munki) is managing                                     | macOS                   | Code based on work by [Kolide](https://github.com/kolide/launcher)                                                                                                                                                                  |
| `puppet_info`            | Information on the last [Puppet](https://puppetlabs.com) run                                  | Linux / macOS / Windows |                                                                                                                                                                                                                                     |
| `puppet_logs`            | Logs from the last [Puppet](https://puppetlabs.com) run                                       | Linux / macOS / Windows |                                                                                                                                                                                                                                     |
| `puppet_state`           | State of every resource [Puppet](https://puppetlabs.com) is managing                          | Linux / macOS / Windows |                                                                                                                                                                                                                                     |
| `unified_log`            | Results from macOS' Unified Log                                                               | macOS                   | Use the constraints `predicate` and `last` to limit the number of results you pull, or this will not be very performant at all (`select * from unified_log where last="1h" and predicate='processImagePath contains "mdmclient"';`) |
