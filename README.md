<div align="center">
  <img src="https://raw.githubusercontent.com/openwrt/branding/refs/heads/master/logo/openwrt_logo_blue_and_dark_blue.png" alt="OpenWrt" height="100" style="vertical-align:middle;display:inline-block;"/>
  <img src="https://mohammad-abbasi.me/arvan-logo-no-background.svg" alt="ArvanCloud" height="100" style="vertical-align:middle;display:inline-block;"/>
</div>

<h1 align="center">OpenWrt ArvanCloud CloudLogs Forwarder</h1>

<p align="center">
  <strong>A lightweight, high-performance daemon to forward OpenWrt logs to ArvanCloud.</strong>

</p>

---

`arvancloud-cloudlogs` is a lightweight, high-performance daemon for OpenWrt devices. It seamlessly subscribes to the system log (logd) via ubus and forwards log entries in efficient batches to the ArvanCloud CloudLogs service.

This daemon is designed to be resource-efficient, making it ideal for low-resource OpenWrt devices. It operates in the background, buffering logs and forwarding them securely to your configured ArvanCloud endpoint.


## Build

---
To build this package, you can use the OpenWrt SDK or include it as a package feed in your OpenWrt buildroot.

1. Place the `arvancloud-cloudlogs` package directory under `<buildroot>/package/`.

2. Run `make menuconfig` and navigate to **Utilities** -> `arvancloud-cloudlogs` to enable it.

3. Build the package:
    ```Bash
    make package/arvancloud-cloudlogs/compile V=sc
    ```

4. The compiled `.ipk` file will be available in `<buildroot>/bin/packages/<arch>/`.

## Installation

---

### Manual Download
You can download the latest release from the [Releases](https://github.com/mohammadv184/openwrt-arvancloud-cloudlogs/releases) page,
then move the `.ipk` file to your OpenWrt device and install it using `opkg`:
```sh
opkg install arvancloud-cloudlogs_*.ipk
```
Or via Luci Web Interface:

Navigate to **System** -> **Software** -> **Packages** and click **Upload Package**,
then select the `.ipk` file you downloaded.


## Configuration

---

Configuration is managed via the UCI file: `/etc/config/arvancloud-cloudlogs`.

```
config arvancloud-cloudlogs 'main'
	option enabled '0'
	option api_key ''
	option device_name ''
	option max_buffer_size '500'
	option max_buffer_bytes '524288'
	option flush_interval_sec '10'
	option min_batch_size '10'
	option allow_partial_process '0'
```

### Configuration Options

| Option                      | Type      | Default          | CLI Flag | Description                                                                                                                                         |
|:----------------------------|:----------|:-----------------|:---------|:----------------------------------------------------------------------------------------------------------------------------------------------------|
| **`enabled`**               | `boolean` | `0`              | -        | Set to `1` to enable the service.                                                                                                                   |
| **`api_key`**               | `string`  | `(empty)`        | `-k`     | **(Required)** Your ArvanCloud API key. The service will not start without this, see [Doc](https://docs.arvancloud.ir/en/accounts/iam/machine-user) |
| **`device_name`**           | `string`  | `(hostname)`     | `-d`     | An identifier for this device. If left empty, the system's hostname is used.                                                                        |
| **`max_buffer_size`**       | `integer` | `500`            | `-b`     | The maximum number of log entries to hold in memory before forcing a flush.                                                                         |
| **`max_buffer_bytes`**      | `integer` | `524288` (512KB) | `-m`     | The maximum total size (in bytes) of the log buffer before forcing a flush.                                                                         |
| **`flush_interval_sec`**    | `integer` | `10`             | `-f`     | The maximum time (in seconds) to wait before flushing the buffer, even if not full.                                                                 |
| **`min_batch_size`**        | `integer` | `10`             | `-t`     | The minimum number of logs required to trigger a flush (unless the flush interval expires).                                                         |
| **`allow_partial_process`** | `boolean` | `0`              | `-p`     | Set to `1` to allow ArvanCloud to process a batch partially if some logs are invalid.                                                               |

After modifying the configuration, restart the service to apply changes:

```sh
service arvancloud-cloudlogs restart
```

## Service Management

---

The service is managed by `procd` and can be controlled via the standard `init.d` script or via `service` command.

* **Start & Enable**:
    ```sh
    service arvancloud-cloudlogs enable # to be automatically started on boot
    service arvancloud-cloudlogs start  # to start immediately
    ```
* **Stop & Disable**:
    ```sh
    service arvancloud-cloudlogs stop    # to stop immediately
    service arvancloud-cloudlogs disable # to not be automatically started on boot
    ```
* **Check Status**:
    ```sh
    service arvancloud-cloudlogs status
    ```
* **Restart**:
    ```sh
    service arvancloud-cloudlogs restart
    ```


## Contributing

---

Contributions are welcome! Please open issues or pull requests for improvements or bug fixes.

## Security

---

If you discover any security-related issues, please email mohammadv184@gmail.com instead of using the issue tracker.

## Credits

---

- [Mohammad Abbasi](https://mohammad-abbasi.me)
- [All Contributors](../../contributors)


## License

---

The Apache 2.0 License (Apache-2.0). Please see [License File](LICENSE) for more information.
