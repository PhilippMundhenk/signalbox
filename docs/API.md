# HTTP API

The web interface uses this API; scripts can too. Log in with `POST /api/login`
(`{"password": "..."}`) and send the `signalbox_session` cookie with every request.
Requests that change something must be JSON (`content-type: application/json`) and come
from the same origin. Errors are `{"error": "<code>", "message": "<text>"}`.

Generated from the code by `tools/gen_api_doc.py`; a test keeps it current.

| Method | Path | What it does |
| --- | --- | --- |
| GET | `/api/health` | Liveness: version, number of devices, time of the last observation round. |
| GET | `/api/session` | Whether this browser is logged in. |
| POST | `/api/login` | Log in with the password; sets the session cookie. |
| POST | `/api/logout` | End the session. |
| POST | `/api/password` | Change the web interface password (ends all sessions). |
| GET | `/api/adapters` | Installed adapters with their settings form (JSON Schema). |
| GET | `/api/rules` | All rules with explanation, severity and whether they are enabled. |
| GET | `/api/sites` | List sites. |
| POST | `/api/sites` | Add a site. |
| PUT | `/api/sites/{site_id}` | Rename a site. |
| DELETE | `/api/sites/{site_id}` | Delete a site without devices. |
| GET | `/api/devices` | List devices with their last status. |
| POST | `/api/devices` | Add a device; secrets in `config` are stored encrypted. |
| GET | `/api/devices/{device_id}` | One device. |
| PUT | `/api/devices/{device_id}` | Change a device; secret settings left empty keep their value. |
| DELETE | `/api/devices/{device_id}` | Remove a device and its last snapshot. |
| POST | `/api/devices/{device_id}/test` | Read the device now and report status, errors and what was found. |
| POST | `/api/devices/{device_id}/trust` | Trust the certificate the device presented (pending fingerprint). |
| GET | `/api/network` | The merged network model (passphrase fingerprints removed). |
| GET | `/api/findings` | Current findings; `?resolved=true` includes resolved ones. |
| POST | `/api/observe` | Read all devices now. |
| GET | `/api/links` | Manually entered links (cables). |
| POST | `/api/links` | Add a link between two ports. |
| DELETE | `/api/links/{link_id}` | Delete a link. |
