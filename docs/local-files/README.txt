Maqbool Mac companion - initial release

For Apple silicon Macs. Your cloud workspace works without this companion.
Use it when publishing approved files into a selected shared folder or editing
supported Word, Excel and PowerPoint documents inside Maqbool.

1. Move this whole folder somewhere you will keep it, such as Applications.
2. Open Setup.command. Enter your Maqbool website address and choose the folder
   Maqbool may publish into. Do not select a broader folder than you need.
3. Optional editing needs Docker Desktop already installed and running, and at
   least 4 GB of available memory. The first setup downloads the free community
   editor and can take several minutes. Shared-folder publishing needs no Docker.
4. macOS asks to trust a certificate for localhost only. This lets your browser
   securely reach this computer. Approve the certificate created by this setup.
5. Open Start.command. Keep its window open. The browser displays a connection
   code. As an Owner, open a project's Delivery > More > Shared folders
   in Maqbool and enter the code. Allow local network access if the browser asks.

If Apple asks for Command Line Tools, install them and run Setup.command again.
The companion uses Apple's Python 3 for safe access within the selected folder.
If macOS blocks the downloaded launcher, use its normal Open confirmation or
Privacy & Security controls after verifying the download came from your Maqbool
website. This initial package is not notarized. Do not disable Gatekeeper.

The companion runs on this Mac. Other members need their own appropriately
configured companion or can continue to edit externally and upload their work.
A shared-folder connection is project-specific and must be approved by an Owner.
After a workspace restore or removed folder access, close Start.command, then
open New connection.command. Confirm the replacement, reopen Start and have an
Owner connect the new code. Your selected folder and publication journals stay
intact; the old revoked connection is never reactivated.

Setup may be run again safely after an interrupted installation. Existing folder
and website choices are retained. An expired localhost certificate can be renewed
by removing only localhost.crt and localhost.key in the settings location below,
then rerunning Setup; keep the identity and config files.

Keep the companion open while publishing or editing. Close Start's window to
stop it. The optional editor continues running in Docker until you stop it there.
Files edited externally do not sync automatically: upload the updated file.
Downloading a delivery package does not publish it to your shared folder.

Privacy and recovery
- The cloud stores encrypted managed documents. A shared-drive reference backs
  up its description only, not the file on your drive.
- Publication checks the expected existing file before changing anything. If it
  differs, stop and review the change in Maqbool rather than deleting the file.
- Publication records and previous versions are retained under .maqbool-delivery
  inside your chosen folder. Keep that hidden folder until the delivery is
  confirmed and any recovery work is complete. It contains local private files;
  your usual shared-drive access and backup rules apply. It is not cloud storage.
- Local editing uses your Docker editor, not a public conversion service. Its
  temporary copies may remain in Docker's local cache until it cleans them. To
  remove that cache when no editing is active, remove maqbool-office in Docker
  and rerun Setup with editing enabled. Never remove it during an active save.
- Settings and the local identity are in ~/Library/Application Support/Maqbool/
  Shared Folder. Keep them private; never send config.json or office.env to others.

Troubleshooting
- Connection unavailable: open Start.command, open https://localhost:3411, check
  the localhost certificate, then allow local network access and retry.
- Editor unavailable: start Docker Desktop and the maqbool-office container;
  wait for it to become ready. You can download/edit/upload instead.
- File changed or disk full: free space or review the conflicting file, then
  resume in Maqbool. The companion does not overwrite unexpected changes.
- To disconnect: revoke the folder connection in Maqbool and close the companion.
  Remove the companion folder and its settings only after recovery is complete.
  You can remove its localhost certificate from Keychain Access afterwards.

Open-source notices are in licences/. ONLYOFFICE Community is a separate,
unmodified AGPL-licensed installation with its original branding preserved.
ONLYOFFICE: https://github.com/ONLYOFFICE/DocumentServer
Docker Desktop: https://docs.docker.com/desktop/setup/install/mac-install/
