# MSI installer (WiX v4) + code signing

Turns the agent into a proper MSI for Add/Remove Programs + silent GPO/Intune deployment.

## Build (needs WiX v4 + .NET)
```
dotnet tool install --global wix          # once
# from repo root, with dist\SNSSecurityAgent\*.exe present (run installer\package.ps1 first):
wix build installer\wix\Product.wxs -o dist\SNSSecurityAgent.msi
```

## Code signing (REQUIRED for distribution — needs a purchased certificate)
Without an EV/OV code-signing certificate, Windows SmartScreen + many AV products will block
the installer on customer machines.
```
signtool sign /fd SHA256 /a /tr http://timestamp.digicert.com /td SHA256 dist\SNSSecurityAgent.msi
# also sign the exes before packaging for best results.
```
Cert options: OV (~$250/yr) or EV (~$300–600/yr, best SmartScreen reputation). This is a
procurement step for the owner.

## Silent / mass deploy
```
msiexec /i SNSSecurityAgent.msi /qn SYSTEMNAME=%COMPUTERNAME% ADMINPASS=Secret ENROLL=<token> SERVER=https://sns.example.com
```

## Status
`Product.wxs` here is the authoring skeleton (files + upgrade + public properties). The deferred
custom action that runs `install.ps1` (service, scheduled tasks, ACLs, `sns-agentctl init`, and
`enroll`) must be wired per your WiX version — the reference logic already exists in
`installer/install.ps1`. Until the MSI is finalized + signed, deploy with the zip bundle +
`install.ps1` (works today).
