import { spawnSync } from 'node:child_process';

/**
 * Best-effort desktop notification. The text is passed through environment variables, never
 * spliced into a script, so a package summary can't inject commands. Failures are silent.
 */

// Windows toast through WinRT from Windows PowerShell 5.1, using PowerShell's own app id.
const WIN_TOAST = `
$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml('<toast><visual><binding template="ToastGeneric"><text></text><text></text></binding></visual></toast>')
$t = $xml.GetElementsByTagName('text')
$t.Item(0).AppendChild($xml.CreateTextNode($env:PKGGUARD_TITLE)) > $null
$t.Item(1).AppendChild($xml.CreateTextNode($env:PKGGUARD_BODY)) > $null
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($xml))
`;

export function notifyCommand(platform: NodeJS.Platform = process.platform): { cmd: string; args: string[] } | undefined {
  if (platform === 'win32') {
    const encoded = Buffer.from(WIN_TOAST, 'utf16le').toString('base64');
    return { cmd: 'powershell.exe', args: ['-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-EncodedCommand', encoded] };
  }
  if (platform === 'darwin') {
    return { cmd: 'osascript', args: ['-e', 'display notification (system attribute "PKGGUARD_BODY") with title (system attribute "PKGGUARD_TITLE")'] };
  }
  return { cmd: 'sh', args: ['-c', 'notify-send "$PKGGUARD_TITLE" "$PKGGUARD_BODY"'] };
}

export function notify(title: string, body: string): boolean {
  const c = notifyCommand();
  if (!c || process.env.PKGGUARD_NO_NOTIFY === '1') return false;
  try {
    const r = spawnSync(c.cmd, c.args, {
      env: { ...process.env, PKGGUARD_TITLE: title.slice(0, 120), PKGGUARD_BODY: body.slice(0, 300) },
      stdio: 'ignore',
      timeout: 15000,
      windowsHide: true,
    });
    return r.status === 0;
  } catch {
    return false;
  }
}
