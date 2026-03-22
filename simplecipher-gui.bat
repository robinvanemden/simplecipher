@echo off
REM simplecipher-gui.bat — GUI launcher for SimpleCipher (Windows)
REM
REM Opens a PowerShell dialog to choose Listen/Connect, enter host/port,
REM then launches simplecipher.exe in a new console window.
REM
REM Usage: Double-click this file from Explorer.
REM        No dependencies beyond PowerShell (built into Windows 10+).

REM Find simplecipher.exe (same directory as this script)
set "SCRIPT_DIR=%~dp0"
set "CIPHER=%SCRIPT_DIR%simplecipher.exe"

if not exist "%CIPHER%" (
    powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('Cannot find simplecipher.exe.`nPlace it next to this script.', 'SimpleCipher', 'OK', 'Error')"
    exit /b 1
)

REM Launch PowerShell GUI
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
$ErrorActionPreference = 'Stop';^
Add-Type -AssemblyName System.Windows.Forms;^
Add-Type -AssemblyName System.Drawing;^
^
$form = New-Object System.Windows.Forms.Form;^
$form.Text = 'SimpleCipher';^
$form.Size = New-Object System.Drawing.Size(380, 340);^
$form.StartPosition = 'CenterScreen';^
$form.FormBorderStyle = 'FixedDialog';^
$form.MaximizeBox = $false;^
$form.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30);^
$form.ForeColor = [System.Drawing.Color]::FromArgb(240, 240, 240);^
^
$title = New-Object System.Windows.Forms.Label;^
$title.Text = 'SimpleCipher';^
$title.Font = New-Object System.Drawing.Font('Segoe UI', 16, [System.Drawing.FontStyle]::Bold);^
$title.Location = New-Object System.Drawing.Point(20, 15);^
$title.AutoSize = $true;^
$form.Controls.Add($title);^
^
$subtitle = New-Object System.Windows.Forms.Label;^
$subtitle.Text = 'Encrypted peer-to-peer chat';^
$subtitle.Font = New-Object System.Drawing.Font('Segoe UI', 9);^
$subtitle.ForeColor = [System.Drawing.Color]::FromArgb(150, 150, 150);^
$subtitle.Location = New-Object System.Drawing.Point(22, 48);^
$subtitle.AutoSize = $true;^
$form.Controls.Add($subtitle);^
^
$rbListen = New-Object System.Windows.Forms.RadioButton;^
$rbListen.Text = 'Listen (wait for peer)';^
$rbListen.Location = New-Object System.Drawing.Point(25, 85);^
$rbListen.AutoSize = $true;^
$rbListen.Checked = $true;^
$form.Controls.Add($rbListen);^
^
$rbConnect = New-Object System.Windows.Forms.RadioButton;^
$rbConnect.Text = 'Connect (to a peer)';^
$rbConnect.Location = New-Object System.Drawing.Point(25, 110);^
$rbConnect.AutoSize = $true;^
$form.Controls.Add($rbConnect);^
^
$hostLabel = New-Object System.Windows.Forms.Label;^
$hostLabel.Text = 'Host or IP address:';^
$hostLabel.Location = New-Object System.Drawing.Point(22, 145);^
$hostLabel.AutoSize = $true;^
$hostLabel.Visible = $false;^
$form.Controls.Add($hostLabel);^
^
$hostBox = New-Object System.Windows.Forms.TextBox;^
$hostBox.Location = New-Object System.Drawing.Point(25, 165);^
$hostBox.Size = New-Object System.Drawing.Size(310, 25);^
$hostBox.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 50);^
$hostBox.ForeColor = [System.Drawing.Color]::FromArgb(240, 240, 240);^
$hostBox.Visible = $false;^
$form.Controls.Add($hostBox);^
^
$portLabel = New-Object System.Windows.Forms.Label;^
$portLabel.Text = 'Port (default 7777):';^
$portLabel.Location = New-Object System.Drawing.Point(22, 200);^
$portLabel.AutoSize = $true;^
$form.Controls.Add($portLabel);^
^
$portBox = New-Object System.Windows.Forms.TextBox;^
$portBox.Text = '7777';^
$portBox.Location = New-Object System.Drawing.Point(25, 220);^
$portBox.Size = New-Object System.Drawing.Size(100, 25);^
$portBox.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 50);^
$portBox.ForeColor = [System.Drawing.Color]::FromArgb(240, 240, 240);^
$form.Controls.Add($portBox);^
^
$tuiCheck = New-Object System.Windows.Forms.CheckBox;^
$tuiCheck.Text = 'Use TUI (split-pane interface)';^
$tuiCheck.Location = New-Object System.Drawing.Point(25, 255);^
$tuiCheck.AutoSize = $true;^
$form.Controls.Add($tuiCheck);^
^
$goBtn = New-Object System.Windows.Forms.Button;^
$goBtn.Text = 'Start';^
$goBtn.Location = New-Object System.Drawing.Point(235, 250);^
$goBtn.Size = New-Object System.Drawing.Size(100, 35);^
$goBtn.BackColor = [System.Drawing.Color]::FromArgb(77, 208, 176);^
$goBtn.ForeColor = [System.Drawing.Color]::FromArgb(13, 13, 13);^
$goBtn.FlatStyle = 'Flat';^
$goBtn.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold);^
$form.Controls.Add($goBtn);^
$form.AcceptButton = $goBtn;^
^
$rbConnect.Add_CheckedChanged({ $hostLabel.Visible = $rbConnect.Checked; $hostBox.Visible = $rbConnect.Checked });^
$rbListen.Add_CheckedChanged({ $hostLabel.Visible = $rbConnect.Checked; $hostBox.Visible = $rbConnect.Checked });^
^
$goBtn.Add_Click({^
    $port = $portBox.Text.Trim();^
    if (-not $port) { $port = '7777' };^
    $tui = '';^
    if ($tuiCheck.Checked) { $tui = '--tui' };^
    if ($rbConnect.Checked) {^
        $host = $hostBox.Text.Trim();^
        if (-not $host) { [System.Windows.Forms.MessageBox]::Show('Host is required.', 'SimpleCipher'); return };^
        $script = 'cmd /c \"\"' + '%CIPHER%'.Replace('\', '/') + '\" ' + $tui + ' connect ' + $host + ' ' + $port + ' & echo. & echo Press Enter to close... & pause >nul\"';^
    } else {^
        $script = 'cmd /c \"\"' + '%CIPHER%'.Replace('\', '/') + '\" ' + $tui + ' listen ' + $port + ' & echo. & echo Press Enter to close... & pause >nul\"';^
    };^
    Start-Process cmd -ArgumentList '/c', $script;^
    $form.Close();^
});^
^
[void]$form.ShowDialog()

