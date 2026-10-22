/* GENERATED once from the Flutter plugin's RaspDetectorDescriptor table. Keep in step with the dashboard. */
import type { DetectorId } from './types';

export type DetectorCategory =
  | 'deviceIntegrity' | 'runtimeProtection' | 'appIntegrity' | 'networkSecurity' | 'privacyScreen' | 'locationIntegrity' | 'other';
export type DetectorSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface DetectorDescriptor {
  id: DetectorId;
  title: string;
  category: DetectorCategory;
  severity: DetectorSeverity;
}

export const DETECTORS: readonly DetectorDescriptor[] = [
  { id: "screenshot_protection", title: "Screenshot & Video Block", category: "privacyScreen", severity: "medium" },
  { id: "usb_connection", title: "USB Connection", category: "deviceIntegrity", severity: "low" },
  { id: "adb_enabled", title: "USB Debugging (ADB)", category: "deviceIntegrity", severity: "medium" },
  { id: "clipboard_protection", title: "Clipboard Protection", category: "privacyScreen", severity: "low" },
  { id: "root_jailbreak", title: "Root / Jailbreak", category: "deviceIntegrity", severity: "critical" },
  { id: "emulator", title: "Emulator", category: "deviceIntegrity", severity: "medium" },
  { id: "device_binding", title: "Device Binding", category: "deviceIntegrity", severity: "high" },
  { id: "clone", title: "App Clone / Dual Space", category: "deviceIntegrity", severity: "high" },
  { id: "developer_mode", title: "Developer Mode", category: "deviceIntegrity", severity: "low" },
  { id: "device_lock_missing", title: "Device Lock", category: "deviceIntegrity", severity: "low" },
  { id: "secure_hardware_unavailable", title: "Hardware-Backed Keystore", category: "deviceIntegrity", severity: "low" },
  { id: "device_fingerprint", title: "Device Fingerprint", category: "deviceIntegrity", severity: "medium" },
  { id: "frida", title: "Frida", category: "runtimeProtection", severity: "critical" },
  { id: "debugger", title: "Debugger", category: "runtimeProtection", severity: "medium" },
  { id: "hook_detection", title: "Hook Detection", category: "runtimeProtection", severity: "critical" },
  { id: "re_tools", title: "Reverse Engineering Tools", category: "runtimeProtection", severity: "high" },
  { id: "risky_app", title: "Risky Application / Environment", category: "other", severity: "high" },
  { id: "tamper", title: "App Tampering", category: "appIntegrity", severity: "high" },
  { id: "repackage", title: "Repackaging", category: "appIntegrity", severity: "high" },
  { id: "untrusted_install_source", title: "Installation Source", category: "appIntegrity", severity: "high" },
  { id: "vpn", title: "VPN", category: "networkSecurity", severity: "low" },
  { id: "mitm", title: "MITM / Proxy", category: "networkSecurity", severity: "high" },
  { id: "high_risk_ip", title: "High-risk IP", category: "networkSecurity", severity: "medium" },
  { id: "overlay", title: "Overlay", category: "privacyScreen", severity: "medium" },
  { id: "accessibility", title: "Accessibility Abuse", category: "privacyScreen", severity: "medium" },
  { id: "external_display", title: "External Display / Mirroring", category: "privacyScreen", severity: "medium" },
  { id: "screenshot_event", title: "Screenshot Event", category: "privacyScreen", severity: "medium" },
  { id: "mock_location", title: "Mock Location", category: "deviceIntegrity", severity: "high" },
  { id: "time_spoofing", title: "Time Spoofing", category: "deviceIntegrity", severity: "medium" },
  { id: "unsafe_wifi", title: "Unsafe Wi-Fi", category: "networkSecurity", severity: "medium" },
  { id: "screen_recording", title: "Screen Recording", category: "privacyScreen", severity: "high" },
  { id: "vishing_call", title: "Call During App Use", category: "privacyScreen", severity: "high" },
  { id: "sim_change", title: "SIM Change", category: "deviceIntegrity", severity: "high" },
  { id: "third_party_keyboard", title: "Third-party Keyboard", category: "privacyScreen", severity: "medium" },
  { id: "task_hijack", title: "Task Hijacking", category: "appIntegrity", severity: "high" },
  { id: "device_state_attestation", title: "Device State Attestation", category: "deviceIntegrity", severity: "high" },
  { id: "malware_reputation", title: "Known Malware Installed", category: "deviceIntegrity", severity: "critical" },
  { id: "otp_interception_risk", title: "OTP Interception Risk", category: "privacyScreen", severity: "high" },
  { id: "sms_reader_abuse", title: "SMS Reader Apps", category: "privacyScreen", severity: "high" },
  { id: "otp_forwarding_risk", title: "OTP Forwarding Risk (hint)", category: "privacyScreen", severity: "medium" },
  { id: "remote_control_app", title: "Remote Control App", category: "privacyScreen", severity: "high" },
  { id: "screen_sharing_risk", title: "Screen Sharing During App Use", category: "privacyScreen", severity: "high" },
  { id: "remote_config_rejected", title: "Remote Configuration Rejected", category: "appIntegrity", severity: "high" },
];
