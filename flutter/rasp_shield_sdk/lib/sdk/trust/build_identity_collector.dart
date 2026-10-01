import 'package:flutter/foundation.dart';
import 'package:package_info_plus/package_info_plus.dart';

import '../activation_manager.dart';
import '../detectors/rasp_native_channel.dart';
import '../sdk_config.dart';
import 'build_identity.dart';
import 'obfuscation_state.dart';
import 'release_environment.dart';
import 'release_signing.dart';

/// Release Obfuscation + Self-Integrity Verification milestone — gathers a
/// [BuildSecurityIdentity] snapshot the same way [TrustAnchorCollector]
/// gathers everything else it observes: every read individually guarded,
/// a failure yields `null`/an honest fallback, never a fabricated pass.
///
/// Kept as its own small collector rather than folded into
/// [TrustAnchorCollector] because [BuildSecurityIdentity] is also consumed
/// by [BuildIdentityClassifier] directly (Phase 6/7), independent of a full
/// trust-anchor collection pass — see `docs/BUILD_SECURITY_IDENTITY.md`.
class BuildIdentityCollector {
  const BuildIdentityCollector();

  Future<BuildSecurityIdentity> collect() async {
    final applicationId = await _applicationId();
    final buildVersion = await _buildVersion();
    final signing = await _signingInfo();
    final nativeMarker = await _nativeObfuscationMarker();
    final obfuscation =
        const ObfuscationChecker().combineWithNative(nativeMarker);

    return BuildSecurityIdentity(
      applicationId: applicationId,
      sdkVersion: SdkConfig.sdkVersion,
      buildVersion: buildVersion,
      buildChannel: signing.signingMode,
      compiledInDebugMode: kDebugMode,
      declaredEnvironment: declaredReleaseEnvironment(),
      signingConfigured: signing.signingConfigured,
      isDebugCertificate: signing.isDebugCertificate,
      obfuscationState: obfuscation,
    );
  }

  static Future<String?> _applicationId() async {
    try {
      final value = await ActivationManager.bundleId();
      return value.isEmpty ? null : value;
    } catch (_) {
      return null;
    }
  }

  static Future<String> _buildVersion() async {
    try {
      final info = await PackageInfo.fromPlatform();
      return '${info.version}+${info.buildNumber}';
    } catch (_) {
      return 'unknown';
    }
  }

  static Future<ReleaseSigningInfo> _signingInfo() async {
    try {
      final raw = await RaspNativeChannel.mapCall('getSigningIdentity');
      return ReleaseSigningInfo.fromMap(raw);
    } catch (_) {
      return ReleaseSigningInfo.unavailable;
    }
  }

  static Future<String?> _nativeObfuscationMarker() async {
    try {
      return await RaspNativeChannel.stringCall('getObfuscationMarker');
    } catch (_) {
      return null;
    }
  }
}
