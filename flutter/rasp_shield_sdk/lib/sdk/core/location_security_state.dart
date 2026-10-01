/// Where a device stands against the *location requirement*, as plain data.
///
/// ## Why this is its own vocabulary
///
/// "Can we read a location?" is not one boolean, it is two independent
/// permissions the user controls separately — an app-level runtime grant and
/// a device-wide services toggle — plus the case where neither could be
/// determined. A single `bool hasLocation` cannot tell an integrator which of
/// those to fix, so the security gate built on it would only ever be able to
/// say "denied" and never "here is the button that unblocks you".
///
/// The values mirror the seven states the OS actually distinguishes. They are
/// deliberately *not* collapsed: [unknown] and [unavailable] are neither
/// satisfied nor a user-fixable denial, and treating them as either would be
/// the same defect [DetectionStatus] exists to prevent.
///
/// Nothing here imports Flutter — this file is pure Dart data, like the rest
/// of `sdk/core/`. The platform reading that *produces* one of these lives in
/// `sdk/location_requirement.dart`.
enum LocationSecurityState {
  /// Runtime permission is granted, but whether the device's location
  /// services are switched on could not be established.
  ///
  /// **Not satisfied.** Half of the requirement is confirmed and the other
  /// half is unknown; reporting that as satisfied would be a guess in the
  /// direction of less protection.
  permissionGranted,

  /// The user declined the runtime permission. Re-askable — the OS will still
  /// show the system prompt.
  permissionDenied,

  /// The user declined permanently ("Don't ask again"), or a device policy
  /// forbids it. The system prompt will no longer appear, so the only route
  /// forward is app settings.
  permissionPermanentlyDenied,

  /// Permission granted **and** device location services on. The one state
  /// that satisfies the requirement.
  serviceEnabled,

  /// Permission is granted but device-wide location services are off. Fixed
  /// in system settings, not by an app prompt.
  serviceDisabled,

  /// This platform has no location capability the SDK can use at all (web, an
  /// unsupported desktop host). Distinct from a denial: no user action can
  /// change it.
  unavailable,

  /// The reading itself failed — the plugin threw, or the call timed out.
  /// A fault worth investigating, never a pass.
  unknown,
}

/// Grouping helpers so callers do not re-derive the same predicates.
extension LocationSecurityStateX on LocationSecurityState {
  /// `true` only for [LocationSecurityState.serviceEnabled] — permission
  /// granted *and* location services on.
  ///
  /// Every other value, including the two inconclusive ones, is false. This
  /// is the single predicate the access gate reads, so "we could not tell"
  /// can never open the gate.
  bool get isSatisfied => this == LocationSecurityState.serviceEnabled;

  /// `true` when the state was actually determined — as opposed to
  /// [LocationSecurityState.unknown] / [LocationSecurityState.unavailable],
  /// where no verdict was reached.
  bool get isConclusive =>
      this != LocationSecurityState.unknown &&
      this != LocationSecurityState.unavailable;

  /// `true` when the user can fix this from inside the app, via the system
  /// permission prompt. Only [LocationSecurityState.permissionDenied]
  /// qualifies — a permanent denial no longer raises a prompt.
  bool get isPromptable => this == LocationSecurityState.permissionDenied;

  /// `true` when the fix lives in the OS Settings app rather than in a
  /// prompt, so the gate offers "Open Settings" instead of "Enable".
  bool get needsSystemSettings =>
      this == LocationSecurityState.permissionPermanentlyDenied ||
      this == LocationSecurityState.serviceDisabled;

  /// Stable wire name used in policy JSON, telemetry, and logs.
  ///
  /// SCREAMING_SNAKE_CASE to match the vocabulary the backend and the task
  /// specification already use (`LOCATION_SERVICE_DISABLED`), rather than
  /// Dart's camelCase.
  String get wireName => switch (this) {
        LocationSecurityState.permissionGranted => 'LOCATION_PERMISSION_GRANTED',
        LocationSecurityState.permissionDenied => 'LOCATION_PERMISSION_DENIED',
        LocationSecurityState.permissionPermanentlyDenied =>
          'LOCATION_PERMISSION_PERMANENTLY_DENIED',
        LocationSecurityState.serviceEnabled => 'LOCATION_SERVICE_ENABLED',
        LocationSecurityState.serviceDisabled => 'LOCATION_SERVICE_DISABLED',
        LocationSecurityState.unavailable => 'LOCATION_UNAVAILABLE',
        LocationSecurityState.unknown => 'LOCATION_UNKNOWN',
      };
}

/// Parses a [LocationSecurityState] from its
/// [LocationSecurityStateX.wireName].
///
/// Returns `null` for an unrecognised name rather than throwing — a newer
/// backend vocabulary must degrade, not break an older SDK build.
LocationSecurityState? locationSecurityStateFromName(String? name) {
  if (name == null) return null;
  for (final state in LocationSecurityState.values) {
    if (state.wireName == name || state.name == name) return state;
  }
  return null;
}

/// One resolved reading of the device's location posture.
///
/// Carries the resolved [state] *and* the two sub-readings it was derived
/// from, so a gate can act on one value while a diagnostic surface can still
/// explain which half failed.
class LocationSecurityStatus {
  /// The single resolved state — see [LocationSecurityState] for the
  /// resolution order.
  final LocationSecurityState state;

  /// Whether the runtime permission is granted, or `null` when the read
  /// failed. Never guessed.
  final bool? permissionGranted;

  /// Whether device-wide location services are on, or `null` when the read
  /// failed.
  final bool? serviceEnabled;

  /// Why no verdict was reached, for [LocationSecurityState.unknown] and
  /// [LocationSecurityState.unavailable]. `null` otherwise.
  final String? reason;

  /// When this reading was taken, in UTC.
  final DateTime observedAt;

  const LocationSecurityStatus({
    required this.state,
    this.permissionGranted,
    this.serviceEnabled,
    this.reason,
    required this.observedAt,
  });

  /// The state before anything has been read. Not satisfied, so a gate that
  /// checks before its first probe stays closed rather than open.
  factory LocationSecurityStatus.unknown({String? reason, DateTime? at}) =>
      LocationSecurityStatus(
        state: LocationSecurityState.unknown,
        reason: reason ?? 'Location posture has not been read yet',
        observedAt: at ?? DateTime.now().toUtc(),
      );

  /// `true` when the requirement is met. Delegates to
  /// [LocationSecurityStateX.isSatisfied] so there is one definition.
  bool get isSatisfied => state.isSatisfied;

  /// Plain-map form for logging, telemetry metadata, or JSON encoding.
  Map<String, Object?> toMap() => {
        'state': state.wireName,
        'permission_granted': permissionGranted,
        'service_enabled': serviceEnabled,
        if (reason != null) 'reason': reason,
        'observed_at': observedAt.toIso8601String(),
      };

  @override
  String toString() => 'LocationSecurityStatus(${state.wireName})';
}
