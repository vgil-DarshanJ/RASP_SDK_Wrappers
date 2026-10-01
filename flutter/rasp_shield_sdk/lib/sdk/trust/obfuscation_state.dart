/// Release Obfuscation + Self-Integrity Verification milestone — whether
/// *this running process* was actually compiled with `--obfuscate`, judged
/// from a real build artifact rather than assumed from the build type.
///
/// See `docs/RELEASE_OBFUSCATION_AUDIT.md` §3 for why `kReleaseMode` alone
/// cannot answer this (a plain `flutter build apk --release`, with no
/// `--obfuscate` flag, is still `kReleaseMode` and still unobfuscated —
/// this codebase's own `scripts/build_release_apk.sh` passes `--obfuscate`
/// itself, but nothing forced every release build to go through that
/// script until this milestone's release-verification enhancement, §5 of
/// the same doc).
enum ObfuscationState {
  /// The marker's observed runtime type name differs from its known,
  /// hardcoded source name, in the shape Dart's identifier obfuscation
  /// actually produces (short, renamed, no library prefix collision).
  obfuscated,

  /// The marker's observed runtime type name is EXACTLY its known source
  /// name. Dart's `--obfuscate` renames private class identifiers
  /// unconditionally when it runs — an exact match is strong evidence
  /// obfuscation did not run for this build, not merely "inconclusive".
  notObfuscated,

  /// The marker resolved to a name that is neither the exact original nor
  /// shaped like a typical obfuscated token — reported honestly as unknown
  /// rather than guessed at either extreme.
  unknown,

  /// The check itself threw. Never treated as `notObfuscated` (fail-open)
  /// or `obfuscated` (fail-easy) — a distinct, honest failure state.
  error,
}

/// A private class not referenced by any `-keep` rule in
/// `android/app/proguard-rules.pro` and not exported/reflected anywhere —
/// exactly the shape of symbol Dart's `--obfuscate` and Android's R8 both
/// rename by default. Its only job is to exist so [ObfuscationChecker] can
/// ask the runtime what it is actually called right now.
///
/// **Why this is not "local value == same local value":** the comparison
/// target, [ObfuscationChecker._expectedUnobfuscatedName], is the class's
/// *source-declared* name — fixed at the moment this file was written, not
/// computed from anything the running process could have tampered with.
/// An attacker who patches the running build to fake "obfuscated" would
/// have to change what `runtimeType.toString()` actually returns for this
/// object, which means defeating Dart's own type-reflection machinery, not
/// flipping a stored boolean.
class RaspObfuscationMarker {
  const RaspObfuscationMarker();
}

/// Runs the marker check described above.
///
/// This is one input among several (see `BuildIdentityClassifier` and
/// `docs/BUILD_SECURITY_IDENTITY.md`) — it answers "was Dart identifier
/// obfuscation applied to at least this symbol", not "is this build
/// unbreakable". A determined attacker who fully decompiles an obfuscated
/// build can still recover logic from control flow and string constants;
/// this raises the cost of that, it does not remove it — the same
/// "cost-raising control, not a guarantee" framing `sdk_integrity.dart`
/// already uses for its own canaries.
class ObfuscationChecker {
  const ObfuscationChecker();

  static const String _expectedUnobfuscatedName = 'RaspObfuscationMarker';

  ObfuscationState check() {
    try {
      final observed = const RaspObfuscationMarker().runtimeType.toString();
      if (observed == _expectedUnobfuscatedName) {
        return ObfuscationState.notObfuscated;
      }
      if (_looksLikeObfuscatedToken(observed)) {
        return ObfuscationState.obfuscated;
      }
      return ObfuscationState.unknown;
    } catch (_) {
      return ObfuscationState.error;
    }
  }

  /// Dart's obfuscator replaces identifiers with short synthetic tokens
  /// (documented behavior of `--obfuscate`) — this is a shape heuristic,
  /// not a proof of *which* renaming pass produced it, which is why a name
  /// that fails this test resolves to [ObfuscationState.unknown] rather
  /// than [ObfuscationState.notObfuscated]: an unexpected name is
  /// unexplained, not evidence of safety.
  static bool _looksLikeObfuscatedToken(String name) {
    if (name.isEmpty) return false;
    if (name.length > 10) return false;
    return RegExp(r'^[A-Za-z_][A-Za-z0-9_$]*$').hasMatch(name);
  }

  /// Combines this Dart-layer verdict with an independent corroborating
  /// signal — on Android, `MainActivity.obfuscationMarker()`'s real,
  /// current R8-renamed (or not) class-name reflection, read via
  /// [nativeMarkerName]. `null` when unavailable (wrong platform, channel
  /// not registered), in which case the Dart-only verdict stands
  /// unchanged.
  ///
  /// Two independent artifacts (a Dart AOT symbol, a JVM/R8 class name)
  /// agreeing is stronger evidence than either alone; **any** one of them
  /// proving `notObfuscated` is treated as the more conservative, more
  /// trustworthy signal — an attacker who wants to fake "obfuscated" must
  /// now defeat both the Dart compiler's own renaming AND R8's, not one.
  static const String _expectedNativeUnobfuscatedName = 'RaspObfuscationMarker';

  ObfuscationState combineWithNative(String? nativeMarkerName) {
    final dartState = check();
    if (nativeMarkerName == null || nativeMarkerName.isEmpty) return dartState;

    final ObfuscationState nativeState;
    if (nativeMarkerName == _expectedNativeUnobfuscatedName) {
      nativeState = ObfuscationState.notObfuscated;
    } else if (_looksLikeObfuscatedToken(nativeMarkerName)) {
      nativeState = ObfuscationState.obfuscated;
    } else {
      nativeState = ObfuscationState.unknown;
    }

    if (dartState == ObfuscationState.notObfuscated ||
        nativeState == ObfuscationState.notObfuscated) {
      return ObfuscationState.notObfuscated;
    }
    if (dartState == ObfuscationState.obfuscated &&
        nativeState == ObfuscationState.obfuscated) {
      return ObfuscationState.obfuscated;
    }
    if (dartState == ObfuscationState.error || nativeState == ObfuscationState.error) {
      return ObfuscationState.error;
    }
    return ObfuscationState.unknown;
  }
}
